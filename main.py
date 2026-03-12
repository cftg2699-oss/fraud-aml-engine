"""
Fraud & AML Platform v3 — Multi-tenant con Auth
Railway + PostgreSQL | Score 0-999 | ML | JWT Auth
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "services"))

from fastapi import FastAPI, HTTPException, Depends, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session
from sqlalchemy import func as sqlfunc, desc
from datetime import datetime, timedelta
from typing import Optional, List
import random, hashlib, uuid

from database import init_db, get_db, SessionLocal
from models import (
    Entity, Profile, TransactionRecord, Alert, ModelVersion,
    EntityCreate, TransactionIn, TransactionOut, AlertFeedback
)
from auth_models import User
from auth_routes import router as auth_router
from services.profile_service import get_or_create_profile, update_profile, build_profile_features
from services.scoring_engine import evaluate
from services import ml_service
from services.auth_service import get_current_user, require_superadmin


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # Seed demo entity + bootstrap model on first run
    db = SessionLocal()
    try:
        if not db.query(Entity).filter(Entity.code == "DEMO").first():
            demo = Entity(
                code="DEMO", name="Demo Bank (Entidad de prueba)",
                identity_type="account_number",
                score_alert=400, score_review=600, score_block=800,
                weight_rules=0.4, weight_ml=0.6
            )
            db.add(demo)
            db.commit()
            print("✅ Entidad DEMO creada")
        import glob
        if not glob.glob("./ml_models/global.pkl"):
            ml_service.train_model(db, entity_id=None)
            print("✅ Modelo bootstrap entrenado")
    except Exception as e:
        print(f"⚠ Seed error: {e}")
    finally:
        db.close()
    yield


app = FastAPI(
    title="Fraud & AML Platform",
    description="Motor de riesgo en tiempo real · Perfiles · Score 0-999 · ML comunitario",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth router
app.include_router(auth_router)

def get_entity_filter(current_user: User) -> Optional[str]:
    """Returns entity_code restriction for non-superadmins"""
    if current_user.role == "superadmin":
        return None  # sees everything
    return current_user.entity_code


# ═══════════════════════════════════════════════════════════
#  SISTEMA
# ═══════════════════════════════════════════════════════════

@app.get("/", tags=["Sistema"])
def root():
    return {"system": "Fraud & AML Platform", "version": "2.0.0",
            "status": "operational", "docs": "/docs"}

@app.get("/health", tags=["Sistema"])
def health():
    return {"status": "ok", "ts": datetime.utcnow().isoformat()}


# ═══════════════════════════════════════════════════════════
#  ENTIDADES
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/entities", tags=["Entidades"])
def list_entities(db: Session = Depends(get_db)):
    rows = db.query(Entity).order_by(Entity.id).all()
    return {"entities": [e.to_dict() for e in rows]}

@app.post("/api/v2/entities", tags=["Entidades"])
def create_entity(data: EntityCreate, db: Session = Depends(get_db)):
    if db.query(Entity).filter(Entity.code == data.code).first():
        raise HTTPException(400, f"Entidad '{data.code}' ya existe")
    e = Entity(**data.dict())
    db.add(e); db.commit(); db.refresh(e)
    return {"message": "Entidad creada", "entity": e.to_dict()}

@app.get("/api/v2/entities/{code}", tags=["Entidades"])
def get_entity(code: str, db: Session = Depends(get_db)):
    e = db.query(Entity).filter(Entity.code == code).first()
    if not e: raise HTTPException(404, "Entidad no encontrada")
    # enrich with counts
    d = e.to_dict()
    d["stats"] = {
        "total_transactions": db.query(TransactionRecord).filter(TransactionRecord.entity_id == e.id).count(),
        "total_profiles":     db.query(Profile).filter(Profile.entity_id == e.id).count(),
        "open_alerts":        db.query(Alert).filter(Alert.entity_id == e.id, Alert.status == "PENDING").count(),
    }
    return d

@app.patch("/api/v2/entities/{code}", tags=["Entidades"])
def update_entity(code: str, data: dict, db: Session = Depends(get_db)):
    e = db.query(Entity).filter(Entity.code == code).first()
    if not e: raise HTTPException(404, "Entidad no encontrada")
    allowed = {"score_alert","score_review","score_block","weight_rules","weight_ml","name","identity_type"}
    for k, v in data.items():
        if k in allowed: setattr(e, k, v)
    db.commit()
    return {"message": "Actualizado", "entity": e.to_dict()}

@app.delete("/api/v2/entities/{code}", tags=["Entidades"])
def delete_entity(code: str, db: Session = Depends(get_db)):
    e = db.query(Entity).filter(Entity.code == code).first()
    if not e: raise HTTPException(404, "No encontrada")
    if code == "DEMO": raise HTTPException(400, "No se puede eliminar la entidad DEMO")
    db.delete(e); db.commit()
    return {"message": f"Entidad {code} eliminada"}


# ═══════════════════════════════════════════════════════════
#  SCORING
# ═══════════════════════════════════════════════════════════

@app.post("/api/v2/score", tags=["Scoring"], response_model=TransactionOut)
def score_transaction(tx: TransactionIn, db: Session = Depends(get_db)):
    entity = db.query(Entity).filter(Entity.code == tx.entity_code).first()
    if not entity:
        raise HTTPException(404, f"Entidad '{tx.entity_code}' no existe. Créala primero en /api/v2/entities")
    profile  = get_or_create_profile(db, entity, tx.identity_value)
    features = build_profile_features(profile, tx)
    ml_prob, ml_ver = ml_service.predict(features, entity_id=entity.id)
    result   = evaluate(tx, entity, features, ml_prob, ml_ver)

    record = TransactionRecord(
        tx_id=result["tx_id"], entity_id=entity.id, profile_id=profile.id,
        identity_type=entity.identity_type, identity_value=profile.identity_value,
        channel=tx.channel, subtype=tx.subtype or "", amount=tx.amount,
        currency=tx.currency, merchant=tx.merchant or "", city=tx.city or "",
        country=tx.country or "", cardholder=tx.cardholder or "",
        is_foreign=tx.is_foreign, new_device=tx.new_device,
        new_beneficiary=tx.new_beneficiary, is_pep=tx.is_pep, is_sanctioned=tx.is_sanctioned,
        score_rules=result["score_rules"], score_ml=result["score_ml"],
        score_final=result["score_final"], decision=result["decision"],
        risk_level=result["risk_level"], rules_triggered=result["triggered_rules"],
        aml_flags=result["aml_flags"], processing_ms=result["processing_ms"],
    )
    db.add(record)

    if result["risk_level"] in ("HIGH","CRITICAL"):
        top = (result["triggered_rules"] + result["aml_flags"])
        db.add(Alert(
            tx_id=result["tx_id"], entity_id=entity.id, profile_id=profile.id,
            channel=tx.channel, risk_level=result["risk_level"],
            decision=result["decision"], score_final=result["score_final"],
            amount=tx.amount, cardholder=tx.cardholder or "",
            top_rule=top[0]["name"] if top else "", city=tx.city or "",
        ))

    update_profile(db, profile, tx, result["score_final"])
    db.commit()

    return TransactionOut(
        tx_id=result["tx_id"], timestamp=result["timestamp"],
        entity_code=tx.entity_code, identity_type=entity.identity_type,
        identity_value=tx.identity_value, channel=tx.channel, amount=tx.amount,
        score_rules=result["score_rules"], score_ml=result["score_ml"],
        score_final=result["score_final"], decision=result["decision"],
        risk_level=result["risk_level"], triggered_rules=result["triggered_rules"],
        aml_flags=result["aml_flags"], profile_snapshot=profile.to_dict(),
        processing_ms=result["processing_ms"],
    )


# ═══════════════════════════════════════════════════════════
#  TRANSACCIONES
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/transactions", tags=["Transacciones"])
def list_transactions(
    entity_code: Optional[str] = None,
    channel:     Optional[str] = None,
    decision:    Optional[str] = None,
    risk_level:  Optional[str] = None,
    min_score:   int = 0,
    limit:  int = Query(50,  ge=1, le=500),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    q = db.query(TransactionRecord)
    if entity_code:
        e = db.query(Entity).filter(Entity.code == entity_code).first()
        if e: q = q.filter(TransactionRecord.entity_id == e.id)
    if channel:    q = q.filter(TransactionRecord.channel    == channel.upper())
    if decision:   q = q.filter(TransactionRecord.decision   == decision.upper())
    if risk_level: q = q.filter(TransactionRecord.risk_level == risk_level.upper())
    if min_score:  q = q.filter(TransactionRecord.score_final >= min_score)
    total = q.count()
    rows  = q.order_by(desc(TransactionRecord.created_at)).offset(offset).limit(limit).all()
    return {"total": total, "offset": offset, "limit": limit, "data": [r.to_dict() for r in rows]}

@app.get("/api/v2/transactions/{tx_id}", tags=["Transacciones"])
def get_transaction(tx_id: str, db: Session = Depends(get_db)):
    r = db.query(TransactionRecord).filter(TransactionRecord.tx_id == tx_id).first()
    if not r: raise HTTPException(404, "TX no encontrada")
    return r.to_dict()


# ═══════════════════════════════════════════════════════════
#  PERFILES
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/profiles", tags=["Perfiles"])
def list_profiles(
    entity_code: Optional[str] = None,
    risk_label:  Optional[str] = None,
    limit: int = Query(30, ge=1, le=200),
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "superadmin":
        entity_code = current_user.entity_code
    q = db.query(Profile)
    if entity_code:
        e = db.query(Entity).filter(Entity.code == entity_code).first()
        if e: q = q.filter(Profile.entity_id == e.id)
    if risk_label:
        q = q.filter(Profile.risk_label == risk_label.upper())
    total   = q.count()
    rows    = q.order_by(desc(Profile.score_max_ever)).offset(offset).limit(limit).all()
    return {"total": total, "offset": offset, "profiles": [p.to_dict() for p in rows]}

@app.get("/api/v2/profiles/search", tags=["Perfiles"])
def search_profile(
    entity_code:    str,
    identity_value: str,
    db: Session = Depends(get_db)
):
    e = db.query(Entity).filter(Entity.code == entity_code).first()
    if not e: raise HTTPException(404, "Entidad no encontrada")
    hashed = hashlib.sha256(identity_value.encode()).hexdigest()[:24]
    p = db.query(Profile).filter(Profile.entity_id == e.id, Profile.identity_value == hashed).first()
    if not p: raise HTTPException(404, "Perfil no encontrado — aún no tiene transacciones")
    last_txs = (db.query(TransactionRecord)
                .filter(TransactionRecord.profile_id == p.id)
                .order_by(desc(TransactionRecord.created_at)).limit(20).all())
    alerts = (db.query(Alert)
              .filter(Alert.profile_id == p.id)
              .order_by(desc(Alert.created_at)).limit(10).all())
    return {
        "profile":      p.to_dict(),
        "entity":       e.to_dict(),
        "transactions": [t.to_dict() for t in last_txs],
        "alerts":       [a.to_dict() for a in alerts],
    }


# ═══════════════════════════════════════════════════════════
#  ALERTAS + FEEDBACK
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/alerts", tags=["Alertas"])
def list_alerts(
    entity_code: Optional[str] = None,
    status:      str = Query("PENDING"),
    risk_level:  Optional[str] = None,
    limit:  int = Query(50, ge=1, le=500),
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "superadmin":
        entity_code = current_user.entity_code
    q = db.query(Alert)
    if entity_code:
        e = db.query(Entity).filter(Entity.code == entity_code).first()
        if e: q = q.filter(Alert.entity_id == e.id)
    if status and status != "ALL":
        q = q.filter(Alert.status == status)
    if risk_level:
        q = q.filter(Alert.risk_level == risk_level.upper())
    total = q.count()
    rows  = q.order_by(desc(Alert.created_at)).offset(offset).limit(limit).all()
    return {"total": total, "data": [a.to_dict() for a in rows]}

@app.get("/api/v2/alerts/{alert_id}", tags=["Alertas"])
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert: raise HTTPException(404, "Alerta no encontrada")
    tx      = db.query(TransactionRecord).filter(TransactionRecord.tx_id == alert.tx_id).first()
    profile = db.query(Profile).filter(Profile.id == alert.profile_id).first() if alert.profile_id else None
    history, prev_alerts = [], []
    if profile:
        history = (db.query(TransactionRecord)
                   .filter(TransactionRecord.profile_id == profile.id)
                   .order_by(desc(TransactionRecord.created_at)).limit(20).all())
        prev_alerts = (db.query(Alert)
                       .filter(Alert.profile_id == profile.id, Alert.id != alert_id)
                       .order_by(desc(Alert.created_at)).limit(10).all())
    return {
        "alert":            alert.to_dict(),
        "transaction":      tx.to_dict() if tx else None,
        "profile":          profile.to_dict() if profile else None,
        "identity_history": [t.to_dict() for t in history],
        "previous_alerts":  [a.to_dict() for a in prev_alerts],
    }

@app.post("/api/v2/alerts/{alert_id}/feedback", tags=["Alertas"])
def label_alert(
    alert_id: int,
    feedback: AlertFeedback,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert: raise HTTPException(404, "Alerta no encontrada")
    if alert.status not in ("PENDING","UNDER_REVIEW"):
        raise HTTPException(400, f"Alerta ya calificada: {alert.status}")

    alert.status = feedback.analyst_label
    alert.analyst_label = feedback.analyst_label
    alert.analyst_note  = feedback.analyst_note
    alert.analyst_id    = feedback.analyst_id
    alert.labeled_at    = datetime.utcnow()

    if alert.profile_id:
        p = db.query(Profile).filter(Profile.id == alert.profile_id).first()
        if p:
            if feedback.analyst_label == "CONFIRMED_FRAUD":
                p.fraud_confirmed = (p.fraud_confirmed or 0) + 1
                p.risk_label = "FRAUD"
            elif feedback.analyst_label == "FALSE_POSITIVE":
                p.false_positives = (p.false_positives or 0) + 1
                if p.risk_label != "FRAUD": p.risk_label = "CLEAN"

    db.commit()

    retrain_triggered = False
    if feedback.trigger_retrain and feedback.analyst_label in ("CONFIRMED_FRAUD","FALSE_POSITIVE"):
        labeled = db.query(Alert).filter(
            Alert.analyst_label.in_(["CONFIRMED_FRAUD","FALSE_POSITIVE"])
        ).count()
        if labeled >= 5:
            background_tasks.add_task(_retrain_bg, alert.entity_id)
            retrain_triggered = True

    return {
        "message": "Feedback guardado",
        "alert_id": alert_id,
        "label": feedback.analyst_label,
        "retrain_triggered": retrain_triggered,
    }

def _retrain_bg(entity_id):
    db = SessionLocal()
    try:
        ml_service.train_model(db, entity_id=None)
        if entity_id: ml_service.train_model(db, entity_id=entity_id)
    except Exception as e:
        print(f"Retrain error: {e}")
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════
#  MODELO ML
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/model/versions", tags=["Modelo ML"])
def model_versions(db: Session = Depends(get_db)):
    rows = db.query(ModelVersion).order_by(desc(ModelVersion.trained_at)).all()
    return {"versions": [v.to_dict() for v in rows]}

@app.post("/api/v2/model/train", tags=["Modelo ML"])
def train_model(
    entity_code: Optional[str] = None,
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db)
):
    entity_id = None
    if entity_code:
        e = db.query(Entity).filter(Entity.code == entity_code).first()
        if not e: raise HTTPException(404, "Entidad no encontrada")
        entity_id = e.id
    labeled = db.query(Alert).filter(
        Alert.analyst_label.in_(["CONFIRMED_FRAUD","FALSE_POSITIVE"])
    ).count()
    background_tasks.add_task(_retrain_bg, entity_id)
    return {"message": "Entrenamiento iniciado", "labeled_samples": labeled,
            "entity_id": entity_id}

@app.get("/api/v2/model/stats", tags=["Modelo ML"])
def model_stats(db: Session = Depends(get_db)):
    total_labeled = db.query(Alert).filter(
        Alert.analyst_label.in_(["CONFIRMED_FRAUD","FALSE_POSITIVE"])
    ).count()
    fraud_labeled = db.query(Alert).filter(Alert.analyst_label == "CONFIRMED_FRAUD").count()
    fp_labeled    = db.query(Alert).filter(Alert.analyst_label == "FALSE_POSITIVE").count()
    pending       = db.query(Alert).filter(Alert.status == "PENDING").count()
    latest        = db.query(ModelVersion).filter(ModelVersion.is_active==True).order_by(desc(ModelVersion.trained_at)).first()
    precision = round(fraud_labeled / max(fraud_labeled + fp_labeled, 1) * 100, 1)
    return {
        "labels": {"total": total_labeled, "fraud": fraud_labeled, "false_positives": fp_labeled},
        "pending_alerts": pending,
        "precision_estimate": precision,
        "latest_model": latest.to_dict() if latest else None,
        "ready_for_training": total_labeled >= 5,
    }


# ═══════════════════════════════════════════════════════════
#  DASHBOARD STATS
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/stats", tags=["Dashboard"])
def get_stats(entity_code: Optional[str] = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "superadmin" and not entity_code:
        entity_code = current_user.entity_code
    q  = db.query(TransactionRecord)
    qa = db.query(Alert)
    qp = db.query(Profile)

    if entity_code:
        e = db.query(Entity).filter(Entity.code == entity_code).first()
        if e:
            q  = q.filter(TransactionRecord.entity_id == e.id)
            qa = qa.filter(Alert.entity_id == e.id)
            qp = qp.filter(Profile.entity_id == e.id)

    total    = q.count()
    blocked  = q.filter(TransactionRecord.decision == "BLOQUEADA").count()
    review   = q.filter(TransactionRecord.decision == "REVISIÓN").count()
    alerted  = q.filter(TransactionRecord.decision == "ALERTA").count()
    approved = q.filter(TransactionRecord.decision == "APROBADA").count()

    avg_score = db.query(sqlfunc.avg(TransactionRecord.score_final)).scalar() or 0
    avg_ms    = db.query(sqlfunc.avg(TransactionRecord.processing_ms)).scalar() or 0

    channels = {}
    for ch in ["CARD","TRANSFER","WALLET","ATM","DIGITAL_BANKING"]:
        channels[ch] = q.filter(TransactionRecord.channel == ch).count()

    # Last 24h volume
    since = datetime.utcnow() - timedelta(hours=24)
    vol24h = db.query(sqlfunc.sum(TransactionRecord.amount)).filter(
        TransactionRecord.created_at >= since).scalar() or 0

    # Trend: last 7 days by day
    trend = []
    for i in range(6, -1, -1):
        d_start = (datetime.utcnow() - timedelta(days=i)).replace(hour=0,minute=0,second=0,microsecond=0)
        d_end   = d_start + timedelta(days=1)
        day_q   = db.query(TransactionRecord).filter(
            TransactionRecord.created_at >= d_start,
            TransactionRecord.created_at <  d_end
        )
        if entity_code and e:
            day_q = day_q.filter(TransactionRecord.entity_id == e.id)
        day_blocked = day_q.filter(TransactionRecord.decision == "BLOQUEADA").count()
        trend.append({
            "date":    d_start.strftime("%d/%m"),
            "total":   day_q.count(),
            "blocked": day_blocked,
        })

    return {
        "totals": {
            "transactions": total, "approved": approved, "alerted": alerted,
            "review": review, "blocked": blocked,
        },
        "rates": {
            "approval":  round(approved / max(total,1) * 100, 1),
            "block":     round(blocked  / max(total,1) * 100, 1),
            "review":    round(review   / max(total,1) * 100, 1),
        },
        "performance": {
            "avg_score": round(float(avg_score), 1),
            "avg_ms":    round(float(avg_ms), 1),
            "vol_24h":   round(float(vol24h), 2),
        },
        "alerts": {
            "pending":          qa.filter(Alert.status == "PENDING").count(),
            "confirmed_fraud":  qa.filter(Alert.status == "CONFIRMED_FRAUD").count(),
            "false_positives":  qa.filter(Alert.status == "FALSE_POSITIVE").count(),
        },
        "profiles": {
            "total": qp.count(),
            "fraud": qp.filter(Profile.risk_label == "FRAUD").count(),
            "clean": qp.filter(Profile.risk_label == "CLEAN").count(),
        },
        "by_channel": channels,
        "trend_7d": trend,
    }

@app.get("/api/v2/feed", tags=["Dashboard"])
def get_feed(limit: int = Query(20, ge=1, le=100),
             entity_code: Optional[str] = None,
             db: Session = Depends(get_db),
             current_user: User = Depends(get_current_user)):
    if current_user.role != "superadmin":
        entity_code = current_user.entity_code
    """Últimas transacciones para el feed en tiempo real"""
    q = db.query(TransactionRecord)
    if entity_code:
        e = db.query(Entity).filter(Entity.code == entity_code).first()
        if e: q = q.filter(TransactionRecord.entity_id == e.id)
    rows = q.order_by(desc(TransactionRecord.created_at)).limit(limit).all()
    return {"data": [r.to_dict() for r in rows]}


# ═══════════════════════════════════════════════════════════
#  SIMULACIÓN
# ═══════════════════════════════════════════════════════════

@app.post("/api/v2/simulate", tags=["Testing"])
def simulate(
    count: int = Query(20, ge=1, le=200),
    entity_code: str = Query("DEMO"),
    db: Session = Depends(get_db)
):
    entity = db.query(Entity).filter(Entity.code == entity_code).first()
    if not entity:
        entity = Entity(code=entity_code, name=f"{entity_code} Bank",
                       identity_type="account_number",
                       score_alert=400, score_review=600, score_block=800,
                       weight_rules=0.4, weight_ml=0.6)
        db.add(entity); db.flush()

    channels  = ["CARD","TRANSFER","WALLET","ATM","DIGITAL_BANKING"]
    subtypes  = {"CARD":["POS","ECOMMERCE","CONTACTLESS"],
                 "TRANSFER":["ACH","WIRE","INTERBANK"],
                 "WALLET":["P2P","QR","PAYMENT"],
                 "ATM":["WITHDRAWAL"],
                 "DIGITAL_BANKING":["ONLINE_TRANSFER","BILL_PAYMENT","MOBILE_RECHARGE"]}
    merchants = ["Amazon","Walmart","Shell","Apple","Netflix","Rappi","Steam","Uber","MercadoLibre","Airbnb"]
    cities    = ["Guayaquil","Bogotá","Lima","São Paulo","Miami","Madrid","Buenos Aires","Ciudad de México"]
    names     = ["Carlos M.","Ana G.","Luis R.","María L.","José M.","Isabel D.","Roberto S.","Carmen T."]
    identities= [f"ACC{1000+i}" for i in range(15)]

    summary = {"APROBADA":0,"ALERTA":0,"REVISIÓN":0,"BLOQUEADA":0}

    for _ in range(count):
        ch   = random.choice(channels)
        roll = random.random()
        if roll > 0.94:   amount = round(9500 + random.random()*499, 2)
        elif roll > 0.86: amount = round(5000 + random.random()*10000, 2)
        elif roll > 0.6:  amount = round(1000 + random.random()*4000, 2)
        else:             amount = round(10   + random.random()*990, 2)

        tx = TransactionIn(
            entity_code=entity_code,
            identity_value=random.choice(identities),
            channel=ch, subtype=random.choice(subtypes[ch]),
            amount=amount, currency="USD",
            merchant=random.choice(merchants),
            city=random.choice(cities), country="EC",
            cardholder=random.choice(names),
            is_foreign=random.random()>0.85,
            new_device=random.random()>0.88,
            new_beneficiary=random.random()>0.70,
            is_pep=random.random()>0.97,
            is_sanctioned=random.random()>0.998,
        )
        profile  = get_or_create_profile(db, entity, tx.identity_value)
        features = build_profile_features(profile, tx)
        ml_prob, ml_ver = ml_service.predict(features, entity_id=entity.id)
        result   = evaluate(tx, entity, features, ml_prob, ml_ver)

        record = TransactionRecord(
            tx_id=result["tx_id"], entity_id=entity.id, profile_id=profile.id,
            identity_type=entity.identity_type, identity_value=profile.identity_value,
            channel=tx.channel, subtype=tx.subtype or "", amount=tx.amount,
            currency=tx.currency, merchant=tx.merchant or "", city=tx.city or "",
            country=tx.country or "", cardholder=tx.cardholder or "",
            is_foreign=tx.is_foreign, new_device=tx.new_device,
            new_beneficiary=tx.new_beneficiary, is_pep=tx.is_pep, is_sanctioned=tx.is_sanctioned,
            score_rules=result["score_rules"], score_ml=result["score_ml"],
            score_final=result["score_final"], decision=result["decision"],
            risk_level=result["risk_level"], rules_triggered=result["triggered_rules"],
            aml_flags=result["aml_flags"], processing_ms=result["processing_ms"],
        )
        db.add(record)

        if result["risk_level"] in ("HIGH","CRITICAL"):
            top = result["triggered_rules"] + result["aml_flags"]
            db.add(Alert(
                tx_id=result["tx_id"], entity_id=entity.id, profile_id=profile.id,
                channel=tx.channel, risk_level=result["risk_level"],
                decision=result["decision"], score_final=result["score_final"],
                amount=tx.amount, cardholder=tx.cardholder or "",
                top_rule=top[0]["name"] if top else "", city=tx.city or "",
            ))

        update_profile(db, profile, tx, result["score_final"])
        summary[result["decision"]] = summary.get(result["decision"],0)+1

    db.commit()
    return {"simulated": count, "entity": entity_code, "summary": summary}


# ═══════════════════════════════════════════════════════════
#  FUNCIÓN INTERNA: score_transaction_internal
#  Usada por el endpoint de upload masivo (auth_routes.py)
# ═══════════════════════════════════════════════════════════

def score_transaction_internal(payload: dict, db: Session):
    """
    Scorea una transacción desde un dict (usado por upload masivo).
    payload debe incluir: entity_code, tx_id, amount, channel, cardholder, city, account_number
    """
    entity_code = payload.get("entity_code", "DEMO")
    entity = db.query(Entity).filter(Entity.code == entity_code).first()
    if not entity:
        raise ValueError(f"Entidad '{entity_code}' no existe")

    tx = TransactionIn(
        entity_code=entity_code,
        identity_value=payload.get("account_number", "UNKNOWN"),
        channel=payload.get("channel", "CARD"),
        subtype=payload.get("subtype", ""),
        amount=float(payload.get("amount", 0)),
        currency="USD",
        merchant=payload.get("merchant", ""),
        city=payload.get("city", ""),
        country=payload.get("country", "EC"),
        cardholder=payload.get("cardholder", ""),
        is_foreign=False,
        new_device=False,
        new_beneficiary=bool(payload.get("dest_account")),
        is_pep=False,
        is_sanctioned=False,
    )

    profile  = get_or_create_profile(db, entity, tx.identity_value)
    features = build_profile_features(profile, tx)
    ml_prob, ml_ver = ml_service.predict(features, entity_id=entity.id)
    result   = evaluate(tx, entity, features, ml_prob, ml_ver)

    # Usar tx_id del payload si se provee
    final_tx_id = payload.get("tx_id") or result["tx_id"]

    record = TransactionRecord(
        tx_id=final_tx_id, entity_id=entity.id, profile_id=profile.id,
        identity_type=entity.identity_type, identity_value=profile.identity_value,
        channel=tx.channel, subtype=tx.subtype or "", amount=tx.amount,
        currency=tx.currency, merchant=tx.merchant or "", city=tx.city or "",
        country=tx.country or "", cardholder=tx.cardholder or "",
        is_foreign=tx.is_foreign, new_device=tx.new_device,
        new_beneficiary=tx.new_beneficiary, is_pep=tx.is_pep, is_sanctioned=tx.is_sanctioned,
        score_rules=result["score_rules"], score_ml=result["score_ml"],
        score_final=result["score_final"], decision=result["decision"],
        risk_level=result["risk_level"], rules_triggered=result["triggered_rules"],
        aml_flags=result["aml_flags"], processing_ms=result["processing_ms"],
    )
    db.add(record)

    if result["risk_level"] in ("HIGH", "CRITICAL"):
        top = result["triggered_rules"] + result["aml_flags"]
        db.add(Alert(
            tx_id=final_tx_id, entity_id=entity.id, profile_id=profile.id,
            channel=tx.channel, risk_level=result["risk_level"],
            decision=result["decision"], score_final=result["score_final"],
            amount=tx.amount, cardholder=tx.cardholder or "",
            top_rule=top[0]["name"] if top else "", city=tx.city or "",
        ))

    update_profile(db, profile, tx, result["score_final"])
    db.commit()

    result["tx_id"] = final_tx_id
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

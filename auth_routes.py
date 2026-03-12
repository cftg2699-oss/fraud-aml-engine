"""
Auth Routes — Register, Login, Admin panel, Upload masivo
"""
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Request
from sqlalchemy.orm import Session
from datetime import datetime
import io, uuid

from database import get_db
from auth_models import User, RegisterRequest, LoginRequest, ApproveRequest, TokenResponse
from models import Entity, Transaction
from services.auth_service import (
    hash_password, verify_password, create_token,
    get_current_user, require_superadmin
)

router = APIRouter(prefix="/api/v2/auth", tags=["Autenticación"])


# ── REGISTER ────────────────────────────────────────────────

@router.post("/register")
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "Email ya registrado")

    ec = (data.requested_entity_code or "").upper().strip().replace(" ", "_")
    en = (data.requested_entity_name or "").strip()
    if ec and not en:
        raise HTTPException(400, "Si indicas un código de entidad debes también indicar el nombre")
    if en and not ec:
        raise HTTPException(400, "Si indicas un nombre de entidad debes también indicar el código")
    if ec and len(ec) < 2:
        raise HTTPException(400, "El código de entidad debe tener al menos 2 caracteres")

    user = User(
        email=data.email,
        name=data.name,
        password=hash_password(data.password),
        role="analyst",
        status="PENDING",
        requested_entity_code=ec or None,
        requested_entity_name=en or None,
    )
    db.add(user); db.commit(); db.refresh(user)
    return {
        "message": "Cuenta creada. Espera aprobación del administrador.",
        "user_id": user.id
    }


# ── LOGIN ────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(401, "Email o contraseña incorrectos")
    if user.status == "PENDING":
        raise HTTPException(403, "Tu cuenta está pendiente de aprobación")
    if user.status == "REJECTED":
        raise HTTPException(403, "Tu cuenta fue rechazada. Contacta al administrador.")
    if not user.is_active:
        raise HTTPException(403, "Cuenta desactivada")
    token = create_token({"sub": str(user.id), "role": user.role, "entity": user.entity_code})
    return TokenResponse(access_token=token, user=user.to_dict())


# ── ME ────────────────────────────────────────────────────────

@router.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return current_user.to_dict()


# ── ADMIN: listar usuarios ────────────────────────────────────

@router.get("/admin/users")
def list_users(
    status: str = "PENDING",
    admin: User = Depends(require_superadmin),
    db: Session = Depends(get_db)
):
    q = db.query(User)
    if status != "ALL":
        q = q.filter(User.status == status)
    return {"users": [u.to_dict() for u in q.order_by(User.created_at.desc()).all()]}


# ── ADMIN: aprobar — crea entidad automáticamente ─────────────

@router.post("/admin/users/{user_id}/approve")
def approve_user(
    user_id: int,
    admin: User = Depends(require_superadmin),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")

    ec = user.requested_entity_code
    en = user.requested_entity_name

    if not ec:
        raise HTTPException(400, "El usuario no indicó una entidad al registrarse")

    entity = db.query(Entity).filter(Entity.code == ec).first()
    if not entity:
        entity = Entity(
            code=ec,
            name=en or ec,
            identity_type="account_number",
            score_alert=400,
            score_review=600,
            score_block=800,
            weight_rules=0.4,
            weight_ml=0.6,
        )
        db.add(entity)
        db.flush()

    existing = db.query(User).filter(
        User.entity_code == ec,
        User.status == "APPROVED",
        User.id != user_id
    ).first()
    if existing:
        raise HTTPException(400, f"La entidad '{ec}' ya tiene un analista: {existing.email}")

    user.status      = "APPROVED"
    user.entity_id   = entity.id
    user.entity_code = ec
    user.approved_at = datetime.utcnow()
    user.approved_by = admin.email
    db.commit()
    return {"message": f"Usuario aprobado y entidad '{ec}' lista", "user": user.to_dict()}


# ── ADMIN: rechazar ───────────────────────────────────────────

@router.post("/admin/users/{user_id}/reject")
def reject_user(
    user_id: int,
    admin: User = Depends(require_superadmin),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    user.status = "REJECTED"
    db.commit()
    return {"message": "Usuario rechazado", "user": user.to_dict()}


# ── ADMIN: eliminar ────────────────────────────────────────────

@router.delete("/admin/users/{user_id}")
def delete_user(
    user_id: int,
    admin: User = Depends(require_superadmin),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    db.delete(user); db.commit()
    return {"message": "Usuario eliminado"}


# ── SETUP SUPERADMIN ──────────────────────────────────────────

@router.post("/admin/setup-superadmin")
def setup_superadmin(data: RegisterRequest, db: Session = Depends(get_db)):
    """Solo funciona si no hay ningun superadmin todavia"""
    if db.query(User).filter(User.role == "superadmin").first():
        raise HTTPException(400, "Ya existe un superadmin. Usa /login.")
    user = User(
        email=data.email,
        name=data.name,
        password=hash_password(data.password),
        role="superadmin",
        status="APPROVED",
    )
    db.add(user); db.commit(); db.refresh(user)
    token = create_token({"sub": str(user.id), "role": "superadmin", "entity": None})
    return {"message": "Superadmin creado", "access_token": token, "user": user.to_dict()}


# ══════════════════════════════════════════════════════════════
#  HELPERS DE PARSEO
# ══════════════════════════════════════════════════════════════

def _detect_separator(line: str) -> str:
    """Detecta el separador: tab, punto y coma, o coma."""
    if "\t" in line:
        return "\t"
    if ";" in line:
        return ";"
    return ","

def _parse_csv_content(contents: bytes) -> list:
    """Parsea CSV/TSV/TXT en lista de listas. Intenta UTF-8 luego latin-1."""
    import csv as _csv
    text = None
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            text = contents.decode(enc)
            break
        except Exception:
            continue
    if text is None:
        raise ValueError("No se pudo decodificar el archivo de texto")

    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return []

    sep = _detect_separator(lines[0])
    reader = _csv.reader(lines, delimiter=sep)
    return list(reader)

def _parse_xlsx_content(contents: bytes) -> list:
    """Parsea xlsx/xls en lista de listas usando openpyxl."""
    try:
        import openpyxl
    except ImportError:
        raise HTTPException(500, "openpyxl no instalado")
    wb = openpyxl.load_workbook(io.BytesIO(contents), data_only=True)
    ws = wb.active
    rows = []
    for row in ws.iter_rows():
        rows.append([cell.value for cell in row])
    return rows


# ══════════════════════════════════════════════════════════════
#  UPLOAD MASIVO — acepta xlsx, xls, csv, tsv, txt
# ══════════════════════════════════════════════════════════════

ACCEPTED_EXTENSIONS = (".xlsx", ".xls", ".csv", ".tsv", ".txt", ".ods")

@router.post("/upload")
async def upload_transactions(
    request: Request,
    file: UploadFile = File(...),
    mapping: str = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Carga masiva con mapeo dinamico de columnas (detectado por IA en el frontend).
    Acepta: .xlsx, .xls, .csv, .tsv, .txt
    mapping: JSON string {"amount":"col_excel","channel":"col_excel",...}
    """
    # Rate limit: max 5 uploads por IP por minuto
    import time as _time
    from collections import defaultdict
    if not hasattr(upload_transactions, '_rate_store'):
        upload_transactions._rate_store = defaultdict(list)
    ip  = request.client.host if request.client else "unknown"
    now = _time.time()
    upload_transactions._rate_store[ip] = [t for t in upload_transactions._rate_store[ip] if now - t < 60]
    if len(upload_transactions._rate_store[ip]) >= 5:
        raise HTTPException(429, "Máximo 5 uploads por minuto. Espera un momento.")
    upload_transactions._rate_store[ip].append(now)

    import json as _json

    fname = (file.filename or "").lower()
    is_csv  = fname.endswith((".csv", ".tsv", ".txt"))
    is_xlsx = fname.endswith((".xlsx", ".xls", ".ods"))

    if not (is_csv or is_xlsx):
        raise HTTPException(
            400,
            f"Formato no soportado '{fname}'. Acepta: {', '.join(ACCEPTED_EXTENSIONS)}"
        )

    entity_code = current_user.entity_code
    if not entity_code and current_user.role != "superadmin":
        raise HTTPException(403, "Tu cuenta no tiene entidad asignada")

    col_map = {}
    if mapping:
        try:
            col_map = _json.loads(mapping)
        except Exception:
            col_map = {}

    contents = await file.read()

    # Parsear archivo
    try:
        if is_csv:
            all_rows = _parse_csv_content(contents)
        else:
            all_rows = _parse_xlsx_content(contents)
    except Exception as e:
        raise HTTPException(400, f"No se pudo leer el archivo: {str(e)}")

    if not all_rows:
        raise HTTPException(400, "El archivo esta vacio")

    # Primera fila = encabezados
    raw_headers   = [str(h or "").strip() for h in all_rows[0]]
    headers_lower = [h.lower() for h in raw_headers]
    data_rows     = all_rows[1:]

    def get_col(row, field_name):
        # 1) Mapeo explicito del frontend
        if field_name in col_map and col_map[field_name]:
            mapped_col = col_map[field_name]
            try:
                idx = raw_headers.index(mapped_col)
                return row[idx] if idx < len(row) else None
            except ValueError:
                pass
        # 2) Fallback por alias
        aliases = {
            "amount":         ["amount","monto","valor","importe","total","cantidad"],
            "channel":        ["channel","canal","tipo","type","medio"],
            "cardholder":     ["cardholder","titular","nombre","name","cliente"],
            "account_number": ["account_number","account","cuenta","tarjeta","card","numero"],
            "tx_id":          ["tx_id","txid","id","transaccion","transaction_id","referencia"],
            "city":           ["city","ciudad","localidad","location","ubicacion"],
            "datetime":       ["datetime","date","fecha","timestamp","hora"],
            "dest_account":   ["dest_account","cuenta_destino","destino","to_account","beneficiario_cuenta"],
            "dest_name":      ["dest_name","nombre_destino","beneficiario","beneficiary","to_name"],
        }
        for alias in aliases.get(field_name, [field_name]):
            try:
                idx = headers_lower.index(alias.lower())
                return row[idx] if idx < len(row) else None
            except ValueError:
                pass
        return None

    VALID_CHANNELS = {"CARD", "TRANSFER", "ATM", "WALLET", "DIGITAL_BANKING"}
    CH_ALIASES = {
        "BANCA_DIGITAL": "DIGITAL_BANKING", "ONLINE": "DIGITAL_BANKING",
        "INTERNET": "DIGITAL_BANKING", "WEB": "DIGITAL_BANKING",
        "APP": "DIGITAL_BANKING", "MOBILE": "DIGITAL_BANKING",
        "TRANSFERENCIA": "TRANSFER", "TARJETA": "CARD",
        "CAJERO": "ATM", "BILLETERA": "WALLET",
    }

    results, errors, saved = [], [], 0

    for i, row in enumerate(data_rows, start=2):
        # Saltar filas vacias
        if not row or all(str(c or "").strip() == "" for c in row):
            continue

        raw_amount  = get_col(row, "amount")
        channel_raw = str(get_col(row, "channel") or "").upper().strip()
        cardholder  = str(get_col(row, "cardholder") or "").strip()
        account     = str(get_col(row, "account_number") or "").strip()
        tx_id_raw   = get_col(row, "tx_id")
        city        = str(get_col(row, "city") or "").strip()
        dt_raw      = get_col(row, "datetime")
        dest_acc    = str(get_col(row, "dest_account") or "").strip()
        dest_name_v = str(get_col(row, "dest_name") or "").strip()

        tx_id = str(tx_id_raw or "").strip() or f"UP-{uuid.uuid4().hex[:8].upper()}"

        row_errors = []

        # Validar amount
        try:
            amount_str = str(raw_amount or "").replace(",", ".").strip()
            amount = float(amount_str)
            if amount <= 0:
                row_errors.append("amount debe ser > 0")
        except Exception:
            row_errors.append(f"amount invalido: '{raw_amount}'")
            amount = 0

        # Validar channel
        channel = CH_ALIASES.get(channel_raw, channel_raw)
        if channel not in VALID_CHANNELS:
            for vc in VALID_CHANNELS:
                if vc in channel or channel in vc:
                    channel = vc
                    break
            else:
                row_errors.append(
                    f"channel '{channel_raw}' invalido. "
                    f"Usa: CARD, TRANSFER, ATM, WALLET, DIGITAL_BANKING"
                )

        if not cardholder:
            row_errors.append("cardholder (titular) requerido")
        if not account:
            account = f"ACC-{i}"

        if row_errors:
            errors.append({"row": i, "tx_id": tx_id, "errors": row_errors})
            continue

        # Parsear fecha
        tx_dt = datetime.utcnow()
        if isinstance(dt_raw, datetime):
            tx_dt = dt_raw
        elif dt_raw:
            raw_str = str(dt_raw).strip().replace(" ", "T")
            for fmt in [None, "%Y-%m-%dT%H:%M", "%Y-%m-%d", "%d/%m/%Y %H:%M", "%d/%m/%Y"]:
                try:
                    parsed = (
                        datetime.fromisoformat(raw_str)
                        if fmt is None
                        else datetime.strptime(str(dt_raw).strip(), fmt)
                    )
                    if 1990 <= parsed.year <= 2100:
                        tx_dt = parsed
                        break
                except Exception:
                    continue

        payload = {
            "entity_code":    entity_code or "DEMO",
            "tx_id":          tx_id,
            "amount":         amount,
            "channel":        channel,
            "subtype":        channel,
            "cardholder":     cardholder,
            "city":           city or "Desconocida",
            "account_number": account,
            "created_at":     tx_dt.isoformat(),
            "dest_account":   dest_acc,
            "dest_name":      dest_name_v,
        }
        results.append(payload)

    if not results and errors:
        return {
            "status": "error",
            "message": "No se proceso ninguna fila valida",
            "total": len(errors), "saved": 0,
            "errors": len(errors), "error_detail": errors[:20], "scored": []
        }

    from main import score_transaction_internal
    from models import TransactionRecord

    scored = []
    for payload in results:
        try:
            existing = db.query(TransactionRecord).filter(
                TransactionRecord.tx_id == payload["tx_id"]
            ).first()
            if existing:
                payload["tx_id"] = payload["tx_id"] + "-" + uuid.uuid4().hex[:6].upper()

            result = score_transaction_internal(payload, db)
            scored.append({
                "tx_id":    payload["tx_id"],
                "amount":   payload["amount"],
                "channel":  payload["channel"],
                "score":    result.get("score_final",  result.get("scoring", {}).get("score_final", 0)),
                "decision": result.get("decision",     result.get("scoring", {}).get("decision",   "APROBADA")),
                "risk":     result.get("risk_level",   result.get("scoring", {}).get("risk_level",  "LOW")),
            })
            saved += 1
        except Exception as e:
            try:
                db.rollback()
            except Exception:
                pass
            err_msg = str(e)
            if "UNIQUE constraint failed" in err_msg or "unique constraint" in err_msg.lower():
                err_msg = f"tx_id '{payload['tx_id']}' duplicado — ya existe en la base de datos"
            errors.append({"tx_id": payload["tx_id"], "errors": [err_msg]})

    return {
        "status":       "ok",
        "total":        len(results) + len(errors),
        "saved":        saved,
        "errors":       len(errors),
        "error_detail": errors[:20],
        "scored":       scored[:200],
    }


# ── DESCARGAR PLANTILLA ───────────────────────────────────────

@router.get("/upload/template")
def download_template():
    return {
        "columns": [
            {"name": "tx_id",           "type": "texto",  "required": True,  "example": "TXN-001",          "description": "ID unico de la transaccion"},
            {"name": "amount",          "type": "numero", "required": True,  "example": "1500.00",          "description": "Monto en USD"},
            {"name": "channel",         "type": "texto",  "required": True,  "example": "CARD",             "description": "CARD | TRANSFER | ATM | WALLET | DIGITAL_BANKING"},
            {"name": "cardholder",      "type": "texto",  "required": True,  "example": "Juan Perez",       "description": "Nombre del titular"},
            {"name": "city",            "type": "texto",  "required": True,  "example": "Guayaquil",        "description": "Ciudad de la transaccion"},
            {"name": "datetime",        "type": "fecha",  "required": True,  "example": "2024-01-15 14:30", "description": "Fecha y hora (YYYY-MM-DD HH:MM)"},
            {"name": "account_number",  "type": "texto",  "required": True,  "example": "ACC1001",          "description": "Cuenta o tarjeta origen"},
            {"name": "dest_account",    "type": "texto",  "required": False, "example": "ACC2002",          "description": "Cuenta destino (solo TRANSFER)"},
            {"name": "dest_name",       "type": "texto",  "required": False, "example": "Maria Garcia",     "description": "Nombre destino (solo TRANSFER)"},
        ],
        "notes": [
            "Formatos aceptados: .xlsx, .xls, .csv, .tsv, .txt",
            "Para CSV/TSV el sistema detecta automaticamente el separador (coma, punto y coma, o tab)",
            "Las columnas dest_account y dest_name solo son necesarias para transacciones TRANSFER",
            "El campo tx_id debe ser unico por entidad",
            "El campo channel acepta aliases: BANCA_DIGITAL, ONLINE, APP, TRANSFERENCIA, TARJETA, CAJERO, BILLETERA",
            "Las fechas aceptan: YYYY-MM-DD HH:MM, YYYY-MM-DDTHH:MM:SS, DD/MM/YYYY",
        ]
    }

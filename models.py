"""
Models v2 — Entidades, Perfiles, Transacciones, Alertas con Feedback
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from sqlalchemy import (Column, Integer, String, Float, Boolean,
                        DateTime, Text, ForeignKey, JSON, Index)
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass

# ═══════════════════════════════════════════════════════════════
#  ORM — ENTIDADES
# ═══════════════════════════════════════════════════════════════

class Entity(Base):
    """Banco / Fintech / Billetera que usa el motor"""
    __tablename__ = "entities"

    id            = Column(Integer, primary_key=True)
    code          = Column(String(30), unique=True, index=True)   # "BANCO_XYZ"
    name          = Column(String(100))
    identity_type = Column(String(30), default="account_number")  # card_number | account_number | user_id | device_fingerprint
    # Umbrales personalizados por entidad
    score_alert   = Column(Integer, default=400)    # Score >= este → ALERTA
    score_review  = Column(Integer, default=600)    # Score >= este → REVISIÓN
    score_block   = Column(Integer, default=800)    # Score >= este → BLOQUEADA
    # Pesos del modelo (reglas vs ML)
    weight_rules  = Column(Float, default=0.4)
    weight_ml     = Column(Float, default=0.6)
    active        = Column(Boolean, default=True)
    created_at    = Column(DateTime, server_default=func.now())

    profiles      = relationship("Profile", back_populates="entity")
    transactions  = relationship("TransactionRecord", back_populates="entity")

    def to_dict(self):
        return {
            "id": self.id, "code": self.code, "name": self.name,
            "identity_type": self.identity_type,
            "thresholds": {"alert": self.score_alert, "review": self.score_review, "block": self.score_block},
            "weights": {"rules": self.weight_rules, "ml": self.weight_ml},
            "active": self.active,
        }


# ═══════════════════════════════════════════════════════════════
#  ORM — PERFILES TRANSACCIONALES
# ═══════════════════════════════════════════════════════════════

class Profile(Base):
    """Perfil acumulativo de una identidad (tarjeta/cuenta/usuario/device)"""
    __tablename__ = "profiles"
    __table_args__ = (
        Index("ix_profile_entity_identity", "entity_id", "identity_value"),
    )

    id              = Column(Integer, primary_key=True)
    entity_id       = Column(Integer, ForeignKey("entities.id"), index=True)
    identity_type   = Column(String(30))          # card_number | account_number | user_id | device_fingerprint
    identity_value  = Column(String(100), index=True)  # hash del valor real

    # ── Velocidad ────────────────────────────────────────────
    tx_count_1h     = Column(Integer, default=0)
    tx_count_24h    = Column(Integer, default=0)
    tx_count_7d     = Column(Integer, default=0)
    tx_count_30d    = Column(Integer, default=0)

    # ── Montos ───────────────────────────────────────────────
    amount_avg_30d  = Column(Float, default=0.0)
    amount_max_30d  = Column(Float, default=0.0)
    amount_sum_24h  = Column(Float, default=0.0)
    amount_sum_7d   = Column(Float, default=0.0)
    amount_sum_30d  = Column(Float, default=0.0)

    # ── Geografía ────────────────────────────────────────────
    cities_seen     = Column(JSON, default=list)    # ["Guayaquil", "Lima"]
    countries_seen  = Column(JSON, default=list)
    cities_24h      = Column(Integer, default=0)    # ciudades distintas últimas 24h
    is_traveler     = Column(Boolean, default=False)

    # ── Comportamiento ───────────────────────────────────────
    channels_used   = Column(JSON, default=dict)    # {"CARD": 15, "ATM": 3}
    hour_dist       = Column(JSON, default=dict)    # {"08": 5, "12": 8, ...}
    typical_hours   = Column(JSON, default=list)    # [8, 9, 12, 13, 18]
    merchants_seen  = Column(JSON, default=list)

    # ── AML ──────────────────────────────────────────────────
    sub_threshold_count = Column(Integer, default=0)  # TX debajo umbral CTR
    beneficiaries_new_30d = Column(Integer, default=0)
    layering_depth_max  = Column(Integer, default=0)

    # ── Score histórico ──────────────────────────────────────
    score_avg_30d   = Column(Float, default=0.0)
    score_max_ever  = Column(Integer, default=0)
    fraud_confirmed = Column(Integer, default=0)   # veces confirmada fraude
    false_positives = Column(Integer, default=0)   # veces marcada falso positivo
    risk_label      = Column(String(20), default="UNKNOWN")  # CLEAN | RISKY | FRAUD | UNKNOWN

    first_seen      = Column(DateTime, server_default=func.now())
    last_seen       = Column(DateTime, server_default=func.now(), onupdate=func.now())
    last_tx_at      = Column(DateTime, nullable=True)

    entity          = relationship("Entity", back_populates="profiles")

    def to_dict(self):
        return {
            "id": self.id,
            "identity_type": self.identity_type,
            "identity_value": self.identity_value,
            "velocity": {
                "tx_1h": self.tx_count_1h, "tx_24h": self.tx_count_24h,
                "tx_7d": self.tx_count_7d, "tx_30d": self.tx_count_30d,
            },
            "amounts": {
                "avg_30d": self.amount_avg_30d, "max_30d": self.amount_max_30d,
                "sum_24h": self.amount_sum_24h, "sum_7d": self.amount_sum_7d,
            },
            "geo": {
                "cities_seen": self.cities_seen or [],
                "countries_seen": self.countries_seen or [],
                "cities_24h": self.cities_24h,
                "is_traveler": self.is_traveler,
            },
            "behavior": {
                "channels": self.channels_used or {},
                "typical_hours": self.typical_hours or [],
                "merchants": (self.merchants_seen or [])[:10],
            },
            "aml": {
                "sub_threshold_count": self.sub_threshold_count,
                "beneficiaries_new_30d": self.beneficiaries_new_30d,
                "layering_depth_max": self.layering_depth_max,
            },
            "risk": {
                "score_avg_30d": self.score_avg_30d,
                "score_max_ever": self.score_max_ever,
                "fraud_confirmed": self.fraud_confirmed,
                "false_positives": self.false_positives,
                "risk_label": self.risk_label,
            },
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }

    def to_feature_vector(self) -> Dict[str, float]:
        """Convierte el perfil a vector de features para el modelo ML"""
        return {
            "tx_count_1h":          float(self.tx_count_1h or 0),
            "tx_count_24h":         float(self.tx_count_24h or 0),
            "tx_count_7d":          float(self.tx_count_7d or 0),
            "tx_count_30d":         float(self.tx_count_30d or 0),
            "amount_avg_30d":       float(self.amount_avg_30d or 0),
            "amount_max_30d":       float(self.amount_max_30d or 0),
            "amount_sum_24h":       float(self.amount_sum_24h or 0),
            "amount_sum_7d":        float(self.amount_sum_7d or 0),
            "cities_24h":           float(self.cities_24h or 0),
            "cities_total":         float(len(self.cities_seen or [])),
            "countries_total":      float(len(self.countries_seen or [])),
            "is_traveler":          float(self.is_traveler or 0),
            "channels_count":       float(len(self.channels_used or {})),
            "sub_threshold_count":  float(self.sub_threshold_count or 0),
            "beneficiaries_new_30d":float(self.beneficiaries_new_30d or 0),
            "layering_depth_max":   float(self.layering_depth_max or 0),
            "score_avg_30d":        float(self.score_avg_30d or 0),
            "score_max_ever":       float(self.score_max_ever or 0),
            "fraud_confirmed":      float(self.fraud_confirmed or 0),
            "false_positives":      float(self.false_positives or 0),
        }


# ═══════════════════════════════════════════════════════════════
#  ORM — TRANSACCIONES
# ═══════════════════════════════════════════════════════════════

class TransactionRecord(Base):
    __tablename__ = "transactions"

    id            = Column(Integer, primary_key=True)
    tx_id         = Column(String(24), unique=True, index=True)
    entity_id     = Column(Integer, ForeignKey("entities.id"), index=True)
    profile_id    = Column(Integer, ForeignKey("profiles.id"), index=True, nullable=True)

    # Identidad
    identity_type  = Column(String(30))
    identity_value = Column(String(100), index=True)

    # Transacción
    channel       = Column(String(20), index=True)
    subtype       = Column(String(30))
    amount        = Column(Float)
    currency      = Column(String(5), default="USD")
    merchant      = Column(String(100))
    city          = Column(String(100))
    country       = Column(String(50))
    cardholder    = Column(String(100))

    # Flags
    is_foreign    = Column(Boolean, default=False)
    new_device    = Column(Boolean, default=False)
    new_beneficiary = Column(Boolean, default=False)
    is_pep        = Column(Boolean, default=False)
    is_sanctioned = Column(Boolean, default=False)

    # Resultado del scoring
    score_rules   = Column(Integer, default=0)   # 0-999 solo reglas
    score_ml      = Column(Integer, default=0)   # 0-999 solo ML
    score_final   = Column(Integer, default=0)   # 0-999 combinado
    decision      = Column(String(20), index=True)
    risk_level    = Column(String(20), index=True)
    rules_triggered = Column(JSON, default=list)
    aml_flags     = Column(JSON, default=list)
    processing_ms = Column(Float)

    created_at    = Column(DateTime, server_default=func.now(), index=True)
    entity        = relationship("Entity", back_populates="transactions")

    def to_dict(self):
        return {
            "tx_id": self.tx_id, "entity_id": self.entity_id,
            "profile_id": self.profile_id,
            "identity": {"type": self.identity_type, "value": self.identity_value},
            "channel": self.channel, "subtype": self.subtype,
            "amount": self.amount, "currency": self.currency,
            "merchant": self.merchant, "city": self.city,
            "cardholder": self.cardholder,
            "scoring": {
                "score_rules": self.score_rules,
                "score_ml": self.score_ml,
                "score_final": self.score_final,
                "decision": self.decision,
                "risk_level": self.risk_level,
            },
            "rules_triggered": self.rules_triggered or [],
            "aml_flags": self.aml_flags or [],
            "processing_ms": self.processing_ms,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ═══════════════════════════════════════════════════════════════
#  ORM — ALERTAS + FEEDBACK
# ═══════════════════════════════════════════════════════════════

class Alert(Base):
    __tablename__ = "alerts"

    id            = Column(Integer, primary_key=True)
    tx_id         = Column(String(24), index=True)
    entity_id     = Column(Integer, ForeignKey("entities.id"), index=True)
    profile_id    = Column(Integer, ForeignKey("profiles.id"), nullable=True)

    channel       = Column(String(20))
    risk_level    = Column(String(20), index=True)
    decision      = Column(String(20))
    score_final   = Column(Integer)
    amount        = Column(Float)
    cardholder    = Column(String(100))
    top_rule      = Column(String(200))
    city          = Column(String(100))

    # Feedback del analista
    status        = Column(String(20), default="PENDING", index=True)
    # PENDING | CONFIRMED_FRAUD | FALSE_POSITIVE | UNDER_REVIEW
    analyst_label = Column(String(30), nullable=True)
    analyst_note  = Column(Text, nullable=True)
    analyst_id    = Column(String(50), nullable=True)
    labeled_at    = Column(DateTime, nullable=True)

    # Re-entrenamiento
    used_for_training = Column(Boolean, default=False)
    model_version_trained = Column(String(20), nullable=True)

    created_at    = Column(DateTime, server_default=func.now(), index=True)

    def to_dict(self):
        return {
            "id": self.id, "tx_id": self.tx_id,
            "entity_id": self.entity_id, "profile_id": self.profile_id,
            "channel": self.channel, "risk_level": self.risk_level,
            "decision": self.decision, "score_final": self.score_final,
            "amount": self.amount, "cardholder": self.cardholder,
            "top_rule": self.top_rule, "city": self.city,
            "feedback": {
                "status": self.status,
                "analyst_label": self.analyst_label,
                "analyst_note": self.analyst_note,
                "analyst_id": self.analyst_id,
                "labeled_at": self.labeled_at.isoformat() if self.labeled_at else None,
                "used_for_training": self.used_for_training,
            },
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ═══════════════════════════════════════════════════════════════
#  ORM — VERSIONES DEL MODELO ML
# ═══════════════════════════════════════════════════════════════

class ModelVersion(Base):
    __tablename__ = "model_versions"

    id              = Column(Integer, primary_key=True)
    version         = Column(String(20), unique=True)   # "global_v1", "BANCO_XYZ_v3"
    entity_id       = Column(Integer, nullable=True)    # NULL = modelo global
    model_type      = Column(String(30))                # "global" | "entity"
    samples_trained = Column(Integer, default=0)
    fraud_samples   = Column(Integer, default=0)
    fp_samples      = Column(Integer, default=0)
    accuracy        = Column(Float, nullable=True)
    precision_score = Column(Float, nullable=True)
    recall_score    = Column(Float, nullable=True)
    feature_names   = Column(JSON, default=list)
    is_active       = Column(Boolean, default=False)
    trained_at      = Column(DateTime, server_default=func.now())
    model_path      = Column(String(200), nullable=True)

    def to_dict(self):
        return {
            "id": self.id, "version": self.version,
            "entity_id": self.entity_id, "model_type": self.model_type,
            "training": {
                "samples": self.samples_trained,
                "fraud": self.fraud_samples,
                "false_positives": self.fp_samples,
            },
            "metrics": {
                "accuracy": self.accuracy,
                "precision": self.precision_score,
                "recall": self.recall_score,
            },
            "is_active": self.is_active,
            "trained_at": self.trained_at.isoformat() if self.trained_at else None,
        }


# ═══════════════════════════════════════════════════════════════
#  PYDANTIC SCHEMAS
# ═══════════════════════════════════════════════════════════════

class EntityCreate(BaseModel):
    code:          str = Field(..., example="BANCO_GUAYAQUIL")
    name:          str = Field(..., example="Banco de Guayaquil")
    identity_type: Literal["card_number","account_number","user_id","device_fingerprint"] = "account_number"
    score_alert:   int = Field(400, ge=0, le=999)
    score_review:  int = Field(600, ge=0, le=999)
    score_block:   int = Field(800, ge=0, le=999)
    weight_rules:  float = Field(0.4, ge=0.0, le=1.0)
    weight_ml:     float = Field(0.6, ge=0.0, le=1.0)


class TransactionIn(BaseModel):
    entity_code:    str   = Field(..., example="BANCO_GUAYAQUIL")
    identity_value: str   = Field(..., example="4532015112830366",
                                  description="Número de tarjeta, cuenta, user_id o device_id según config de la entidad")
    channel:        str   = Field(..., example="CARD")
    subtype:        Optional[str] = Field(None, example="ECOMMERCE")
    amount:         float = Field(..., gt=0, example=7500.0)
    currency:       str   = Field("USD", example="USD")
    merchant:       Optional[str] = Field(None, example="Amazon")
    city:           Optional[str] = Field(None, example="Guayaquil")
    country:        Optional[str] = Field(None, example="EC")
    cardholder:     Optional[str] = Field(None, example="Carlos Mendoza")
    is_foreign:     bool  = False
    new_device:     bool  = False
    new_beneficiary:bool  = False
    is_pep:         bool  = False
    is_sanctioned:  bool  = False

    class Config:
        json_schema_extra = {"example": {
            "entity_code": "BANCO_GUAYAQUIL",
            "identity_value": "4532015112830366",
            "channel": "CARD", "subtype": "ECOMMERCE",
            "amount": 7500.00, "currency": "USD",
            "merchant": "Steam", "city": "Miami", "country": "US",
            "cardholder": "Carlos Mendoza",
            "is_foreign": True, "new_device": False,
            "new_beneficiary": False, "is_pep": False, "is_sanctioned": False
        }}


class TransactionOut(BaseModel):
    tx_id:           str
    timestamp:       datetime
    entity_code:     str
    identity_type:   str
    identity_value:  str
    channel:         str
    amount:          float
    score_rules:     int = Field(..., description="Score 0-999 solo reglas")
    score_ml:        int = Field(..., description="Score 0-999 modelo ML")
    score_final:     int = Field(..., description="Score 0-999 combinado (reglas×peso + ML×peso)")
    decision:        str = Field(..., description="APROBADA | ALERTA | REVISIÓN | BLOQUEADA")
    risk_level:      str = Field(..., description="LOW | MEDIUM | HIGH | CRITICAL")
    triggered_rules: List[Dict]
    aml_flags:       List[Dict]
    profile_snapshot: Optional[Dict]
    processing_ms:   float


class AlertFeedback(BaseModel):
    analyst_label: Literal["CONFIRMED_FRAUD","FALSE_POSITIVE","UNDER_REVIEW"]
    analyst_note:  Optional[str] = Field(None, example="Cliente viajó a Miami esta semana")
    analyst_id:    Optional[str] = Field(None, example="analyst_001")
    trigger_retrain: bool = Field(True, description="Re-entrenar el modelo con este label")

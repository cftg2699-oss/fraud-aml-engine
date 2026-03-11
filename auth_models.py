"""
Auth Models — User table + Pydantic schemas
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from pydantic import BaseModel, Field
from typing import Optional
from database import Base


class User(Base):
    __tablename__ = "users"

    id               = Column(Integer, primary_key=True)
    email            = Column(String(120), unique=True, index=True)
    name             = Column(String(100))
    password         = Column(String(200))
    role             = Column(String(20), default="analyst")     # superadmin | analyst
    status           = Column(String(20), default="PENDING")     # PENDING | APPROVED | REJECTED
    entity_id        = Column(Integer, nullable=True)
    entity_code      = Column(String(30), nullable=True)
    # campos que el analista llena al registrarse
    requested_entity_code = Column(String(30), nullable=True)
    requested_entity_name = Column(String(120), nullable=True)
    is_active        = Column(Boolean, default=True)
    created_at       = Column(DateTime, server_default=func.now())
    approved_at      = Column(DateTime, nullable=True)
    approved_by      = Column(String(100), nullable=True)

    def to_dict(self):
        return {
            "id":                     self.id,
            "email":                  self.email,
            "name":                   self.name,
            "role":                   self.role,
            "status":                 self.status,
            "entity_id":              self.entity_id,
            "entity_code":            self.entity_code,
            "requested_entity_code":  self.requested_entity_code,
            "requested_entity_name":  self.requested_entity_name,
            "created_at":             self.created_at.isoformat() if self.created_at else None,
            "approved_at":            self.approved_at.isoformat() if self.approved_at else None,
        }

    def to_safe_dict(self):
        return self.to_dict()


# ── Pydantic schemas ─────────────────────────────────────────

class RegisterRequest(BaseModel):
    email:                str
    name:                 str
    password:             str = Field(min_length=6)
    requested_entity_code: Optional[str] = None   # ej: BANCO_XYZ
    requested_entity_name: Optional[str] = None   # ej: Banco de Guayaquil

class LoginRequest(BaseModel):
    email:    str
    password: str

class ApproveRequest(BaseModel):
    # ya no se manda entity_code desde el admin — se usa el que pidió el usuario
    pass

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    user:         dict

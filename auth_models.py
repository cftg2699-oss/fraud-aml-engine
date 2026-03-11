"""
Auth Models — User table + Pydantic schemas
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from database import Base


class User(Base):
    __tablename__ = "users"

    id          = Column(Integer, primary_key=True)
    email       = Column(String(120), unique=True, index=True)
    name        = Column(String(100))
    password    = Column(String(200))
    role        = Column(String(20), default="analyst")     # superadmin | analyst
    status      = Column(String(20), default="PENDING")     # PENDING | APPROVED | REJECTED
    entity_id   = Column(Integer, nullable=True)  # asignado por admin
    entity_code = Column(String(30), nullable=True)
    is_active   = Column(Boolean, default=True)
    created_at  = Column(DateTime, server_default=func.now())
    approved_at = Column(DateTime, nullable=True)
    approved_by = Column(String(100), nullable=True)

    def to_dict(self):
        return {
            "id":           self.id,
            "email":        self.email,
            "name":         self.name,
            "role":         self.role,
            "status":       self.status,
            "entity_id":    self.entity_id,
            "entity_code":  self.entity_code,
            "created_at":   self.created_at.isoformat() if self.created_at else None,
            "approved_at":  self.approved_at.isoformat() if self.approved_at else None,
        }

    def to_safe_dict(self):
        """Sin campos sensibles"""
        d = self.to_dict()
        return d


# ── Pydantic schemas ─────────────────────────────────────────

class RegisterRequest(BaseModel):
    email:    str
    name:     str
    password: str = Field(min_length=6)

class LoginRequest(BaseModel):
    email:    str
    password: str

class ApproveRequest(BaseModel):
    entity_code: str  # entidad que se le asigna al analista

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    user:         dict

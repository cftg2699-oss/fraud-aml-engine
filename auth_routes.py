"""
Auth Routes — Register, Login, Admin panel
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from datetime import datetime

from database import get_db
from auth_models import User, RegisterRequest, LoginRequest, ApproveRequest, TokenResponse
from models import Entity
from services.auth_service import (
    hash_password, verify_password, create_token,
    get_current_user, require_superadmin
)

router = APIRouter(prefix="/api/v2/auth", tags=["Autenticación"])


@router.post("/register")
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "Email ya registrado")
    user = User(
        email=data.email,
        name=data.name,
        password=hash_password(data.password),
        role="analyst",
        status="PENDING",
    )
    db.add(user); db.commit(); db.refresh(user)
    return {"message": "Cuenta creada. Espera aprobación del administrador.", "user_id": user.id}


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


@router.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return current_user.to_dict()


# ── Admin endpoints ──────────────────────────────────────────

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


@router.post("/admin/users/{user_id}/approve")
def approve_user(
    user_id: int,
    data: ApproveRequest,
    admin: User = Depends(require_superadmin),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(404, "Usuario no encontrado")

    entity = db.query(Entity).filter(Entity.code == data.entity_code).first()
    if not entity: raise HTTPException(404, f"Entidad '{data.entity_code}' no existe")

    # Check if entity already has an analyst
    existing = db.query(User).filter(
        User.entity_code == data.entity_code,
        User.status == "APPROVED",
        User.id != user_id
    ).first()
    if existing:
        raise HTTPException(400, f"La entidad '{data.entity_code}' ya tiene un analista asignado: {existing.email}")

    user.status      = "APPROVED"
    user.entity_id   = entity.id
    user.entity_code = data.entity_code
    user.approved_at = datetime.utcnow()
    user.approved_by = admin.email
    db.commit()
    return {"message": f"Usuario aprobado y asignado a {data.entity_code}", "user": user.to_dict()}


@router.post("/admin/users/{user_id}/reject")
def reject_user(
    user_id: int,
    admin: User = Depends(require_superadmin),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(404, "Usuario no encontrado")
    user.status = "REJECTED"
    db.commit()
    return {"message": "Usuario rechazado", "user": user.to_dict()}


@router.delete("/admin/users/{user_id}")
def delete_user(
    user_id: int,
    admin: User = Depends(require_superadmin),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(404, "Usuario no encontrado")
    db.delete(user); db.commit()
    return {"message": "Usuario eliminado"}


@router.post("/admin/setup-superadmin")
def setup_superadmin(data: RegisterRequest, db: Session = Depends(get_db)):
    """Solo funciona si no hay ningún superadmin todavía"""
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

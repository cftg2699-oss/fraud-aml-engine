"""
Auth Routes — Register, Login, Admin panel, Upload masivo
"""
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
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

    # Validar formato del código si se provee
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

    # Crear entidad si no existe
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
        db.flush()  # para obtener entity.id

    # Verificar que la entidad no tenga ya un analista aprobado
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


# ══════════════════════════════════════════════════════════════
#  UPLOAD MASIVO DE TRANSACCIONES (Excel .xlsx)
# ══════════════════════════════════════════════════════════════

@router.post("/upload")
async def upload_transactions(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Carga masiva de transacciones desde Excel.
    Columnas requeridas: tx_id, amount, channel, cardholder, city, datetime, account_number
    Columnas opcionales (solo TRANSFER): dest_account, dest_name
    """
    try:
        import openpyxl
    except ImportError:
        raise HTTPException(500, "openpyxl no instalado en el servidor")

    if not file.filename.endswith((".xlsx", ".xls")):
        raise HTTPException(400, "Solo se aceptan archivos Excel (.xlsx)")

    entity_code = current_user.entity_code
    if not entity_code and current_user.role != "superadmin":
        raise HTTPException(403, "Tu cuenta no tiene entidad asignada")

    contents = await file.read()
    try:
        wb = openpyxl.load_workbook(io.BytesIO(contents), data_only=True)
        ws = wb.active
    except Exception as e:
        raise HTTPException(400, f"No se pudo leer el archivo Excel: {str(e)}")

    # Leer headers
    headers = [str(cell.value or "").strip().lower() for cell in ws[1]]
    required = {"tx_id", "amount", "channel", "cardholder", "city", "datetime", "account_number"}
    missing = required - set(headers)
    if missing:
        raise HTTPException(400, f"Columnas faltantes: {', '.join(sorted(missing))}")

    def col(row, name):
        try:
            idx = headers.index(name)
            return row[idx].value
        except (ValueError, IndexError):
            return None

    VALID_CHANNELS = {"CARD", "TRANSFER", "ATM", "WALLET"}

    results = []
    errors  = []
    saved   = 0

    for i, row in enumerate(ws.iter_rows(min_row=2), start=2):
        if all(c.value is None for c in row):
            continue  # fila vacía

        tx_id      = str(col(row, "tx_id") or "").strip()
        raw_amount = col(row, "amount")
        channel    = str(col(row, "channel") or "").upper().strip()
        cardholder = str(col(row, "cardholder") or "").strip()
        city       = str(col(row, "city") or "").strip()
        dt_raw     = col(row, "datetime")
        account    = str(col(row, "account_number") or "").strip()
        dest_acc   = str(col(row, "dest_account") or "").strip() if "dest_account" in headers else ""
        dest_name  = str(col(row, "dest_name") or "").strip() if "dest_name" in headers else ""

        # Validaciones básicas
        row_errors = []
        if not tx_id:
            tx_id = f"UP-{uuid.uuid4().hex[:8].upper()}"
        try:
            amount = float(str(raw_amount).replace(",", "."))
            if amount <= 0:
                row_errors.append("amount debe ser > 0")
        except:
            row_errors.append(f"amount inválido: {raw_amount}")
            amount = 0

        if channel not in VALID_CHANNELS:
            row_errors.append(f"channel '{channel}' inválido (usa: CARD, TRANSFER, ATM, WALLET)")

        if row_errors:
            errors.append({"row": i, "tx_id": tx_id, "errors": row_errors})
            continue

        # Parsear fecha
        if isinstance(dt_raw, datetime):
            tx_dt = dt_raw
        else:
            try:
                tx_dt = datetime.fromisoformat(str(dt_raw))
            except:
                tx_dt = datetime.utcnow()

        # Construir payload para el motor de scoring
        payload = {
            "entity_code":    entity_code or "DEMO",
            "tx_id":          tx_id,
            "amount":         amount,
            "channel":        channel,
            "subtype":        "TRANSFER" if channel == "TRANSFER" else channel,
            "cardholder":     cardholder,
            "city":           city,
            "account_number": account,
            "created_at":     tx_dt.isoformat(),
        }
        if channel == "TRANSFER":
            payload["dest_account"] = dest_acc
            payload["dest_name"]    = dest_name

        results.append(payload)

    if not results:
        return {
            "status": "error",
            "message": "No se procesó ninguna fila válida",
            "errors": errors
        }

    # Llamar al motor de scoring interno
    # Importamos aquí para evitar importaciones circulares
    from main import score_transaction_internal

    scored = []
    for payload in results:
        try:
            result = score_transaction_internal(payload, db)
            scored.append({
                "tx_id":    payload["tx_id"],
                "amount":   payload["amount"],
                "channel":  payload["channel"],
                "score":    result["scoring"]["score_final"],
                "decision": result["scoring"]["decision"],
                "risk":     result["scoring"]["risk_level"],
            })
            saved += 1
        except Exception as e:
            errors.append({"tx_id": payload["tx_id"], "errors": [str(e)]})

    return {
        "status":  "ok",
        "total":   len(results) + len(errors),
        "saved":   saved,
        "errors":  len(errors),
        "error_detail": errors[:20],  # máximo 20 errores detallados
        "scored":  scored[:200],       # preview de hasta 200 resultados
    }


# ── DESCARGAR PLANTILLA EXCEL ──────────────────────────────────

@router.get("/upload/template")
def download_template():
    """Devuelve una URL de ejemplo y la estructura esperada del Excel"""
    return {
        "columns": [
            {"name": "tx_id",           "type": "texto",   "required": True,  "example": "TXN-001",         "description": "ID único de la transacción"},
            {"name": "amount",          "type": "número",  "required": True,  "example": "1500.00",         "description": "Monto en USD"},
            {"name": "channel",         "type": "texto",   "required": True,  "example": "CARD",            "description": "CARD | TRANSFER | ATM | WALLET"},
            {"name": "cardholder",      "type": "texto",   "required": True,  "example": "Juan Pérez",      "description": "Nombre del titular"},
            {"name": "city",            "type": "texto",   "required": True,  "example": "Guayaquil",       "description": "Ciudad de la transacción"},
            {"name": "datetime",        "type": "fecha",   "required": True,  "example": "2024-01-15 14:30","description": "Fecha y hora (YYYY-MM-DD HH:MM)"},
            {"name": "account_number",  "type": "texto",   "required": True,  "example": "ACC1001",         "description": "Cuenta o tarjeta origen"},
            {"name": "dest_account",    "type": "texto",   "required": False, "example": "ACC2002",         "description": "Cuenta destino (solo TRANSFER)"},
            {"name": "dest_name",       "type": "texto",   "required": False, "example": "María García",    "description": "Nombre destino (solo TRANSFER)"},
        ],
        "notes": [
            "Las columnas dest_account y dest_name solo son necesarias para transacciones de tipo TRANSFER",
            "El campo tx_id debe ser único por entidad",
            "El campo channel solo acepta: CARD, TRANSFER, ATM, WALLET",
            "Las fechas deben estar en formato YYYY-MM-DD HH:MM o YYYY-MM-DDTHH:MM:SS",
        ]
    }

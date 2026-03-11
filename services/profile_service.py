"""
Profile Service — Construye y actualiza perfiles transaccionales
"""
import hashlib
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from models import Profile, Entity, TransactionRecord


def _hash_identity(value: str) -> str:
    """Hash de la identidad para privacidad (no guardamos número real)"""
    return hashlib.sha256(value.encode()).hexdigest()[:24]


def get_or_create_profile(db: Session, entity: Entity, identity_value: str) -> Profile:
    """Obtiene el perfil existente o crea uno nuevo"""
    hashed = _hash_identity(identity_value)
    profile = (db.query(Profile)
               .filter(Profile.entity_id == entity.id,
                       Profile.identity_value == hashed)
               .first())
    if not profile:
        profile = Profile(
            entity_id      = entity.id,
            identity_type  = entity.identity_type,
            identity_value = hashed,
            cities_seen    = [],
            countries_seen = [],
            channels_used  = {},
            hour_dist      = {},
            typical_hours  = [],
            merchants_seen = [],
        )
        db.add(profile)
        db.flush()  # get ID without commit
    return profile


def update_profile(db: Session, profile: Profile, tx, score: int) -> Profile:
    """Actualiza el perfil con los datos de la nueva transacción"""
    now = datetime.utcnow()
    hour = str(now.hour)

    # ── Velocidad ──────────────────────────────────────────────
    # Conteo real desde BD para las ventanas de tiempo
    one_hour_ago  = now - timedelta(hours=1)
    one_day_ago   = now - timedelta(hours=24)
    seven_days_ago= now - timedelta(days=7)

    profile.tx_count_1h  = (db.query(TransactionRecord)
                            .filter(TransactionRecord.profile_id == profile.id,
                                    TransactionRecord.created_at >= one_hour_ago).count()) + 1
    profile.tx_count_24h = (db.query(TransactionRecord)
                            .filter(TransactionRecord.profile_id == profile.id,
                                    TransactionRecord.created_at >= one_day_ago).count()) + 1
    profile.tx_count_7d  = (db.query(TransactionRecord)
                            .filter(TransactionRecord.profile_id == profile.id,
                                    TransactionRecord.created_at >= seven_days_ago).count()) + 1
    profile.tx_count_30d = (profile.tx_count_30d or 0) + 1

    # ── Montos ─────────────────────────────────────────────────
    profile.amount_sum_24h = (profile.amount_sum_24h or 0) + tx.amount
    profile.amount_sum_7d  = (profile.amount_sum_7d  or 0) + tx.amount
    profile.amount_sum_30d = (profile.amount_sum_30d or 0) + tx.amount

    # Promedio acumulado (Welford)
    n = profile.tx_count_30d
    old_avg = profile.amount_avg_30d or 0
    profile.amount_avg_30d = old_avg + (tx.amount - old_avg) / n
    if tx.amount > (profile.amount_max_30d or 0):
        profile.amount_max_30d = tx.amount

    # ── Geografía ──────────────────────────────────────────────
    cities = profile.cities_seen or []
    if tx.city and tx.city not in cities:
        cities.append(tx.city)
    profile.cities_seen = cities

    countries = profile.countries_seen or []
    if tx.country and tx.country not in countries:
        countries.append(tx.country)
    profile.countries_seen = countries

    # Ciudades distintas en últimas 24h
    cities_24h = (db.query(TransactionRecord.city)
                  .filter(TransactionRecord.profile_id == profile.id,
                          TransactionRecord.created_at >= one_day_ago)
                  .distinct().all())
    unique_cities = set(c[0] for c in cities_24h if c[0])
    if tx.city:
        unique_cities.add(tx.city)
    profile.cities_24h = len(unique_cities)
    profile.is_traveler = len(profile.countries_seen or []) > 2

    # ── Canales ────────────────────────────────────────────────
    channels = profile.channels_used or {}
    channels[tx.channel] = channels.get(tx.channel, 0) + 1
    profile.channels_used = channels

    # ── Horarios ───────────────────────────────────────────────
    hour_dist = profile.hour_dist or {}
    hour_dist[hour] = hour_dist.get(hour, 0) + 1
    profile.hour_dist = hour_dist
    # Horas típicas = top 6 más frecuentes
    profile.typical_hours = [int(h) for h, _ in
                              sorted(hour_dist.items(), key=lambda x: -x[1])[:6]]

    # ── Comercios ──────────────────────────────────────────────
    if tx.merchant:
        merchants = profile.merchants_seen or []
        if tx.merchant not in merchants:
            merchants.append(tx.merchant)
        profile.merchants_seen = merchants[-30:]  # últimos 30

    # ── AML ────────────────────────────────────────────────────
    if tx.amount and 9500 <= tx.amount < 10000:
        profile.sub_threshold_count = (profile.sub_threshold_count or 0) + 1
    if tx.new_beneficiary:
        profile.beneficiaries_new_30d = (profile.beneficiaries_new_30d or 0) + 1

    # ── Score histórico ────────────────────────────────────────
    old_score_avg = profile.score_avg_30d or 0
    profile.score_avg_30d = old_score_avg + (score - old_score_avg) / n
    if score > (profile.score_max_ever or 0):
        profile.score_max_ever = score

    profile.last_tx_at = now

    return profile


def build_profile_features(profile: Profile, tx) -> dict:
    """
    Construye el vector de features para el modelo ML
    combinando el perfil histórico con el contexto de la TX actual.
    """
    pf = profile.to_feature_vector() if profile else {}
    avg = pf.get("amount_avg_30d", 1) or 1

    features = {
        # Perfil base
        **pf,
        # Features de la TX actual vs perfil
        "amount_vs_avg":       tx.amount / avg if avg > 0 else 1.0,
        "amount_vs_max":       tx.amount / max(pf.get("amount_max_30d", 1), 1),
        "amount_abs":          tx.amount,
        "is_foreign":          float(tx.is_foreign),
        "new_device":          float(tx.new_device),
        "new_beneficiary":     float(tx.new_beneficiary),
        "is_pep":              float(tx.is_pep),
        "is_sanctioned":       float(tx.is_sanctioned),
        "channel_is_card":     float(tx.channel == "CARD"),
        "channel_is_transfer": float(tx.channel == "TRANSFER"),
        "channel_is_wallet":   float(tx.channel == "WALLET"),
        "channel_is_atm":      float(tx.channel == "ATM"),
        "hour_of_day":         float(datetime.utcnow().hour),
        "is_night":            float(datetime.utcnow().hour < 6 or datetime.utcnow().hour > 22),
        # Anomalía de ciudad
        "city_is_new":         float(tx.city not in (profile.cities_seen or []) if tx.city else 0),
        # Anomalía de monto
        "amount_10x_avg":      float(tx.amount > avg * 10),
        "amount_above_5k":     float(tx.amount > 5000),
        "amount_near_threshold": float(9500 <= tx.amount < 10000),
    }
    return features

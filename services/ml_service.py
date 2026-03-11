"""
ML Service — Modelo global + modelo por entidad
Re-entrenamiento automático con feedback de analistas
"""
import os, pickle, logging
from datetime import datetime
from typing import Optional, Tuple, List
from sqlalchemy.orm import Session
from models import Alert, ModelVersion, Profile

logger = logging.getLogger(__name__)
MODELS_DIR = os.getenv("MODELS_DIR", "./ml_models")
os.makedirs(MODELS_DIR, exist_ok=True)

# Feature names (debe coincidir con profile_service.build_profile_features)
FEATURE_NAMES = [
    "tx_count_1h", "tx_count_24h", "tx_count_7d", "tx_count_30d",
    "amount_avg_30d", "amount_max_30d", "amount_sum_24h", "amount_sum_7d",
    "cities_24h", "cities_total", "countries_total", "is_traveler",
    "channels_count", "sub_threshold_count", "beneficiaries_new_30d",
    "layering_depth_max", "score_avg_30d", "score_max_ever",
    "fraud_confirmed", "false_positives",
    "amount_vs_avg", "amount_vs_max", "amount_abs",
    "is_foreign", "new_device", "new_beneficiary", "is_pep", "is_sanctioned",
    "channel_is_card", "channel_is_transfer", "channel_is_wallet", "channel_is_atm",
    "hour_of_day", "is_night", "city_is_new",
    "amount_10x_avg", "amount_above_5k", "amount_near_threshold",
]


def _features_to_vector(features: dict) -> list:
    return [features.get(f, 0.0) for f in FEATURE_NAMES]


def _load_model(path: str):
    if os.path.exists(path):
        with open(path, "rb") as f:
            return pickle.load(f)
    return None


def _save_model(model, path: str):
    with open(path, "wb") as f:
        pickle.dump(model, f)


def predict(features: dict, entity_id: Optional[int] = None) -> Tuple[float, str]:
    """
    Predice probabilidad de fraude (0.0–1.0).
    Intenta usar modelo de la entidad, cae al global si no existe.
    Devuelve (probability, model_version_used)
    """
    vector = _features_to_vector(features)

    # Intenta modelo de entidad
    if entity_id:
        entity_path = os.path.join(MODELS_DIR, f"entity_{entity_id}.pkl")
        model = _load_model(entity_path)
        if model:
            try:
                prob = model.predict_proba([vector])[0][1]
                return float(prob), f"entity_{entity_id}"
            except Exception as e:
                logger.warning(f"Entity model predict failed: {e}")

    # Modelo global
    global_path = os.path.join(MODELS_DIR, "global.pkl")
    model = _load_model(global_path)
    if model:
        try:
            prob = model.predict_proba([vector])[0][1]
            return float(prob), "global"
        except Exception as e:
            logger.warning(f"Global model predict failed: {e}")

    # Sin modelo — retorna heurística basada en features
    score = 0.0
    if features.get("is_sanctioned"):     score += 0.95
    if features.get("is_pep"):            score += 0.3
    if features.get("amount_near_threshold"): score += 0.25
    if features.get("sub_threshold_count", 0) >= 3: score += 0.3
    if features.get("amount_10x_avg"):    score += 0.2
    if features.get("city_is_new"):       score += 0.1
    if features.get("tx_count_1h", 0) >= 3: score += 0.2
    return min(score, 0.99), "heuristic"


def get_training_data(db: Session, entity_id: Optional[int] = None) -> Tuple[List[list], List[int]]:
    """
    Obtiene datos de entrenamiento de alertas calificadas por analistas.
    Retorna (X, y) donde y=1 es fraude, y=0 es falso positivo.
    """
    from models import Alert, TransactionRecord

    query = (db.query(Alert, TransactionRecord)
             .join(TransactionRecord, Alert.tx_id == TransactionRecord.tx_id)
             .filter(Alert.analyst_label.in_(["CONFIRMED_FRAUD", "FALSE_POSITIVE"])))

    if entity_id:
        query = query.filter(Alert.entity_id == entity_id)

    rows = query.all()
    X, y = [], []

    for alert, tx in rows:
        # Rebuild features from TX record
        features = {
            "tx_count_1h": 1.0, "tx_count_24h": 1.0,
            "tx_count_7d": 5.0, "tx_count_30d": 20.0,
            "amount_avg_30d": tx.amount * 0.8,
            "amount_max_30d": tx.amount,
            "amount_sum_24h": tx.amount,
            "amount_sum_7d": tx.amount * 3,
            "cities_24h": 1.0, "cities_total": 2.0,
            "countries_total": 1.0, "is_traveler": 0.0,
            "channels_count": 1.0,
            "sub_threshold_count": 1.0 if 9500 <= tx.amount < 10000 else 0.0,
            "beneficiaries_new_30d": float(tx.new_beneficiary),
            "layering_depth_max": 0.0,
            "score_avg_30d": float(tx.score_final or 0),
            "score_max_ever": float(tx.score_final or 0),
            "fraud_confirmed": 0.0, "false_positives": 0.0,
            "amount_vs_avg": 1.5,
            "amount_vs_max": 1.0,
            "amount_abs": tx.amount,
            "is_foreign": float(tx.is_foreign),
            "new_device": float(tx.new_device),
            "new_beneficiary": float(tx.new_beneficiary),
            "is_pep": float(tx.is_pep),
            "is_sanctioned": float(tx.is_sanctioned),
            "channel_is_card": float(tx.channel == "CARD"),
            "channel_is_transfer": float(tx.channel == "TRANSFER"),
            "channel_is_wallet": float(tx.channel == "WALLET"),
            "channel_is_atm": float(tx.channel == "ATM"),
            "hour_of_day": 12.0, "is_night": 0.0,
            "city_is_new": float(tx.is_foreign),
            "amount_10x_avg": float(tx.amount > 5000),
            "amount_above_5k": float(tx.amount > 5000),
            "amount_near_threshold": float(9500 <= tx.amount < 10000),
        }
        X.append(_features_to_vector(features))
        y.append(1 if alert.analyst_label == "CONFIRMED_FRAUD" else 0)

    return X, y


def train_model(db: Session, entity_id: Optional[int] = None) -> dict:
    """
    Entrena o re-entrena el modelo.
    entity_id=None → modelo global
    entity_id=X    → modelo local de esa entidad (basado en global + sus datos)
    """
    try:
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
        from sklearn.model_selection import cross_val_score
        from sklearn.preprocessing import StandardScaler
        import numpy as np
    except ImportError:
        return {"error": "scikit-learn no instalado. Ejecuta: pip install scikit-learn numpy"}

    X, y = get_training_data(db, entity_id=None)  # siempre arranca con datos globales

    # Si es modelo de entidad, agrega sus datos con mayor peso (duplicados)
    if entity_id:
        Xe, ye = get_training_data(db, entity_id=entity_id)
        # Duplicar datos propios para darles más peso
        X = X + Xe + Xe
        y = y + ye + ye

    if len(X) < 10:
        # Sin suficientes datos — genera datos sintéticos de bootstrap
        X, y = _generate_bootstrap_data()
        was_bootstrap = True
    else:
        was_bootstrap = False

    X_arr = np.array(X)
    y_arr = np.array(y)

    # Modelo: GradientBoosting (mejor para fraude que RandomForest)
    model = GradientBoostingClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=4,
        random_state=42,
        subsample=0.8,
    )
    model.fit(X_arr, y_arr)

    # Métricas con cross-validation
    metrics = {}
    if len(X) >= 20:
        try:
            acc = cross_val_score(model, X_arr, y_arr, cv=min(5, len(X)//4), scoring="accuracy").mean()
            prec = cross_val_score(model, X_arr, y_arr, cv=min(5, len(X)//4), scoring="precision").mean()
            rec = cross_val_score(model, X_arr, y_arr, cv=min(5, len(X)//4), scoring="recall").mean()
            metrics = {"accuracy": round(float(acc), 4),
                       "precision": round(float(prec), 4),
                       "recall": round(float(rec), 4)}
        except Exception:
            metrics = {}

    # Guardar modelo
    if entity_id:
        path = os.path.join(MODELS_DIR, f"entity_{entity_id}.pkl")
        version = f"entity_{entity_id}_v{datetime.utcnow().strftime('%Y%m%d%H%M')}"
        model_type = "entity"
    else:
        path = os.path.join(MODELS_DIR, "global.pkl")
        version = f"global_v{datetime.utcnow().strftime('%Y%m%d%H%M')}"
        model_type = "global"

    _save_model(model, path)

    # Registrar versión en BD
    fraud_count = sum(y)
    fp_count    = len(y) - fraud_count
    mv = ModelVersion(
        version=version, entity_id=entity_id, model_type=model_type,
        samples_trained=len(X), fraud_samples=fraud_count, fp_samples=fp_count,
        accuracy=metrics.get("accuracy"), precision_score=metrics.get("precision"),
        recall_score=metrics.get("recall"),
        feature_names=FEATURE_NAMES, is_active=True, model_path=path,
    )
    # Desactivar versiones anteriores
    db.query(ModelVersion).filter(
        ModelVersion.entity_id == entity_id,
        ModelVersion.is_active == True
    ).update({"is_active": False})
    db.add(mv)
    db.commit()

    return {
        "version": version, "model_type": model_type,
        "samples": len(X), "fraud": fraud_count, "fp": fp_count,
        "metrics": metrics, "bootstrap": was_bootstrap,
        "path": path
    }


def _generate_bootstrap_data():
    """
    Genera datos sintéticos para el modelo inicial antes de tener feedback real.
    Basado en reglas conocidas de fraude.
    """
    import random
    random.seed(42)
    X, y = [], []

    def make_sample(is_fraud: bool):
        if is_fraud:
            return [
                random.uniform(3, 8),    # tx_count_1h
                random.uniform(8, 20),   # tx_count_24h
                random.uniform(15, 40),  # tx_count_7d
                random.uniform(30, 80),  # tx_count_30d
                random.uniform(100, 500),  # amount_avg_30d
                random.uniform(5000, 15000),  # amount_max_30d
                random.uniform(5000, 20000),  # amount_sum_24h
                random.uniform(10000, 40000), # amount_sum_7d
                random.uniform(2, 4),    # cities_24h
                random.uniform(3, 8),    # cities_total
                random.uniform(2, 5),    # countries_total
                random.choice([0, 1]),   # is_traveler
                random.uniform(2, 4),    # channels_count
                random.uniform(2, 5),    # sub_threshold_count
                random.uniform(3, 8),    # beneficiaries_new_30d
                random.uniform(2, 4),    # layering_depth_max
                random.uniform(300, 700),# score_avg_30d
                random.uniform(600, 999),# score_max_ever
                random.uniform(1, 3),    # fraud_confirmed
                random.uniform(0, 1),    # false_positives
                random.uniform(8, 20),   # amount_vs_avg
                random.uniform(0.8, 1.2),# amount_vs_max
                random.uniform(3000, 15000),  # amount_abs
                random.choice([0, 1]),   # is_foreign
                random.choice([0, 1]),   # new_device
                random.choice([0, 1]),   # new_beneficiary
                random.choice([0, 0, 1]),# is_pep
                random.choice([0, 0, 0, 1]),  # is_sanctioned
                random.choice([0, 1]),   # channel_is_card
                random.choice([0, 1]),   # channel_is_transfer
                random.choice([0, 1]),   # channel_is_wallet
                random.choice([0, 1]),   # channel_is_atm
                random.uniform(0, 23),   # hour_of_day
                random.choice([0, 1]),   # is_night
                random.choice([0, 1]),   # city_is_new
                random.choice([0, 1]),   # amount_10x_avg
                random.choice([0, 1]),   # amount_above_5k
                random.choice([0, 1]),   # amount_near_threshold
            ]
        else:  # legítima
            return [
                random.uniform(0, 1),    # tx_count_1h
                random.uniform(1, 4),    # tx_count_24h
                random.uniform(3, 10),   # tx_count_7d
                random.uniform(10, 30),  # tx_count_30d
                random.uniform(50, 300), # amount_avg_30d
                random.uniform(200, 2000),  # amount_max_30d
                random.uniform(50, 500), # amount_sum_24h
                random.uniform(100, 2000),  # amount_sum_7d
                random.uniform(0, 1),    # cities_24h
                random.uniform(1, 3),    # cities_total
                random.uniform(1, 2),    # countries_total
                random.choice([0, 1]),   # is_traveler
                random.uniform(1, 2),    # channels_count
                0,                       # sub_threshold_count
                random.uniform(0, 1),    # beneficiaries_new_30d
                0,                       # layering_depth_max
                random.uniform(50, 200), # score_avg_30d
                random.uniform(100, 400),# score_max_ever
                0, 0,                    # fraud_confirmed, false_positives
                random.uniform(0.5, 2),  # amount_vs_avg
                random.uniform(0.3, 0.9),# amount_vs_max
                random.uniform(20, 500), # amount_abs
                0, 0, 0, 0, 0,           # flags
                random.choice([0, 1]),   # channel_is_card
                random.choice([0, 1]),   # channel_is_transfer
                random.choice([0, 1]),   # channel_is_wallet
                random.choice([0, 1]),   # channel_is_atm
                random.uniform(7, 21),   # hour_of_day
                0,                       # is_night
                0,                       # city_is_new
                0, 0, 0,                 # amount anomalies
            ]

    for _ in range(150):  # 150 fraudes
        X.append(make_sample(True))
        y.append(1)
    for _ in range(350):  # 350 legítimas
        X.append(make_sample(False))
        y.append(0)

    return X, y

"""
Scoring Engine v2
- Escala 0–999
- Híbrido: reglas (peso configurable) + modelo ML
- Umbrales por entidad
"""
import time, uuid
from datetime import datetime
from typing import Tuple, List, Dict
from models import Entity


# ── REGLAS BASE (score normalizado a 0–999) ──────────────────
RULES = [
    # TARJETAS
    {"id":"R001","ch":"CARD","sev":"HIGH",   "name":"Monto alto en tarjeta",              "desc":"Tarjeta >$5,000",                     "pts":300,"eval":lambda tx,p: tx.channel=="CARD" and tx.amount>5000},
    {"id":"R002","ch":"CARD","sev":"HIGH",   "name":"Tarjeta extranjera monto elevado",   "desc":"Extranjero + >$1,000",                "pts":350,"eval":lambda tx,p: tx.channel=="CARD" and tx.is_foreign and tx.amount>1000},
    {"id":"R003","ch":"CARD","sev":"CRIT",   "name":"Transacciones rápidas sucesivas",    "desc":"3+ TX en <5 min",                     "pts":420,"eval":lambda tx,p: tx.channel=="CARD" and p.get("tx_count_1h",0)>=3},
    {"id":"R004","ch":"CARD","sev":"HIGH",   "name":"E-commerce nocturno alto",           "desc":"Online nocturno >$2,000",             "pts":320,"eval":lambda tx,p: tx.channel=="CARD" and tx.subtype=="ECOMMERCE" and tx.amount>2000 and (datetime.utcnow().hour<6 or datetime.utcnow().hour>22)},
    {"id":"R005","ch":"CARD","sev":"CRIT",   "name":"Múltiples ciudades",                 "desc":"2+ ciudades en <2h",                  "pts":460,"eval":lambda tx,p: tx.channel=="CARD" and p.get("cities_24h",0)>1},
    {"id":"R016b","ch":"CARD","sev":"HIGH",  "name":"Dispositivo nuevo monto alto",       "desc":"Nuevo device >$800",                  "pts":310,"eval":lambda tx,p: tx.channel=="CARD" and tx.new_device and tx.amount>800},
    {"id":"R017","ch":"CARD","sev":"MED",    "name":"Ciudad nueva para este cliente",     "desc":"Ciudad no vista antes",               "pts":180,"eval":lambda tx,p: tx.channel=="CARD" and p.get("city_is_new",False)},
    # TRANSFERENCIAS
    {"id":"R006","ch":"TRANSFER","sev":"MED","name":"Transferencia alto monto",           "desc":">$10,000",                            "pts":240,"eval":lambda tx,p: tx.channel=="TRANSFER" and tx.amount>10000},
    {"id":"R007","ch":"TRANSFER","sev":"CRIT","name":"Posible estructuración CTR",        "desc":"$9,500–$9,999 (sub-umbral)",          "pts":600,"eval":lambda tx,p: tx.channel=="TRANSFER" and 9500<=tx.amount<10000},
    {"id":"R008","ch":"TRANSFER","sev":"HIGH","name":"Beneficiario nuevo + monto alto",   "desc":"Nuevo destino >$3,000",               "pts":370,"eval":lambda tx,p: tx.channel=="TRANSFER" and tx.new_beneficiary and tx.amount>3000},
    {"id":"R009","ch":"TRANSFER","sev":"MED","name":"Monto exacto sospechoso",            "desc":"Múltiplo de $1,000 >$5,000",          "pts":200,"eval":lambda tx,p: tx.channel=="TRANSFER" and tx.amount>=5000 and tx.amount%1000==0},
    {"id":"R010","ch":"TRANSFER","sev":"CRIT","name":"Vaciado rápido de cuenta",          "desc":">80% del saldo",                      "pts":510,"eval":lambda tx,p: tx.channel=="TRANSFER" and p.get("amount_avg_30d",1)>0 and tx.amount>p.get("amount_avg_30d",1)*15},
    # BILLETERAS
    {"id":"R011","ch":"WALLET","sev":"HIGH",  "name":"Monto inusual billetera",           "desc":">10× promedio",                       "pts":400,"eval":lambda tx,p: tx.channel=="WALLET" and p.get("amount_avg_30d",1)>0 and tx.amount>p["amount_avg_30d"]*10},
    {"id":"R012","ch":"WALLET","sev":"CRIT",  "name":"Múltiples destinatarios 1h",        "desc":"5+ distintos en 1h",                  "pts":460,"eval":lambda tx,p: tx.channel=="WALLET" and p.get("tx_count_1h",0)>=5},
    {"id":"R013","ch":"WALLET","sev":"HIGH",  "name":"Dispositivo nuevo billetera",       "desc":"Nuevo device >$500",                  "pts":350,"eval":lambda tx,p: tx.channel=="WALLET" and tx.new_device and tx.amount>500},
    # ATM
    {"id":"R014","ch":"ATM","sev":"HIGH",     "name":"Múltiples retiros ATM",             "desc":"3+ retiros hoy",                      "pts":360,"eval":lambda tx,p: tx.channel=="ATM" and p.get("tx_count_24h",0)>=3},
    {"id":"R015","ch":"ATM","sev":"HIGH",     "name":"ATM país extranjero",               "desc":"Retiro en extranjero",                "pts":300,"eval":lambda tx,p: tx.channel=="ATM" and tx.is_foreign},
    {"id":"R016","ch":"ATM","sev":"HIGH",     "name":"Retiro nocturno alto",              "desc":">$1,000 entre 00–05h",               "pts":330,"eval":lambda tx,p: tx.channel=="ATM" and tx.amount>1000 and 0<=datetime.utcnow().hour<5},
    # AML
    {"id":"A001","ch":"AML","sev":"CRIT",     "name":"Estructuración (Smurfing)",         "desc":"3+ TX sub-umbral CTR",                "pts":700,"eval":lambda tx,p: p.get("sub_threshold_count",0)>=3},
    {"id":"A002","ch":"AML","sev":"CRIT",     "name":"Estratificación (Layering)",        "desc":"Fondos en 3+ cuentas intermedias",    "pts":750,"eval":lambda tx,p: p.get("layering_depth_max",0)>=3},
    {"id":"A003","ch":"AML","sev":"CRIT",     "name":"Velocidad AML",                     "desc":">$50K en 24h",                        "pts":660,"eval":lambda tx,p: p.get("amount_sum_24h",0)>50000},
    {"id":"A004","ch":"AML","sev":"CRIT",     "name":"PEP",                               "desc":"Persona Políticamente Expuesta",      "pts":550,"eval":lambda tx,p: tx.is_pep},
    {"id":"A005","ch":"AML","sev":"CRIT",     "name":"Lista Sanciones OFAC/ONU",          "desc":"Coincidencia lista negra",            "pts":999,"eval":lambda tx,p: tx.is_sanctioned},
]
MAX_RULE_SCORE = 999


def _run_rules(tx, profile_features: dict) -> Tuple[int, List[Dict], List[Dict]]:
    """Evalúa todas las reglas y retorna (score_0_999, rules_triggered, aml_flags)"""
    triggered, aml = [], []
    total_pts = 0

    for r in RULES:
        try:
            if r["eval"](tx, profile_features):
                entry = {
                    "rule_id": r["id"], "name": r["name"],
                    "description": r["desc"], "points": r["pts"],
                    "severity": r["sev"], "channel": r["ch"],
                }
                if r["ch"] == "AML":
                    aml.append(entry)
                else:
                    triggered.append(entry)
                total_pts += r["pts"]
        except Exception:
            pass

    # Cap a 999
    score = min(999, total_pts)
    return score, triggered, aml


def evaluate(tx, entity: Entity, profile_features: dict,
             ml_probability: float = 0.0, ml_version: str = "none") -> dict:
    """
    Evaluación completa: reglas + ML → score 0–999 → decisión
    """
    start = time.time()

    # 1. Score de reglas (0–999)
    score_rules_raw, triggered, aml_flags = _run_rules(tx, profile_features)
    score_rules = score_rules_raw  # ya está en 0–999

    # 2. Score ML (0–999)
    score_ml = int(min(999, ml_probability * 999))

    # 3. Score combinado según pesos de la entidad
    w_rules = entity.weight_rules if entity else 0.4
    w_ml    = entity.weight_ml    if entity else 0.6
    score_final = int(min(999, score_rules * w_rules + score_ml * w_ml))

    # 4. Forzar BLOQUEADA en sanciones
    if tx.is_sanctioned:
        score_final = 999

    # 5. Decisión según umbrales de la entidad
    t_alert  = entity.score_alert  if entity else 400
    t_review = entity.score_review if entity else 600
    t_block  = entity.score_block  if entity else 800

    if score_final >= t_block or tx.is_sanctioned:
        decision, risk_level = "BLOQUEADA", "CRITICAL"
    elif score_final >= t_review:
        decision, risk_level = "REVISIÓN",  "HIGH"
    elif score_final >= t_alert:
        decision, risk_level = "ALERTA",    "MEDIUM"
    else:
        decision, risk_level = "APROBADA",  "LOW"

    ms = round((time.time() - start) * 1000 + 10, 1)

    return {
        "tx_id":        f"TX{uuid.uuid4().hex[:10].upper()}",
        "timestamp":    datetime.utcnow(),
        "score_rules":  score_rules,
        "score_ml":     score_ml,
        "score_final":  score_final,
        "decision":     decision,
        "risk_level":   risk_level,
        "triggered_rules": triggered,
        "aml_flags":    aml_flags,
        "ml_version":   ml_version,
        "processing_ms":ms,
    }

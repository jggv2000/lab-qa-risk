import os
import re
from typing import Any, Dict, List

# Patrones de ejemplo para detectar posibles datos personales (PII) en textos libres
DNI_NIE_PATTERN = re.compile(r"\b[XYZ]?\d{7,8}[A-Z]\b", re.IGNORECASE)
PHONE_PATTERN = re.compile(r"\b(?:\+34[\s-]?)?[6789]\d{2}[\s-]?\d{3}[\s-]?\d{3}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def detect_pii_findings(text: str) -> List[str]:
    # Busca coincidencias de posibles identificadores o datos de contacto en el texto
    findings: List[str] = []
    if not text:
        return findings
    if DNI_NIE_PATTERN.search(text):
        findings.append("dni_nie_like")
    if PHONE_PATTERN.search(text):
        findings.append("phone_like")
    if EMAIL_PATTERN.search(text):
        findings.append("email_like")
    return findings


def local_rule_engine(
    amount: float,
    discount_pct: float,
    marketing_consent: int,
    notes: str,
) -> Dict[str, Any]:
    # Motor determinista local: siempre funciona sin depender de red ni claves externas
    pii_findings = detect_pii_findings(notes)
    gdpr_alert = bool(pii_findings) or (marketing_consent == 0 and len(notes.strip()) > 120)

    reasons: List[str] = []
    if amount >= 5000:
        reasons.append("Importe elevado (>= 5000)")
    if discount_pct > 30:
        reasons.append("Descuento superior al 30%")
    if pii_findings:
        reasons.append(f"Posibles datos personales en notas: {', '.join(pii_findings)}")
    if marketing_consent == 0 and pii_findings:
        reasons.append("Datos personales registrados sin consentimiento explícito")

    # Clasificación sencilla de riesgo según reglas de negocio y privacidad
    if amount >= 10000 or (pii_findings and marketing_consent == 0):
        risk_level = "CRITICAL"
    elif amount >= 5000 or discount_pct > 30 or pii_findings:
        risk_level = "HIGH"
    elif discount_pct > 15 or gdpr_alert:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if not reasons:
        reasons.append("Operación dentro de parámetros normales sin alertas de riesgo")

    return {
        "engine": "local_rule_engine",
        "risk_level": risk_level,
        "gdpr_alert": gdpr_alert,
        "pii_findings": pii_findings,
        "reasons": reasons,
    }


def evaluate_order_risk(
    amount: float,
    discount_pct: float,
    marketing_consent: int,
    notes: str,
) -> Dict[str, Any]:
    # Si no hay GEMINI_API_KEY configurada, usa directamente el motor local determinista
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    base = local_rule_engine(amount, discount_pct, marketing_consent, notes)

    if not api_key:
        return base

    # Si existe clave, intenta enriquecer el análisis con Gemini; ante cualquier fallo, cae al motor local
    try:
        from google import genai  # Importación opcional si se usa Gemini en el entorno

        client = genai.Client(api_key=api_key)
        prompt = (
            "Evalúa brevemente el riesgo operativo y GDPR de este pedido en JSON con claves "
            "risk_level (LOW|MEDIUM|HIGH|CRITICAL), gdpr_alert (bool) y summary (str): "
            f"amount={amount}, discount_pct={discount_pct}, marketing_consent={marketing_consent}, notes={notes!r}"
        )
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        text_out = (response.text or "").strip()
        return {
            **base,
            "engine": "gemini-2.5-flash+guardrail",
            "ai_raw_note": text_out[:300],
        }
    except Exception as exc:
        return {
            **base,
            "engine": "local_rule_engine_fallback",
            "fallback_reason": type(exc).__name__,
        }

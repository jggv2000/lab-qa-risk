from __future__ import annotations

import re
from typing import Any

# Detección estructural de datos personales (PII) sin depender de palabras clave
DNI_NIE_STRUCT_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:[XYZ]\d{7}|\d{8})[A-HJ-NP-TV-Z](?![A-Za-z0-9])",
    re.IGNORECASE,
)
EMAIL_STRUCT_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9._%+-])"
)
PHONE_STRUCT_RE = re.compile(
    r"(?<!\w)(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d[\d\s.-]{6,13}\d(?!\w)"
)


def detect_pii_findings(text: str | None) -> list[str]:
    """Detecta patrones estructurales de PII (DNI/NIE, teléfono, email) en un texto."""
    if not text:
        return []

    findings: set[str] = set()

    if DNI_NIE_STRUCT_RE.search(text):
        findings.add("dni_nie_like")

    if EMAIL_STRUCT_RE.search(text):
        findings.add("email_like")

    for match in PHONE_STRUCT_RE.finditer(text):
        candidate = match.group(0).strip()
        digits_only = re.sub(r"\D", "", candidate)
        if 9 <= len(digits_only) <= 15 and not DNI_NIE_STRUCT_RE.fullmatch(candidate):
            findings.add("phone_like")
            break

    return sorted(findings)


def evaluate_order_risk(
    amount: float,
    discount_pct: float = 0.0,
    marketing_consent: int | bool = 0,
    notes: str | None = None,
    customer_email: str | None = None,
) -> dict[str, Any]:
    """Evalúa el nivel de riesgo y alerta RGPD/PII de un pedido."""
    pii_sources = " ".join(part for part in (notes, customer_email) if part)
    pii_findings = detect_pii_findings(pii_sources)
    has_consent = bool(marketing_consent)
    has_pii = len(pii_findings) > 0

    gdpr_alert = has_pii and not has_consent

    risk_score = 0
    reasons: list[str] = []

    if amount >= 1000.0:
        risk_score += 2
        reasons.append("high_amount")
    elif amount >= 500.0:
        risk_score += 1
        reasons.append("medium_amount")

    if discount_pct >= 25.0:
        risk_score += 2
        reasons.append("high_discount")
    elif discount_pct >= 15.0:
        risk_score += 1
        reasons.append("moderate_discount")

    if gdpr_alert:
        risk_score += 3
        reasons.append("pii_without_marketing_consent")
    elif has_pii:
        risk_score += 1
        reasons.append("pii_detected_with_consent")

    if risk_score >= 4:
        risk_level = "CRITICAL"
    elif risk_score >= 2:
        risk_level = "HIGH"
    elif risk_score == 1:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "gdpr_alert": gdpr_alert,
        "pii_findings": pii_findings,
        "reasons": reasons,
    }

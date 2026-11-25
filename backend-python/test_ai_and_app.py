import json
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from ai_risk_advisor import detect_pii_findings, evaluate_order_risk
from app_service import app

client = TestClient(app)

RESULTS_FILE = Path(__file__).resolve().parent / "qa_test_results.json"

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


def detect_pii_structural(text: str) -> dict[str, list[str]]:
    """Detecta PII por estructura aunque no aparezcan las palabras DNI, teléfono o email."""
    base = detect_pii_findings(text) or {}

    dni_nie = set(base.get("dni_nie_like") or [])
    dni_nie.update(m.group(0).upper() for m in DNI_NIE_STRUCT_RE.finditer(text))

    emails = set(base.get("email_like") or [])
    emails.update(m.group(0) for m in EMAIL_STRUCT_RE.finditer(text))

    phones = set(base.get("phone_like") or [])
    for m in PHONE_STRUCT_RE.finditer(text):
        candidate = m.group(0).strip()
        digits_only = re.sub(r"\D", "", candidate)
        # Evita confundir un DNI/NIE de 8 dígitos suelto o códigos cortos con teléfonos
        if 9 <= len(digits_only) <= 15 and not DNI_NIE_STRUCT_RE.fullmatch(candidate):
            phones.add(candidate)

    result: dict[str, list[str]] = dict(base)
    if dni_nie:
        result["dni_nie_like"] = sorted(dni_nie)
    if phones:
        result["phone_like"] = sorted(phones)
    if emails:
        result["email_like"] = sorted(emails)
    return result


def _append_result(entry: dict) -> None:
    history: list[dict] = []
    if RESULTS_FILE.exists():
        try:
            history = json.loads(RESULTS_FILE.read_text(encoding="utf-8"))
            if not isinstance(history, list):
                history = []
        except json.JSONDecodeError:
            history = []

    entry["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
    history.append(entry)
    RESULTS_FILE.write_text(
        json.dumps(history, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def pytest_runtest_makereport(item, call):
    """Guarda automáticamente el resultado de cada test al terminar su ejecución."""
    if call.when == "call":
        status = "PASSED" if call.excinfo is None else "FAILED"
        error_msg = str(call.excinfo.value) if call.excinfo is not None else None
        _append_result(
            {
                "test_name": item.name,
                "status": status,
                "duration_sec": round(call.duration, 4),
                "error": error_msg,
            }
        )


def test_detect_pii_and_gdpr_alert():
    # Verifica detección por estructura sin necesidad de las palabras DNI, tel/telephone o correo/email
    sample_text = "Juan Pérez, 12345678A, +34 612 345 678, ana@ejemplo.com"
    findings = detect_pii_structural(sample_text)
    assert "dni_nie_like" in findings
    assert "phone_like" in findings
    assert "email_like" in findings

    res = evaluate_order_risk(
        amount=1200.0,
        discount_pct=10.0,
        marketing_consent=0,
        notes="Llamar al 612345678",
    )
    assert res["gdpr_alert"] is True
    assert res["risk_level"] in ("HIGH", "CRITICAL")

    _append_result(
        {
            "test_name": "test_detect_pii_and_gdpr_alert",
            "detail": "pii_and_risk_evaluation",
            "sample_text": sample_text,
            "findings": findings,
            "risk_result": res,
        }
    )


def test_low_risk_order_calculation():
    # Verifica cálculo de importe final con descuento y evaluación de bajo riesgo
    res = client.post(
        "/orders",
        headers={"X-User-Email": "cliente1@ejemplo.com"},
        json={
            "customer_email": "cliente1@ejemplo.com",
            "amount": 200.0,
            "discount_pct": 10.0,
            "marketing_consent": 1,
            "notes": "Pedido estándar sin datos personales",
        },
    )
    assert res.status_code == 201
    body = res.json()
    assert body["order"]["final_amount"] == 180.0
    assert body["risk_assessment"]["risk_level"] == "LOW"
    assert body["risk_assessment"]["gdpr_alert"] is False


def test_rbac_viewer_cannot_create_and_customer_isolated():
    # El rol viewer es solo lectura (403 al intentar crear)
    forbidden = client.post(
        "/orders",
        headers={"X-User-Email": "viewer@ejemplo.com"},
        json={
            "customer_email": "cliente1@ejemplo.com",
            "amount": 100.0,
            "discount_pct": 0.0,
            "marketing_consent": 0,
            "notes": "Intento de escritura con viewer",
        },
    )
    assert forbidden.status_code == 403

    # Un cliente no puede crear pedidos a nombre de otro cliente
    cross_customer = client.post(
        "/orders",
        headers={"X-User-Email": "cliente1@ejemplo.com"},
        json={
            "customer_email": "cliente2@ejemplo.com",
            "amount": 100.0,
            "discount_pct": 0.0,
            "marketing_consent": 0,
            "notes": "Intento de suplantación de cliente2",
        },
    )
    assert cross_customer.status_code == 403


def test_invalid_amount_rejected_by_validation():
    # Valores fuera de dominio (importe <= 0) deben ser rechazados con 422
    bad = client.post(
        "/orders",
        headers={"X-User-Email": "cliente1@ejemplo.com"},
        json={
            "customer_email": "cliente1@ejemplo.com",
            "amount": -50.0,
            "discount_pct": 0.0,
            "marketing_consent": 0,
            "notes": "Importe negativo",
        },
    )
    assert bad.status_code == 422

from fastapi.testclient import TestClient

from ai_risk_advisor import detect_pii_findings, evaluate_order_risk
from app_service import app

client = TestClient(app)


def test_detect_pii_and_gdpr_alert():
    # Verifica detección de posibles datos personales (PII) y activación de alerta GDPR
    findings = detect_pii_findings("Cliente DNI 12345678A, tel 612345678, correo ana@ejemplo.com")
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

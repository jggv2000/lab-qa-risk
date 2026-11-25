import pytest
import sqlite3
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from ai_risk_advisor import detect_pii_findings, evaluate_order_risk
from app_service import app

client = TestClient(app)


def _clean_token() -> str:
    res = client.post(
        "/mode/clean-login",
        json={"username": "instructor@lab.local", "password": "CleanMode2026!"},
    )
    assert res.status_code == 200
    return res.json()["clean_token"]


def _session_token(email: str, password: str) -> str:
    res = client.post(
        "/login",
        json={"email": email, "password": password},
    )
    assert res.status_code == 200
    return res.json()["session_token"]

# Guarda en la raíz del repositorio para no mezclar artefactos dentro de tests/
RESULTS_FILE = Path(__file__).resolve().parents[1] / "qa_test_results.json"
LAB_VERSION = os.getenv("LAB_VERSION", "v1.0-all_errors")


def _save_run_record(record: dict) -> None:
    history: list[dict] = []
    if RESULTS_FILE.exists():
        try:
            loaded = json.loads(RESULTS_FILE.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                history = loaded
        except json.JSONDecodeError:
            history = []

    record.setdefault("lab_version", LAB_VERSION)
    record["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
    history.append(record)
    RESULTS_FILE.write_text(
        json.dumps(history, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def pytest_runtest_makereport(item, call):
    if call.when == "call":
        _save_run_record(
            {
                "test_name": item.name,
                "status": "PASSED" if call.excinfo is None else "FAILED",
                "duration_sec": round(call.duration, 4),
                "error": str(call.excinfo.value) if call.excinfo is not None else None,
            }
        )


def test_detect_pii_and_gdpr_alert():
    # Texto sin las palabras "DNI", "teléfono" ni "email": valida detección por estructura
    raw_text = "Contacto directo: 12345678A, +34 612 345 678, ana@ejemplo.com"
    findings = detect_pii_findings(raw_text)
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

    _save_run_record(
        {
            "test_name": "test_detect_pii_and_gdpr_alert",
            "event": "pii_and_risk_snapshot",
            "raw_text": raw_text,
            "findings": findings,
            "risk_level": res["risk_level"],
            "gdpr_alert": res["gdpr_alert"],
        }
    )

def test_low_risk_order_calculation():
    res = client.post(
        "/orders",
        headers={
            "X-User-Email": "cliente1@ejemplo.com",
            "X-Session-Token": _session_token("cliente1@ejemplo.com", "Cliente123!"),
            "X-Lab-Mode": "clean",
            "X-Clean-Token": _clean_token(),
            "X-Test-Cycle": "all_clean",
        },
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

    risk = evaluate_order_risk(
        amount=200.0,
        discount_pct=10.0,
        marketing_consent=1,
        notes="Pedido estándar sin datos personales",
        customer_email="cliente1@ejemplo.com",
    )
    assert risk["risk_level"] in ("LOW", "MEDIUM")
    assert risk["gdpr_alert"] is False


def test_rbac_viewer_cannot_create_and_customer_isolated():
    clean_headers = {
        "X-User-Email": "viewer@ejemplo.com",
        "X-Session-Token": _session_token("viewer@ejemplo.com", "Viewer123!"),
        "X-Test-Cycle": "all_clean",
        "X-Lab-Mode": "clean",
        "X-Clean-Token": _clean_token(),
    }
    forbidden = client.post(
        "/orders",
        headers=clean_headers,
        json={
            "customer_email": "cliente1@ejemplo.com",
            "amount": 100.0,
            "discount_pct": 0.0,
            "marketing_consent": 0,
            "notes": "Intento de escritura con viewer",
        },
    )
    assert forbidden.status_code == 403

    cross_customer = client.post(
        "/orders",
        headers={
            "X-User-Email": "cliente1@ejemplo.com",
            "X-Session-Token": _session_token("cliente1@ejemplo.com", "Cliente123!"),
            "X-Test-Cycle": "all_clean",
            "X-Lab-Mode": "clean",
            "X-Clean-Token": _clean_token(),
        },
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
    # En ciclo half_errors, la validación de rango rechaza importes <= 0 con 422
    bad = client.post(
        "/orders",
        headers={
            "X-User-Email": "cliente1@ejemplo.com",
            "X-Test-Cycle": "half_errors",
        },
        json={
            "customer_email": "cliente1@ejemplo.com",
            "amount": -50.0,
            "discount_pct": 0.0,
            "marketing_consent": 0,
            "notes": "Importe negativo",
        },
    )
    assert bad.status_code == 422

    # En ciclo all_errors sin control previo, la restricción CHECK de SQLite dispara IntegrityError
    with pytest.raises(sqlite3.IntegrityError):
        client.post(
            "/orders",
            headers={
                "X-User-Email": "cliente1@ejemplo.com",
                "X-Test-Cycle": "all_errors",
            },
            json={
                "customer_email": "cliente1@ejemplo.com",
                "amount": -50.0,
                "discount_pct": 0.0,
                "marketing_consent": 0,
                "notes": "Importe negativo sin control previo",
            },
        )

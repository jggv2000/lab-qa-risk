import re
from typing import Any, Optional
from fastapi import Header, HTTPException
from pydantic import BaseModel, Field


class OrderFlexibleInput(BaseModel):
    """Recibe los campos del formulario/API sin bloquear en Pydantic para que
    los controles dependan del ciclo activo (sin controles vs. con controles)."""
    customer_email: str = Field(default="")
    amount: float = Field(default=0.0)
    discount_pct: float = Field(default=0.0)
    marketing_consent: int = Field(default=0)
    notes: str = Field(default="")


def validate_and_sanitize_order_fields(
    payload: OrderFlexibleInput,
    lab_mode: str,
    cycle: str,
) -> tuple[str, float, float, int, str]:
    """Aplica validación según el ciclo:
    - all_errors: SIN controles (acepta datos malos en los campos).
    - half_errors: controles parciales (bloquea importes/descuentos imposibles, pero permite correo inválido o HTML en notas).
    - all_clean (o modo clean): CON controles estrictos y sanitización.
    """
    raw_email = (payload.customer_email or "").strip()
    raw_notes = payload.notes or ""

    # 1. SIN CONTROLES (Ciclo 1: all_errors en modo buggy)
    if cycle == "all_errors" and lab_mode != "clean":
        return raw_email, payload.amount, payload.discount_pct, payload.marketing_consent, raw_notes

    # 2. CONTROLES PARCIALES (Ciclo 2: half_errors -> valida números, deja pasar 1 fallo de formato/sanitización)
    if cycle == "half_errors" and lab_mode != "clean":
        if payload.amount <= 0 or payload.amount > 100000:
            raise HTTPException(status_code=422, detail="Control parcial: amount debe estar entre 0.01 y 100000.")
        if payload.discount_pct < 0 or payload.discount_pct > 100:
            raise HTTPException(status_code=422, detail="Control parcial: discount_pct debe estar entre 0 y 100.")
        if payload.marketing_consent not in (0, 1):
            raise HTTPException(status_code=422, detail="Control parcial: marketing_consent debe ser 0 o 1.")
        # Fallo intencional en half_errors: no valida formato de email ni bloquea '<script>' en notes
        return raw_email.lower(), payload.amount, payload.discount_pct, payload.marketing_consent, raw_notes

    # 3. CON CONTROLES ESTRICTOS (Ciclo 3: all_clean o modo clean)
    if not re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", raw_email):
        raise HTTPException(status_code=422, detail="Control estricto: customer_email no tiene formato válido.")
    if payload.amount <= 0 or payload.amount > 100000:
        raise HTTPException(status_code=422, detail="Control estricto: amount debe ser > 0 y <= 100000.")
    if payload.discount_pct < 0 or payload.discount_pct > 100:
        raise HTTPException(status_code=422, detail="Control estricto: discount_pct debe estar entre 0 y 100.")
    if payload.marketing_consent not in (0, 1):
        raise HTTPException(status_code=422, detail="Control estricto: marketing_consent solo admite 0 o 1.")
    if len(raw_notes) > 500:
        raise HTTPException(status_code=422, detail="Control estricto: notes supera el máximo de 500 caracteres.")
    if "<" in raw_notes or ">" in raw_notes:
        raise HTTPException(status_code=422, detail="Control estricto: caracteres '<' o '>' no permitidos en notes (prevención XSS).")

    clean_notes = raw_notes.strip()
    return raw_email.lower(), payload.amount, payload.discount_pct, payload.marketing_consent, clean_notes


def seed_initial_orders() -> None:
    """Siembra datos BUENOS y MALOS en la base de datos para inspección y pruebas."""
    existing_count = conn.execute("SELECT COUNT(*) AS cnt FROM orders").fetchone()["cnt"]
    if existing_count == 0:
        conn.executemany(
            """
            INSERT INTO orders (
                owner_email, customer_email, amount, discount_pct,
                final_amount, status, marketing_consent, notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                # --- DATOS BUENOS (válidos y conformes) ---
                (
                    "cliente1@ejemplo.com",
                    "cliente1@ejemplo.com",
                    200.0,
                    10.0,
                    180.0,
                    "approved",
                    1,
                    "[BUENO] Pedido estándar válido con consentimiento",
                ),
                (
                    "cliente2@ejemplo.com",
                    "cliente2@ejemplo.com",
                    350.0,
                    15.0,
                    297.5,
                    "pending",
                    1,
                    "[BUENO] Pedido en umbral de descuento 15%",
                ),
                # --- DATOS MALOS / ANÓMALOS (para detectar en auditoría y pruebas) ---
                (
                    "cliente1@ejemplo.com",
                    "correo-invalido-sin-arroba",
                    -120.0,
                    140.0,
                    48.0,
                    "pending",
                    9,
                    "[MALO] Importe negativo, descuento >100%, email roto y consent=9",
                ),
                (
                    "cliente2@ejemplo.com",
                    "cliente2@ejemplo.com",
                    500.0,
                    30.0,
                    425.0,
                    "pending",
                    0,
                    "[MALO-RGPD] Llamar al 600123456 DNI 12345678A <script>alert(1)</script>",
                ),
            ],
        )
        conn.commit()

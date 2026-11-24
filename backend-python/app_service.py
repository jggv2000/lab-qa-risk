import os
from pathlib import Path
from typing import Literal, Optional
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field

from ai_risk_advisor import evaluate_order_risk
from database import init_db

# Permite aislar el archivo SQLite en pruebas mediante la variable de entorno LAB_DB_PATH
DB_PATH = os.getenv("LAB_DB_PATH", "lab_orders.db")
conn = init_db(DB_PATH)

app = FastAPI(
    title="Pearson QA Risk Lab API",
    description="API de laboratorio para pruebas de caja negra, caja blanca, RBAC, GDPR e IA.",
    version="1.0.0",
)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class OrderCreateRequest(BaseModel):
    customer_email: EmailStr
    amount: float = Field(gt=0, description="Importe bruto positivo")
    discount_pct: float = Field(default=0, ge=0, le=100, description="Descuento entre 0 y 100")
    marketing_consent: int = Field(default=0, ge=0, le=1)
    notes: str = Field(default="", max_length=1000)


class OrderStatusUpdate(BaseModel):
    status: Literal["pending", "approved", "cancelled"]


def get_current_user(x_user_email: Optional[str]) -> dict:
    # Autenticación simplificada de laboratorio mediante cabecera X-User-Email
    if not x_user_email:
        raise HTTPException(status_code=401, detail="Falta cabecera X-User-Email")
    row = conn.execute(
        "SELECT id, email, role FROM users WHERE email = ?",
        (x_user_email.strip().lower(),),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Usuario no registrado en el laboratorio")
    return dict(row)


@app.get("/health")
def health_check() -> dict:
    return {"status": "ok", "service": "pearson-qa-risk-lab"}


@app.get("/app", response_class=HTMLResponse)
def user_portal() -> HTMLResponse:
    html_path = Path(__file__).resolve().parent / "static" / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.post("/login")
def login(payload: LoginRequest) -> dict:
    email_norm = payload.email.strip().lower()
    row = conn.execute(
        "SELECT id, email, password, role FROM users WHERE email = ?",
        (email_norm,),
    ).fetchone()
    if not row or row["password"] != payload.password:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    return {
        "authenticated": True,
        "email": row["email"],
        "role": row["role"],
        "header_to_use": {"X-User-Email": row["email"]},
    }


@app.post("/orders/ai-risk-check")
def ai_risk_check(
    payload: OrderCreateRequest,
    x_user_email: Optional[str] = Header(default=None),
) -> dict:
    user = get_current_user(x_user_email)
    if user["role"] == "viewer":
        raise HTTPException(status_code=403, detail="El rol viewer no puede evaluar o crear pedidos")
    return evaluate_order_risk(
        amount=payload.amount,
        discount_pct=payload.discount_pct,
        marketing_consent=payload.marketing_consent,
        notes=payload.notes,
    )


@app.post("/orders", status_code=201)
def create_order(
    payload: OrderCreateRequest,
    x_user_email: Optional[str] = Header(default=None),
) -> dict:
    user = get_current_user(x_user_email)
    # Regla RBAC: viewer es estrictamente de solo lectura
    if user["role"] == "viewer":
        raise HTTPException(status_code=403, detail="El rol viewer tiene acceso de solo lectura")

    # Regla de negocio: un cliente solo puede crear pedidos asociados a su propio correo
    if user["role"] == "customer" and payload.customer_email.lower() != user["email"].lower():
        raise HTTPException(
            status_code=403,
            detail="Un cliente no puede crear pedidos a nombre de otro cliente",
        )

    final_amount = round(payload.amount * (1 - payload.discount_pct / 100.0), 2)
    risk_report = evaluate_order_risk(
        amount=payload.amount,
        discount_pct=payload.discount_pct,
        marketing_consent=payload.marketing_consent,
        notes=payload.notes,
    )

    cursor = conn.execute(
        """
        INSERT INTO orders (
            owner_email, customer_email, amount, discount_pct,
            final_amount, status, marketing_consent, notes
        )
        VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
        """,
        (
            user["email"],
            payload.customer_email.lower(),
            payload.amount,
            payload.discount_pct,
            final_amount,
            payload.marketing_consent,
            payload.notes,
        ),
    )
    conn.commit()
    order_id = cursor.lastrowid

    row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    return {
        "order": dict(row),
        "risk_assessment": risk_report,
    }


@app.get("/orders")
def list_orders(x_user_email: Optional[str] = Header(default=None)) -> dict:
    user = get_current_user(x_user_email)
    # admin y viewer pueden consultar todos los pedidos; customer solo ve los suyos
    if user["role"] in ("admin", "viewer"):
        rows = conn.execute("SELECT * FROM orders ORDER BY id ASC").fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM orders WHERE owner_email = ? OR customer_email = ? ORDER BY id ASC",
            (user["email"], user["email"]),
        ).fetchall()
    return {
        "role": user["role"],
        "count": len(rows),
        "orders": [dict(r) for r in rows],
    }


@app.patch("/orders/{order_id}/status")
def update_order_status(
    order_id: int,
    payload: OrderStatusUpdate,
    x_user_email: Optional[str] = Header(default=None),
) -> dict:
    user = get_current_user(x_user_email)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Solo admin puede cambiar el estado de un pedido")

    existing = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Pedido no encontrado")

    conn.execute(
        "UPDATE orders SET status = ? WHERE id = ?",
        (payload.status, order_id),
    )
    conn.commit()
    updated = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    return {"order": dict(updated)}


@app.delete("/orders/{order_id}")
def delete_order(
    order_id: int,
    x_user_email: Optional[str] = Header(default=None),
) -> dict:
    user = get_current_user(x_user_email)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Solo admin puede eliminar pedidos")

    existing = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Pedido no encontrado")

    conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    return {"deleted": True, "order_id": order_id}

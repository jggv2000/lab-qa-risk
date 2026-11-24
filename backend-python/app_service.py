import os
from pathlib import Path
from typing import Literal, Optional
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field

from ai_risk_advisor import evaluate_order_risk
from database import init_db

# Permite aislar el archivo SQLite en pruebas mediante la variable de entorno LAB_DB_PATH
DB_PATH = os.getenv("LAB_DB_PATH", "lab_orders.db")
conn = init_db(DB_PATH)

# Tabla de trazabilidad / auditoría en SQLite
conn.execute(
    """
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT DEFAULT (datetime('now')),
        actor_email TEXT NOT NULL,
        role TEXT NOT NULL,
        action TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        detail TEXT NOT NULL
    )
    """
)
conn.commit()

app = FastAPI(
    title="Pearson QA Risk Lab API",
    description="API de laboratorio para pruebas de caja negra, caja blanca, RBAC, GDPR e IA.",
    version="1.1.0",
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


def log_audit(
    actor_email: str,
    role: str,
    action: str,
    status_code: int,
    detail: str,
) -> None:
    conn.execute(
        """
        INSERT INTO audit_logs (actor_email, role, action, status_code, detail)
        VALUES (?, ?, ?, ?, ?)
        """,
        (actor_email.strip().lower(), role, action, status_code, detail[:500]),
    )
    conn.commit()


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
        role_guess = row["role"] if row else "unknown"
        log_audit(email_norm, role_guess, "login", 401, "Intento de inicio de sesión fallido")
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    log_audit(row["email"], row["role"], "login", 200, "Inicio de sesión exitoso")
    return {
        "authenticated": True,
        "email": row["email"],
        "role": row["role"],
        "header_to_use": {"X-User-Email": row["email"]},
    }


@app.post("/logout")
def logout(x_user_email: Optional[str] = Header(default=None)) -> dict:
    user = get_current_user(x_user_email)
    log_audit(user["email"], user["role"], "logout", 200, "Cierre de sesión")
    return {"authenticated": False, "logged_out": True, "email": user["email"]}


@app.post("/orders/ai-risk-check")
def ai_risk_check(
    payload: OrderCreateRequest,
    x_user_email: Optional[str] = Header(default=None),
) -> dict:
    user = get_current_user(x_user_email)
    if user["role"] == "viewer":
        log_audit(
            user["email"],
            user["role"],
            "ai_risk_check",
            403,
            "Denegado: rol viewer no puede evaluar riesgo",
        )
        raise HTTPException(status_code=403, detail="El rol viewer no puede evaluar o crear pedidos")

    report = evaluate_order_risk(
        amount=payload.amount,
        discount_pct=payload.discount_pct,
        marketing_consent=payload.marketing_consent,
        notes=payload.notes,
    )
    log_audit(
        user["email"],
        user["role"],
        "ai_risk_check",
        200,
        f"Evaluación de riesgo para {payload.customer_email} (importe={payload.amount}, desc={payload.discount_pct}%)",
    )
    return report


@app.post("/orders", status_code=201)
def create_order(
    payload: OrderCreateRequest,
    x_user_email: Optional[str] = Header(default=None),
) -> dict:
    user = get_current_user(x_user_email)
    if user["role"] == "viewer":
        log_audit(user["email"], user["role"], "create_order", 403, "Denegado: rol viewer")
        raise HTTPException(status_code=403, detail="El rol viewer tiene acceso de solo lectura")

    if user["role"] == "customer" and payload.customer_email.lower() != user["email"].lower():
        log_audit(
            user["email"],
            user["role"],
            "create_order",
            403,
            f"Denegado: intentó crear pedido para {payload.customer_email}",
        )
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

    log_audit(
        user["email"],
        user["role"],
        "create_order",
        201,
        f"Pedido #{order_id} creado para {payload.customer_email} por {final_amount}",
    )

    row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    return {
        "order": dict(row),
        "risk_assessment": risk_report,
    }


@app.get("/orders")
def list_orders(x_user_email: Optional[str] = Header(default=None)) -> dict:
    user = get_current_user(x_user_email)
    if user["role"] in ("admin", "viewer"):
        rows = conn.execute("SELECT * FROM orders ORDER BY id ASC").fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM orders WHERE owner_email = ? OR customer_email = ? ORDER BY id ASC",
            (user["email"], user["email"]),
        ).fetchall()

    log_audit(
        user["email"],
        user["role"],
        "list_orders",
        200,
        f"Consultados {len(rows)} pedidos",
    )
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
        log_audit(
            user["email"],
            user["role"],
            "update_order_status",
            403,
            f"Denegado: intentó cambiar pedido #{order_id} a '{payload.status}'",
        )
        raise HTTPException(status_code=403, detail="Solo admin puede cambiar el estado de un pedido")

    existing = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not existing:
        log_audit(
            user["email"],
            user["role"],
            "update_order_status",
            404,
            f"Pedido #{order_id} no encontrado",
        )
        raise HTTPException(status_code=404, detail="Pedido no encontrado")

    conn.execute(
        "UPDATE orders SET status = ? WHERE id = ?",
        (payload.status, order_id),
    )
    conn.commit()
    log_audit(
        user["email"],
        user["role"],
        "update_order_status",
        200,
        f"Pedido #{order_id} actualizado a '{payload.status}'",
    )
    updated = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    return {"order": dict(updated)}


@app.delete("/orders/{order_id}")
def delete_order(
    order_id: int,
    x_user_email: Optional[str] = Header(default=None),
) -> dict:
    user = get_current_user(x_user_email)
    if user["role"] != "admin":
        log_audit(
            user["email"],
            user["role"],
            "delete_order",
            403,
            f"Denegado: intentó borrar pedido #{order_id}",
        )
        raise HTTPException(status_code=403, detail="Solo admin puede eliminar pedidos")

    existing = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not existing:
        log_audit(
            user["email"],
            user["role"],
            "delete_order",
            404,
            f"Pedido #{order_id} no encontrado al borrar",
        )
        raise HTTPException(status_code=404, detail="Pedido no encontrado")

    conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    log_audit(
        user["email"],
        user["role"],
        "delete_order",
        200,
        f"Pedido #{order_id} eliminado",
    )
    return {"deleted": True, "order_id": order_id}


@app.get("/audit-logs")
def get_audit_logs(
    x_user_email: Optional[str] = Header(default=None),
    user_filter: Optional[str] = Query(default=None, description="Solo aplica si eres admin"),
) -> dict:
    user = get_current_user(x_user_email)
    if user["role"] == "admin":
        if user_filter and user_filter.strip():
            rows = conn.execute(
                """
                SELECT id, created_at, actor_email, role, action, status_code, detail
                FROM audit_logs
                WHERE actor_email LIKE ?
                ORDER BY id DESC
                LIMIT 200
                """,
                (f"%{user_filter.strip().lower()}%",),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, created_at, actor_email, role, action, status_code, detail
                FROM audit_logs
                ORDER BY id DESC
                LIMIT 200
                """
            ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT id, created_at, actor_email, role, action, status_code, detail
            FROM audit_logs
            WHERE actor_email = ?
            ORDER BY id DESC
            LIMIT 200
            """,
            (user["email"],),
        ).fetchall()

    return {
        "viewer_email": user["email"],
        "viewer_role": user["role"],
        "scope": "all_users" if user["role"] == "admin" else "own_user_only",
        "count": len(rows),
        "logs": [dict(r) for r in rows],
    }

import hashlib
import os
import secrets
from pathlib import Path
from typing import Literal, Optional
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field

from ai_risk_advisor import evaluate_order_risk
from database import init_db

DB_PATH = os.getenv("LAB_DB_PATH", "lab_orders.db")
CLEAN_MODE_USER = os.getenv("CLEAN_MODE_USER", "instructor@lab.local").strip().lower()
CLEAN_MODE_PASS = os.getenv("CLEAN_MODE_PASS", "CleanMode2026!")

# Almacén en memoria de tokens válidos para el modo solucionado (clean)
ACTIVE_CLEAN_TOKENS: set[str] = set()

conn = init_db(DB_PATH)


def ensure_schema_and_seed() -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT DEFAULT (datetime('now')),
            lab_mode TEXT NOT NULL DEFAULT 'buggy',
            actor_email TEXT NOT NULL,
            role TEXT NOT NULL,
            action TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            detail TEXT NOT NULL
        )
        """
    )
    # Por si existía una tabla audit_logs previa sin columna lab_mode
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(audit_logs)").fetchall()]
    if "lab_mode" not in cols:
        conn.execute("ALTER TABLE audit_logs ADD COLUMN lab_mode TEXT NOT NULL DEFAULT 'buggy'")
    conn.commit()


def seed_initial_orders() -> None:
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
                (
                    "cliente1@ejemplo.com",
                    "cliente1@ejemplo.com",
                    200.0,
                    10.0,
                    180.0,
                    "pending",
                    1,
                    "Pedido estándar sin datos personales",
                ),
                (
                    "cliente2@ejemplo.com",
                    "cliente2@ejemplo.com",
                    320.0,
                    5.0,
                    304.0,
                    "pending",
                    0,
                    "Revisión de consentimiento RGPD",
                ),
            ],
        )
        conn.commit()


ensure_schema_and_seed()
seed_initial_orders()

app = FastAPI(
    title="Pearson QA Risk Lab API",
    description="API de laboratorio con modo prácticas (buggy), modo solucionado (clean), RBAC y trazabilidad.",
    version="1.2.0",
)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class CleanModeAuthRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class OrderCreateRequest(BaseModel):
    customer_email: EmailStr
    amount: float = Field(gt=0, description="Importe bruto positivo")
    discount_pct: float = Field(default=0, ge=0, le=100, description="Descuento entre 0 y 100")
    marketing_consent: int = Field(default=0, ge=0, le=1)
    notes: str = Field(default="", max_length=1000)


class OrderStatusUpdate(BaseModel):
    status: Literal["pending", "approved", "cancelled"]


def resolve_lab_mode(x_lab_mode: Optional[str], x_clean_token: Optional[str]) -> str:
    requested = (x_lab_mode or "buggy").strip().lower()
    if requested == "clean":
        if x_clean_token and x_clean_token in ACTIVE_CLEAN_TOKENS:
            return "clean"
        raise HTTPException(
            status_code=403,
            detail="Acceso al modo solucionado (clean) no autorizado. Inicia sesión de modo limpio.",
        )
    return "buggy"


def log_audit(
    actor_email: str,
    role: str,
    action: str,
    status_code: int,
    detail: str,
    lab_mode: str = "buggy",
) -> None:
    conn.execute(
        """
        INSERT INTO audit_logs (lab_mode, actor_email, role, action, status_code, detail)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (lab_mode, actor_email.strip().lower(), role, action, status_code, detail[:500]),
    )
    conn.commit()


def get_current_user(x_user_email: Optional[str]) -> dict:
    if not x_user_email:
        raise HTTPException(status_code=401, detail="Falta cabecera X-User-Email")
    row = conn.execute(
        "SELECT id, email, role FROM users WHERE email = ?",
        (x_user_email.strip().lower(),),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Usuario no registrado en el laboratorio")
    return dict(row)


def compute_final_amount(amount: float, discount_pct: float, mode: str) -> float:
    # En modo 'buggy' se aplica un redondeo/cálculo defectuoso intencional cuando el descuento supera el 15%
    if mode == "buggy" and discount_pct > 15:
        return round(amount * (1 - (discount_pct * 0.5) / 100.0), 2)
    return round(amount * (1 - discount_pct / 100.0), 2)


@app.get("/health")
def health_check() -> dict:
    return {"status": "ok", "service": "pearson-qa-risk-lab"}


@app.get("/app", response_class=HTMLResponse)
def user_portal() -> HTMLResponse:
    html_path = Path(__file__).resolve().parent / "static" / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.post("/mode/clean-login")
def clean_mode_login(
    payload: CleanModeAuthRequest,
    x_user_email: Optional[str] = Header(default=None),
) -> dict:
    user_norm = payload.username.strip().lower()
    valid_user = secrets.compare_digest(user_norm, CLEAN_MODE_USER)
    valid_pass = secrets.compare_digest(payload.password, CLEAN_MODE_PASS)
    actor = (x_user_email or user_norm or "anonymous").strip().lower()

    if not (valid_user and valid_pass):
        log_audit(actor, "unknown", "clean_mode_login", 401, "Credenciales inválidas para modo solucionado", "buggy")
        raise HTTPException(status_code=401, detail="Usuario o contraseña del modo solucionado inválidos")

    token = secrets.token_urlsafe(24)
    ACTIVE_CLEAN_TOKENS.add(token)
    log_audit(actor, "clean_auth", "clean_mode_login", 200, "Activado modo solucionado (clean)", "clean")
    return {
        "clean_unlocked": True,
        "mode": "clean",
        "clean_token": token,
    }


@app.post("/login")
def login(
    payload: LoginRequest,
    x_lab_mode: Optional[str] = Header(default=None),
    x_clean_token: Optional[str] = Header(default=None),
) -> dict:
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    email_norm = payload.email.strip().lower()
    row = conn.execute(
        "SELECT id, email, password, role FROM users WHERE email = ?",
        (email_norm,),
    ).fetchone()
    if not row or row["password"] != payload.password:
        role_guess = row["role"] if row else "unknown"
        log_audit(email_norm, role_guess, "login", 401, "Intento de inicio de sesión fallido", mode)
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    log_audit(row["email"], row["role"], "login", 200, "Inicio de sesión exitoso", mode)
    return {
        "authenticated": True,
        "email": row["email"],
        "role": row["role"],
        "lab_mode": mode,
        "header_to_use": {"X-User-Email": row["email"]},
    }


@app.post("/logout")
def logout(
    x_user_email: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default=None),
    x_clean_token: Optional[str] = Header(default=None),
) -> dict:
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    user = get_current_user(x_user_email)
    log_audit(user["email"], user["role"], "logout", 200, "Cierre de sesión", mode)
    return {"authenticated": False, "logged_out": True, "email": user["email"], "lab_mode": mode}


@app.post("/reset-lab")
def reset_lab(
    x_user_email: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default=None),
    x_clean_token: Optional[str] = Header(default=None),
) -> dict:
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    user = get_current_user(x_user_email)
    if user["role"] != "admin":
        log_audit(user["email"], user["role"], "reset_lab", 403, "Denegado: solo admin puede reiniciar el laboratorio", mode)
        raise HTTPException(status_code=403, detail="Solo admin puede reiniciar los datos del laboratorio")

    conn.execute("DELETE FROM orders")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='orders'")
    conn.execute("DELETE FROM audit_logs")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='audit_logs'")
    conn.commit()
    seed_initial_orders()
    log_audit(user["email"], user["role"], "reset_lab", 200, "Datos iniciales restaurados", mode)
    return {"reset": True, "lab_mode": mode}


@app.post("/orders/ai-risk-check")
def ai_risk_check(
    payload: OrderCreateRequest,
    x_user_email: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default=None),
    x_clean_token: Optional[str] = Header(default=None),
) -> dict:
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    user = get_current_user(x_user_email)
    if user["role"] == "viewer":
        log_audit(user["email"], user["role"], "ai_risk_check", 403, "Denegado: rol viewer no puede evaluar riesgo", mode)
        raise HTTPException(status_code=403, detail="El rol viewer no puede evaluar o crear pedidos")

    report = evaluate_order_risk(
        amount=payload.amount,
        discount_pct=payload.discount_pct,
        marketing_consent=payload.marketing_consent,
        notes=payload.notes,
    )
    # En modo 'buggy' se omite alerta cuando hay consentimiento 0 y descuento alto
    if mode == "buggy" and payload.marketing_consent == 0 and payload.discount_pct >= 20:
        report = {
            **report,
            "buggy_note": "Simulación de omisión de regla en modo prácticas",
        }

    log_audit(
        user["email"],
        user["role"],
        "ai_risk_check",
        200,
        f"Evaluación de riesgo para {payload.customer_email} (importe={payload.amount}, desc={payload.discount_pct}%)",
        mode,
    )
    return {"lab_mode": mode, "risk_assessment": report}


@app.post("/orders", status_code=201)
def create_order(
    payload: OrderCreateRequest,
    x_user_email: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default=None),
    x_clean_token: Optional[str] = Header(default=None),
) -> dict:
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    user = get_current_user(x_user_email)
    if user["role"] == "viewer":
        log_audit(user["email"], user["role"], "create_order", 403, "Denegado: rol viewer", mode)
        raise HTTPException(status_code=403, detail="El rol viewer tiene acceso de solo lectura")

    # En modo 'clean' se exige estrictamente que el cliente coincida; en 'buggy' hay un fallo intencional
    if user["role"] == "customer" and payload.customer_email.lower() != user["email"].lower():
        if mode == "clean":
            log_audit(
                user["email"],
                user["role"],
                "create_order",
                403,
                f"Denegado: intentó crear pedido para {payload.customer_email}",
                mode,
            )
            raise HTTPException(
                status_code=403,
                detail="Un cliente no puede crear pedidos a nombre de otro cliente",
            )

    final_amount = compute_final_amount(payload.amount, payload.discount_pct, mode)
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
        f"ID_PED-{order_id} creado para {payload.customer_email} por {final_amount}",
        mode,
    )

    row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    order_dict = dict(row)
    order_dict["id_ped"] = f"ID_PED-{order_dict['id']}"
    return {
        "lab_mode": mode,
        "order": order_dict,
        "risk_assessment": risk_report,
    }


@app.get("/orders")
def list_orders(
    x_user_email: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default=None),
    x_clean_token: Optional[str] = Header(default=None),
) -> dict:
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    user = get_current_user(x_user_email)
    if user["role"] in ("admin", "viewer"):
        rows = conn.execute("SELECT * FROM orders ORDER BY id ASC").fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM orders WHERE owner_email = ? OR customer_email = ? ORDER BY id ASC",
            (user["email"], user["email"]),
        ).fetchall()

    log_audit(user["email"], user["role"], "list_orders", 200, f"Consultados {len(rows)} pedidos", mode)
    orders_list = []
    for r in rows:
        item = dict(r)
        item["id_ped"] = f"ID_PED-{item['id']}"
        orders_list.append(item)

    return {
        "lab_mode": mode,
        "role": user["role"],
        "count": len(orders_list),
        "orders": orders_list,
    }


@app.patch("/orders/{order_id}/status")
def update_order_status(
    order_id: int,
    payload: OrderStatusUpdate,
    x_user_email: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default=None),
    x_clean_token: Optional[str] = Header(default=None),
) -> dict:
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    user = get_current_user(x_user_email)
    if user["role"] != "admin":
        log_audit(
            user["email"],
            user["role"],
            "update_order_status",
            403,
            f"Denegado: intentó cambiar ID_PED-{order_id} a '{payload.status}'",
            mode,
        )
        raise HTTPException(status_code=403, detail="Solo admin puede cambiar el estado de un pedido")

    existing = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not existing:
        log_audit(user["email"], user["role"], "update_order_status", 404, f"ID_PED-{order_id} no encontrado", mode)
        raise HTTPException(status_code=404, detail="Pedido no encontrado")

    conn.execute("UPDATE orders SET status = ? WHERE id = ?", (payload.status, order_id))
    conn.commit()
    log_audit(
        user["email"],
        user["role"],
        "update_order_status",
        200,
        f"ID_PED-{order_id} actualizado a '{payload.status}'",
        mode,
    )
    updated = dict(conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone())
    updated["id_ped"] = f"ID_PED-{updated['id']}"
    return {"lab_mode": mode, "order": updated}


@app.delete("/orders/{order_id}")
def delete_order(
    order_id: int,
    x_user_email: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default=None),
    x_clean_token: Optional[str] = Header(default=None),
) -> dict:
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    user = get_current_user(x_user_email)
    if user["role"] != "admin":
        log_audit(
            user["email"],
            user["role"],
            "delete_order",
            403,
            f"Denegado: intentó borrar ID_PED-{order_id}",
            mode,
        )
        raise HTTPException(status_code=403, detail="Solo admin puede eliminar pedidos")

    existing = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not existing:
        log_audit(user["email"], user["role"], "delete_order", 404, f"ID_PED-{order_id} no encontrado al borrar", mode)
        raise HTTPException(status_code=404, detail="Pedido no encontrado")

    conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    log_audit(user["email"], user["role"], "delete_order", 200, f"ID_PED-{order_id} eliminado", mode)
    return {"deleted": True, "order_id": order_id, "id_ped": f"ID_PED-{order_id}", "lab_mode": mode}


@app.get("/audit-logs")
def get_audit_logs(
    x_user_email: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default=None),
    x_clean_token: Optional[str] = Header(default=None),
    user_filter: Optional[str] = Query(default=None, description="Solo aplica si eres admin"),
    limit: int = Query(default=25, ge=1, le=100, description="25, 50 o 100 registros"),
) -> dict:
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    user = get_current_user(x_user_email)
    safe_limit = limit if limit in (25, 50, 100) else 25

    if user["role"] == "admin":
        if user_filter and user_filter.strip():
            rows = conn.execute(
                """
                SELECT id, created_at, lab_mode, actor_email, role, action, status_code, detail
                FROM audit_logs
                WHERE actor_email LIKE ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (f"%{user_filter.strip().lower()}%", safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, created_at, lab_mode, actor_email, role, action, status_code, detail
                FROM audit_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT id, created_at, lab_mode, actor_email, role, action, status_code, detail
            FROM audit_logs
            WHERE actor_email = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (user["email"], safe_limit),
        ).fetchall()

    logs_list = []
    for r in rows:
        item = dict(r)
        item["id_tra"] = f"ID_TRA-{item['id']}"
        logs_list.append(item)

    return {
        "lab_mode": mode,
        "viewer_email": user["email"],
        "viewer_role": user["role"],
        "scope": "all_users" if user["role"] == "admin" else "own_user_only",
        "limit": safe_limit,
        "count": len(logs_list),
        "logs": logs_list,
    }

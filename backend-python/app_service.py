import os
import re
import secrets
from pathlib import Path
from typing import Literal, Optional
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field

from database import init_db

DB_PATH = os.getenv("LAB_DB_PATH", "lab_orders.db")
CLEAN_MODE_USER = os.getenv("CLEAN_MODE_USER", "instructor@lab.local").strip().lower()
CLEAN_MODE_PASS = os.getenv("CLEAN_MODE_PASS", "CleanMode2026!")

TestCycle = Literal["all_errors", "half_errors", "all_clean"]

ACTIVE_SESSIONS: dict[str, dict] = {}
ACTIVE_CLEAN_TOKENS: set[str] = set()
CURRENT_CYCLE: TestCycle = "all_errors"

conn = init_db(DB_PATH)


def ensure_schema_and_seed() -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT DEFAULT (datetime('now')),
            lab_mode TEXT NOT NULL DEFAULT 'buggy',
            test_cycle TEXT NOT NULL DEFAULT 'all_errors',
            actor_email TEXT NOT NULL,
            role TEXT NOT NULL,
            action TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            detail TEXT NOT NULL
        )
        """
    )
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(audit_logs)").fetchall()]
    if "lab_mode" not in cols:
        conn.execute("ALTER TABLE audit_logs ADD COLUMN lab_mode TEXT NOT NULL DEFAULT 'buggy'")
    if "test_cycle" not in cols:
        conn.execute("ALTER TABLE audit_logs ADD COLUMN test_cycle TEXT NOT NULL DEFAULT 'all_errors'")
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
    title="Pearson QA Risk Lab API — 3 Ciclos de Pruebas",
    description="Soporta ciclos all_errors, half_errors (1 fallo de cada tipo) y all_clean.",
    version="3.0.0",
)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class CleanModeAuthRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class CycleChangeRequest(BaseModel):
    cycle: TestCycle


class OrderCreateRequest(BaseModel):
    customer_email: EmailStr
    amount: float = Field(gt=0)
    discount_pct: float = Field(default=0, ge=0, le=100)
    marketing_consent: int = Field(default=0, ge=0, le=1)
    notes: str = Field(default="", max_length=1000)


class OrderStatusUpdate(BaseModel):
    status: Literal["pending", "approved", "cancelled"]


def fmt_order_id(order_id: int) -> str:
    return f"ID_PED-{order_id}"


def fmt_trace_id(trace_id: int) -> str:
    return f"ID_TRA-{trace_id}"


def serialize_order(row) -> dict:
    data = dict(row)
    data["order_code"] = fmt_order_id(data["id"])
    return data


def serialize_audit(row) -> dict:
    data = dict(row)
    data["trace_code"] = fmt_trace_id(data["id"])
    return data


def resolve_cycle(x_test_cycle: Optional[str]) -> TestCycle:
    if x_test_cycle in ("all_errors", "half_errors", "all_clean"):
        return x_test_cycle
    return CURRENT_CYCLE


def log_audit(
    actor_email: str,
    role: str,
    action: str,
    status_code: int,
    detail: str,
    lab_mode: str = "buggy",
    cycle: Optional[TestCycle] = None,
) -> str:
    active_cycle = cycle or CURRENT_CYCLE
    # En all_errors se omite intencionalmente el registro de acciones de lectura/consulta
    if active_cycle == "all_errors" and action in ("LIST_ORDERS", "LIST_LOGS"):
        return "ID_TRA-OMITIDO(ALL_ERRORS)"

    recorded_mode = "buggy" if (active_cycle == "half_errors" and action == "CREATE_ORDER") else lab_mode

    cur = conn.execute(
        """
        INSERT INTO audit_logs (lab_mode, test_cycle, actor_email, role, action, status_code, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (recorded_mode, active_cycle, actor_email, role, action, status_code, detail),
    )
    conn.commit()
    return fmt_trace_id(cur.lastrowid)


def resolve_lab_mode(x_lab_mode: Optional[str], x_clean_token: Optional[str]) -> Literal["buggy", "clean"]:
    requested = (x_lab_mode or "buggy").strip().lower()
    if requested == "clean":
        if x_clean_token and x_clean_token in ACTIVE_CLEAN_TOKENS:
            return "clean"
        raise HTTPException(
            status_code=403,
            detail="El modo 'clean' requiere /mode/clean-login y cabecera X-Clean-Token válida.",
        )
    return "buggy"


def get_current_user(
    x_user_email: Optional[str],
    x_session_token: Optional[str] = None,
    lab_mode: str = "buggy",
    cycle: TestCycle = "all_errors",
):
    if not x_user_email:
        raise HTTPException(status_code=401, detail="Falta cabecera X-User-Email")
    email = x_user_email.strip().lower()
    user = conn.execute(
        "SELECT id, email, role, password_hash FROM users WHERE lower(email) = ?",
        (email,),
    ).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no registrado")

    # En all_clean o modo clean se exige token de sesión activo
    if cycle == "all_clean" or lab_mode == "clean":
        if not x_session_token or x_session_token not in ACTIVE_SESSIONS:
            raise HTTPException(
                status_code=401,
                detail="Se requiere X-Session-Token válido de sesión activa.",
            )
        if ACTIVE_SESSIONS[x_session_token]["email"] != email:
            raise HTTPException(status_code=401, detail="Token de sesión no coincide con el usuario.")

    return user


def compute_final_amount(amount: float, discount_pct: float, lab_mode: str, cycle: TestCycle) -> float:
    standard = round(amount * (1.0 - discount_pct / 100.0), 2)
    if lab_mode == "clean" or cycle == "all_clean":
        return standard
    # En all_errors y half_errors (1 fallo de negocio): descuento > 15% se calcula mal
    if discount_pct > 15:
        return round(amount * (1.0 - discount_pct / 200.0), 2)
    return standard


def evaluate_risk_by_cycle(payload: OrderCreateRequest, lab_mode: str, cycle: TestCycle) -> dict:
    has_pii_pattern = bool(
        re.search(r"(\b\d{8}[A-Za-z]\b|\b\d{9}\b|@)", payload.notes or "")
    )
    findings = []

    if lab_mode == "clean" or cycle == "all_clean":
        if payload.marketing_consent == 0 and has_pii_pattern:
            findings.append("RGPD: Se detectan posibles datos personales/contacto en notas con marketing_consent=0.")
        elif has_pii_pattern:
            findings.append("Privacidad: Se detectan posibles datos personales/contacto en notas; revisar minimización.")
        if payload.discount_pct > 20:
            findings.append("Negocio: Descuento superior al 20% requiere revisión de margen.")
    elif cycle == "half_errors":
        # 1 fallo RGPD: no detecta PII en notas cuando marketing_consent=0, pero sí alerta descuento > 20%
        if payload.discount_pct > 20:
            findings.append("Negocio: Descuento superior al 20% requiere revisión de margen.")
    else:
        # all_errors: omite alertas RGPD y de descuento
        pass

    risk_level = "ALTO" if findings else ("BAJO" if (lab_mode == "clean" or cycle == "all_clean") else "NO_EVALUADO")
    return {
        "cycle": cycle,
        "lab_mode": lab_mode,
        "risk_level": risk_level,
        "findings": findings,
        "marketing_consent": payload.marketing_consent,
        "has_pii_in_notes": has_pii_pattern,
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "current_cycle": CURRENT_CYCLE,
        "cycles_supported": ["all_errors", "half_errors", "all_clean"],
    }


@app.get("/app", response_class=HTMLResponse)
def serve_frontend():
    html_path = Path(__file__).resolve().parent / "static" / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"), status_code=200)


@app.post("/cycle/set")
def set_test_cycle(
    payload: CycleChangeRequest,
    x_user_email: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default="buggy"),
    x_clean_token: Optional[str] = Header(default=None),
):
    global CURRENT_CYCLE
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    previous = CURRENT_CYCLE
    CURRENT_CYCLE = payload.cycle
    actor = (x_user_email or "instructor").strip().lower()
    role = "instructor"
    if x_user_email:
        u = conn.execute("SELECT role FROM users WHERE lower(email) = ?", (actor,)).fetchone()
        if u:
            role = u["role"]
    trace_code = log_audit(
        actor_email=actor,
        role=role,
        action="SET_CYCLE",
        status_code=200,
        detail=f"Ciclo cambiado de {previous} a {CURRENT_CYCLE}",
        lab_mode=mode,
        cycle=CURRENT_CYCLE,
    )
    return {
        "previous_cycle": previous,
        "current_cycle": CURRENT_CYCLE,
        "trace_code": trace_code,
    }


@app.post("/mode/clean-login")
def clean_mode_login(payload: CleanModeAuthRequest):
    if payload.username.strip().lower() != CLEAN_MODE_USER or payload.password != CLEAN_MODE_PASS:
        trace_code = log_audit(
            actor_email=payload.username.strip().lower() or "unknown",
            role="guest",
            action="CLEAN_MODE_LOGIN",
            status_code=401,
            detail="Credenciales inválidas para modo CLEAN",
            lab_mode="buggy",
        )
        raise HTTPException(status_code=401, detail=f"Credenciales de modo CLEAN inválidas ({trace_code})")
    token = secrets.token_hex(24)
    ACTIVE_CLEAN_TOKENS.add(token)
    trace_code = log_audit(
        actor_email=CLEAN_MODE_USER,
        role="clean_operator",
        action="CLEAN_MODE_LOGIN",
        status_code=200,
        detail="Modo CLEAN activado",
        lab_mode="clean",
    )
    return {"lab_mode": "clean", "clean_token": token, "trace_code": trace_code}


@app.post("/login")
def login(
    payload: LoginRequest,
    x_lab_mode: Optional[str] = Header(default="buggy"),
    x_clean_token: Optional[str] = Header(default=None),
    x_test_cycle: Optional[str] = Header(default=None),
):
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    cycle = resolve_cycle(x_test_cycle)
    email = payload.email.strip().lower()
    user = conn.execute(
        "SELECT id, email, role, password_hash FROM users WHERE lower(email) = ?",
        (email,),
    ).fetchone()
    if not user or user["password_hash"] != payload.password:
        trace_code = log_audit(
            actor_email=email,
            role="unknown",
            action="LOGIN",
            status_code=401,
            detail="Login fallido",
            lab_mode=mode,
            cycle=cycle,
        )
        raise HTTPException(status_code=401, detail=f"Credenciales inválidas ({trace_code})")

    session_token = secrets.token_hex(20)
    ACTIVE_SESSIONS[session_token] = {"email": user["email"], "role": user["role"]}
    trace_code = log_audit(
        actor_email=user["email"],
        role=user["role"],
        action="LOGIN",
        status_code=200,
        detail="Inicio de sesión correcto",
        lab_mode=mode,
        cycle=cycle,
    )
    return {
        "authenticated": True,
        "lab_mode": mode,
        "cycle": cycle,
        "email": user["email"],
        "role": user["role"],
        "session_token": session_token,
        "trace_code": trace_code,
    }


@app.post("/logout")
def logout(
    x_user_email: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default="buggy"),
    x_clean_token: Optional[str] = Header(default=None),
    x_test_cycle: Optional[str] = Header(default=None),
):
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    cycle = resolve_cycle(x_test_cycle)
    if x_session_token and x_session_token in ACTIVE_SESSIONS:
        ACTIVE_SESSIONS.pop(x_session_token, None)
    actor = (x_user_email or "anonymous").strip().lower()
    role = "guest"
    if x_user_email:
        u = conn.execute("SELECT role FROM users WHERE lower(email) = ?", (actor,)).fetchone()
        if u:
            role = u["role"]
    trace_code = log_audit(
        actor_email=actor,
        role=role,
        action="LOGOUT",
        status_code=200,
        detail="Cierre de sesión",
        lab_mode=mode,
        cycle=cycle,
    )
    return {"authenticated": False, "lab_mode": mode, "cycle": cycle, "trace_code": trace_code}


@app.post("/reset-lab")
def reset_lab(
    x_user_email: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default="buggy"),
    x_clean_token: Optional[str] = Header(default=None),
    x_test_cycle: Optional[str] = Header(default=None),
):
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    cycle = resolve_cycle(x_test_cycle)
    user = get_current_user(x_user_email, x_session_token, mode, cycle)

    # En all_errors se permite reset sin validar rol admin; en half_errors y all_clean se exige admin
    if cycle != "all_errors" and user["role"] != "admin":
        trace_code = log_audit(
            actor_email=user["email"],
            role=user["role"],
            action="RESET_LAB",
            status_code=403,
            detail="Intento no autorizado de reset-lab",
            lab_mode=mode,
            cycle=cycle,
        )
        raise HTTPException(status_code=403, detail=f"Solo admin puede reiniciar ({trace_code})")

    conn.execute("DELETE FROM orders")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='orders'")
    conn.execute("DELETE FROM audit_logs")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='audit_logs'")
    conn.commit()
    seed_initial_orders()

    trace_code = log_audit(
        actor_email=user["email"],
        role=user["role"],
        action="RESET_LAB",
        status_code=200,
        detail="Laboratorio reiniciado",
        lab_mode=mode,
        cycle=cycle,
    )
    return {"reset": True, "cycle": cycle, "trace_code": trace_code}


@app.post("/orders/ai-risk-check")
def ai_risk_check(
    payload: OrderCreateRequest,
    x_user_email: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default="buggy"),
    x_clean_token: Optional[str] = Header(default=None),
    x_test_cycle: Optional[str] = Header(default=None),
):
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    cycle = resolve_cycle(x_test_cycle)
    user = get_current_user(x_user_email, x_session_token, mode, cycle)
    if user["role"] == "viewer" and mode == "clean":
        raise HTTPException(status_code=403, detail="Viewer sin permiso para evaluar riesgo/RGPD")

    assessment = evaluate_risk_by_cycle(payload, mode, cycle)
    trace_code = log_audit(
        actor_email=user["email"],
        role=user["role"],
        action="AI_RISK_CHECK",
        status_code=200,
        detail=f"Riesgo={assessment['risk_level']} hallazgos={len(assessment['findings'])}",
        lab_mode=mode,
        cycle=cycle,
    )
    return {"cycle": cycle, "lab_mode": mode, "assessment": assessment, "trace_code": trace_code}


@app.post("/orders", status_code=201)
def create_order(
    payload: OrderCreateRequest,
    x_user_email: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default="buggy"),
    x_clean_token: Optional[str] = Header(default=None),
    x_test_cycle: Optional[str] = Header(default=None),
):
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    cycle = resolve_cycle(x_test_cycle)
    user = get_current_user(x_user_email, x_session_token, mode, cycle)

    # En all_errors se permite crear pedidos para terceros; en half_errors y all_clean se bloquea a customer
    if cycle != "all_errors" and mode != "buggy" and user["role"] == "customer":
        if str(payload.customer_email).lower() != user["email"].lower():
            trace_code = log_audit(
                actor_email=user["email"],
                role=user["role"],
                action="CREATE_ORDER",
                status_code=403,
                detail="customer intentó crear pedido para otro cliente",
                lab_mode=mode,
                cycle=cycle,
            )
            raise HTTPException(status_code=403, detail=f"No autorizado ({trace_code})")

    final_amount = compute_final_amount(payload.amount, payload.discount_pct, mode, cycle)
    cur = conn.execute(
        """
        INSERT INTO orders (
            owner_email, customer_email, amount, discount_pct,
            final_amount, status, marketing_consent, notes
        )
        VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
        """,
        (
            user["email"],
            str(payload.customer_email).lower(),
            payload.amount,
            payload.discount_pct,
            final_amount,
            payload.marketing_consent,
            payload.notes,
        ),
    )
    conn.commit()
    order_code = fmt_order_id(cur.lastrowid)
    trace_code = log_audit(
        actor_email=user["email"],
        role=user["role"],
        action="CREATE_ORDER",
        status_code=201,
        detail=f"Creado {order_code} final={final_amount}",
        lab_mode=mode,
        cycle=cycle,
    )
    row = conn.execute("SELECT * FROM orders WHERE id = ?", (cur.lastrowid,)).fetchone()
    order_data = serialize_order(row)
    order_data["trace_code"] = trace_code
    return {"cycle": cycle, "lab_mode": mode, "order": order_data, "trace_code": trace_code}


@app.get("/orders")
def list_orders(
    x_user_email: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default="buggy"),
    x_clean_token: Optional[str] = Header(default=None),
    x_test_cycle: Optional[str] = Header(default=None),
):
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    cycle = resolve_cycle(x_test_cycle)
    user = get_current_user(x_user_email, x_session_token, mode, cycle)
    if user["role"] in ("admin", "viewer"):
        rows = conn.execute("SELECT * FROM orders ORDER BY id DESC").fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM orders WHERE lower(owner_email) = ? OR lower(customer_email) = ? ORDER BY id DESC",
            (user["email"].lower(), user["email"].lower()),
        ).fetchall()
    log_audit(user["email"], user["role"], "LIST_ORDERS", 200, f"Total={len(rows)}", mode, cycle)
    return {"cycle": cycle, "lab_mode": mode, "orders": [serialize_order(r) for r in rows]}


@app.patch("/orders/{order_id}/status")
def update_order_status(
    order_id: int,
    payload: OrderStatusUpdate,
    x_user_email: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default="buggy"),
    x_clean_token: Optional[str] = Header(default=None),
    x_test_cycle: Optional[str] = Header(default=None),
):
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    cycle = resolve_cycle(x_test_cycle)
    user = get_current_user(x_user_email, x_session_token, mode, cycle)
    order_code = fmt_order_id(order_id)

    # En all_errors y half_errors (1 fallo RBAC): customer puede cambiar estado; en all_clean solo admin
    if cycle == "all_clean" and user["role"] != "admin":
        trace_code = log_audit(
            actor_email=user["email"],
            role=user["role"],
            action="UPDATE_ORDER_STATUS",
            status_code=403,
            detail=f"Denegado cambiar estado de {order_code}",
            lab_mode=mode,
            cycle=cycle,
        )
        raise HTTPException(status_code=403, detail=f"Solo admin puede cambiar estado ({trace_code})")

    existing = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail=f"{order_code} no encontrado")

    conn.execute("UPDATE orders SET status = ? WHERE id = ?", (payload.status, order_id))
    conn.commit()
    trace_code = log_audit(
        actor_email=user["email"],
        role=user["role"],
        action="UPDATE_ORDER_STATUS",
        status_code=200,
        detail=f"{order_code} -> {payload.status}",
        lab_mode=mode,
        cycle=cycle,
    )
    updated = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    return {"cycle": cycle, "lab_mode": mode, "order": serialize_order(updated), "trace_code": trace_code}


@app.delete("/orders/{order_id}")
def delete_order(
    order_id: int,
    x_user_email: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default="buggy"),
    x_clean_token: Optional[str] = Header(default=None),
    x_test_cycle: Optional[str] = Header(default=None),
):
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    cycle = resolve_cycle(x_test_cycle)
    user = get_current_user(x_user_email, x_session_token, mode, cycle)
    order_code = fmt_order_id(order_id)

    if cycle == "all_clean" and user["role"] != "admin":
        trace_code = log_audit(
            actor_email=user["email"],
            role=user["role"],
            action="DELETE_ORDER",
            status_code=403,
            detail=f"Denegado borrar {order_code}",
            lab_mode=mode,
            cycle=cycle,
        )
        raise HTTPException(status_code=403, detail=f"Solo admin puede borrar ({trace_code})")

    existing = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail=f"{order_code} no encontrado")

    conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    trace_code = log_audit(
        actor_email=user["email"],
        role=user["role"],
        action="DELETE_ORDER",
        status_code=200,
        detail=f"Borrado {order_code}",
        lab_mode=mode,
        cycle=cycle,
    )
    return {"deleted": True, "order_code": order_code, "cycle": cycle, "trace_code": trace_code}


@app.get("/audit-logs")
def get_audit_logs(
    limit: int = Query(default=25, ge=1, le=100),
    actor_filter: Optional[str] = Query(default=None),
    x_user_email: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default="buggy"),
    x_clean_token: Optional[str] = Header(default=None),
    x_test_cycle: Optional[str] = Header(default=None),
):
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    cycle = resolve_cycle(x_test_cycle)
    user = get_current_user(x_user_email, x_session_token, mode, cycle)

    # En all_errors se expone todo el historial incluso a no-admin; en half_errors y all_clean se aísla
    if user["role"] == "admin" or cycle == "all_errors":
        if actor_filter and actor_filter.strip():
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE lower(actor_email) LIKE ? ORDER BY id DESC LIMIT ?",
                (f"%{actor_filter.strip().lower()}%", limit),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM audit_logs WHERE lower(actor_email) = ? ORDER BY id DESC LIMIT ?",
            (user["email"].lower(), limit),
        ).fetchall()

    return {"cycle": cycle, "lab_mode": mode, "count": len(rows), "logs": [serialize_audit(r) for r in rows]}

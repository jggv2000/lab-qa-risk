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
                # --- DATOS BUENOS ---
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
                # --- DATOS MALOS / ANÓMALOS ---
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


ensure_schema_and_seed()
seed_initial_orders()

app = FastAPI(
    title="Pearson QA Risk Lab API — 3 Ciclos + Visor BD + Sintéticos",
    description="Laboratorio endurecido con ciclos all_errors, half_errors y all_clean, controles de entrada, visor SQLite y datos sintéticos.",
    version="4.0.0",
)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class CleanModeAuthRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class CycleChangeRequest(BaseModel):
    cycle: TestCycle


class OrderFlexibleInput(BaseModel):
    customer_email: str = Field(default="")
    amount: float = Field(default=0.0)
    discount_pct: float = Field(default=0.0)
    marketing_consent: int = Field(default=0)
    notes: str = Field(default="")


class OrderStatusUpdate(BaseModel):
    status: Literal["pending", "approved", "cancelled"]


class SyntheticBatchRequest(BaseModel):
    profile: Literal["normal", "extremos", "rgpd", "mixto"] = "mixto"
    count: int = Field(default=4, ge=1, le=20)


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

    if cycle == "all_clean" or lab_mode == "clean":
        if not x_session_token or x_session_token not in ACTIVE_SESSIONS:
            raise HTTPException(status_code=401, detail="Se requiere X-Session-Token válido.")
        if ACTIVE_SESSIONS[x_session_token]["email"] != email:
            raise HTTPException(status_code=401, detail="Token de sesión no coincide con X-User-Email.")

    return user


def validate_and_sanitize_order_fields(
    payload: OrderFlexibleInput,
    lab_mode: str,
    cycle: TestCycle,
) -> tuple[str, float, float, int, str]:
    raw_email = (payload.customer_email or "").strip()
    raw_notes = payload.notes or ""

    # Ciclo 1: SIN CONTROLES
    if cycle == "all_errors" and lab_mode != "clean":
        return raw_email, payload.amount, payload.discount_pct, payload.marketing_consent, raw_notes

    # Ciclo 2: CONTROLES PARCIALES (bloquea rangos numéricos imposibles; deja pasar formato email y HTML en notas)
    if cycle == "half_errors" and lab_mode != "clean":
        if payload.amount <= 0 or payload.amount > 100000:
            raise HTTPException(status_code=422, detail="Control parcial: amount debe estar entre 0.01 y 100000.")
        if payload.discount_pct < 0 or payload.discount_pct > 100:
            raise HTTPException(status_code=422, detail="Control parcial: discount_pct debe estar entre 0 y 100.")
        if payload.marketing_consent not in (0, 1):
            raise HTTPException(status_code=422, detail="Control parcial: marketing_consent debe ser 0 o 1.")
        return raw_email.lower(), payload.amount, payload.discount_pct, payload.marketing_consent, raw_notes

    # Ciclo 3 (o modo CLEAN): CON CONTROLES ESTRICTOS
    if not re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", raw_email):
        raise HTTPException(status_code=422, detail="Control estricto: customer_email sin formato válido.")
    if payload.amount <= 0 or payload.amount > 100000:
        raise HTTPException(status_code=422, detail="Control estricto: amount debe ser > 0 y <= 100000.")
    if payload.discount_pct < 0 or payload.discount_pct > 100:
        raise HTTPException(status_code=422, detail="Control estricto: discount_pct debe estar entre 0 y 100.")
    if payload.marketing_consent not in (0, 1):
        raise HTTPException(status_code=422, detail="Control estricto: marketing_consent solo admite 0 o 1.")
    if len(raw_notes) > 500:
        raise HTTPException(status_code=422, detail="Control estricto: notes supera 500 caracteres.")
    if "<" in raw_notes or ">" in raw_notes:
        raise HTTPException(status_code=422, detail="Control estricto: '<' o '>' no permitidos en notes (prevención XSS).")

    return raw_email.lower(), payload.amount, payload.discount_pct, payload.marketing_consent, raw_notes.strip()


def compute_final_amount(amount: float, discount_pct: float, lab_mode: str, cycle: TestCycle) -> float:
    standard = round(amount * (1.0 - discount_pct / 100.0), 2)
    if lab_mode == "clean" or cycle == "all_clean":
        return standard
    if discount_pct > 15:
        return round(amount * (1.0 - discount_pct / 200.0), 2)
    return standard


def evaluate_risk_by_cycle(payload: OrderFlexibleInput, lab_mode: str, cycle: TestCycle) -> dict:
    has_pii = bool(re.search(r"(\b\d{8}[A-Za-z]\b|\b\d{9}\b|@)", payload.notes or ""))
    has_xss = "<" in (payload.notes or "") or ">" in (payload.notes or "")
    findings = []

    if lab_mode == "clean" or cycle == "all_clean":
        if payload.marketing_consent == 0 and has_pii:
            findings.append("RGPD: Datos personales/contacto en notas con marketing_consent=0.")
        elif has_pii:
            findings.append("Privacidad: Datos personales/contacto en notas; aplicar minimización.")
        if has_xss:
            findings.append("Seguridad: Etiquetas HTML/script detectadas en notas.")
        if payload.discount_pct > 20:
            findings.append("Negocio: Descuento superior al 20% requiere revisión.")
        if payload.amount <= 0 or payload.discount_pct < 0 or payload.discount_pct > 100:
            findings.append("Integridad: Valores fuera de rango permitido.")
    elif cycle == "half_errors":
        if payload.discount_pct > 20:
            findings.append("Negocio: Descuento superior al 20% requiere revisión.")
    else:
        pass

    risk_level = "ALTO" if findings else ("BAJO" if (lab_mode == "clean" or cycle == "all_clean") else "NO_EVALUADO")
    return {
        "cycle": cycle,
        "lab_mode": lab_mode,
        "risk_level": risk_level,
        "findings": findings,
        "marketing_consent": payload.marketing_consent,
        "has_pii_in_notes": has_pii,
        "has_html_in_notes": has_xss,
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "current_cycle": CURRENT_CYCLE,
        "db_path": DB_PATH,
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
    return {"previous_cycle": previous, "current_cycle": CURRENT_CYCLE, "trace_code": trace_code}


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
        trace_code = log_audit(email, "unknown", "LOGIN", 401, "Login fallido", mode, cycle)
        raise HTTPException(status_code=401, detail=f"Credenciales inválidas ({trace_code})")

    session_token = secrets.token_hex(20)
    ACTIVE_SESSIONS[session_token] = {"email": user["email"], "role": user["role"]}
    trace_code = log_audit(user["email"], user["role"], "LOGIN", 200, "Inicio de sesión correcto", mode, cycle)
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
    trace_code = log_audit(actor, role, "LOGOUT", 200, "Cierre de sesión", mode, cycle)
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

    if cycle != "all_errors" and user["role"] != "admin":
        trace_code = log_audit(user["email"], user["role"], "RESET_LAB", 403, "Intento no autorizado de reset", mode, cycle)
        raise HTTPException(status_code=403, detail=f"Solo admin puede reiniciar ({trace_code})")

    conn.execute("DELETE FROM orders")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='orders'")
    conn.execute("DELETE FROM audit_logs")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='audit_logs'")
    conn.commit()
    seed_initial_orders()

    trace_code = log_audit(user["email"], user["role"], "RESET_LAB", 200, "Laboratorio reiniciado con datos buenos y malos", mode, cycle)
    return {"reset": True, "cycle": cycle, "trace_code": trace_code}


@app.post("/orders/ai-risk-check")
def ai_risk_check(
    payload: OrderFlexibleInput,
    x_user_email: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default="buggy"),
    x_clean_token: Optional[str] = Header(default=None),
    x_test_cycle: Optional[str] = Header(default=None),
):
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    cycle = resolve_cycle(x_test_cycle)
    user = get_current_user(x_user_email, x_session_token, mode, cycle)
    if user["role"] == "viewer" and (mode == "clean" or cycle == "all_clean"):
        raise HTTPException(status_code=403, detail="Viewer sin permiso para evaluar riesgo/RGPD")

    assessment = evaluate_risk_by_cycle(payload, mode, cycle)
    trace_code = log_audit(
        user["email"],
        user["role"],
        "AI_RISK_CHECK",
        200,
        f"Riesgo={assessment['risk_level']} hallazgos={len(assessment['findings'])}",
        mode,
        cycle,
    )
    return {"cycle": cycle, "lab_mode": mode, "assessment": assessment, "trace_code": trace_code}


@app.post("/orders", status_code=201)
def create_order(
    payload: OrderFlexibleInput,
    x_user_email: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default="buggy"),
    x_clean_token: Optional[str] = Header(default=None),
    x_test_cycle: Optional[str] = Header(default=None),
):
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    cycle = resolve_cycle(x_test_cycle)
    user = get_current_user(x_user_email, x_session_token, mode, cycle)

    try:
        cust_email, amount, discount_pct, consent, clean_notes = validate_and_sanitize_order_fields(
            payload, mode, cycle
        )
    except HTTPException as exc:
        trace_code = log_audit(
            user["email"], user["role"], "CREATE_ORDER_VALIDATION", exc.status_code, str(exc.detail), mode, cycle
        )
        raise HTTPException(status_code=exc.status_code, detail=f"{exc.detail} ({trace_code})")

    if cycle != "all_errors" and user["role"] == "customer" and cust_email != user["email"].lower():
        trace_code = log_audit(user["email"], user["role"], "CREATE_ORDER", 403, "Pedido para tercero bloqueado", mode, cycle)
        raise HTTPException(status_code=403, detail=f"No autorizado ({trace_code})")

    final_amount = compute_final_amount(amount, discount_pct, mode, cycle)
    cur = conn.execute(
        """
        INSERT INTO orders (
            owner_email, customer_email, amount, discount_pct,
            final_amount, status, marketing_consent, notes
        )
        VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
        """,
        (user["email"], cust_email, amount, discount_pct, final_amount, consent, clean_notes),
    )
    conn.commit()
    order_code = fmt_order_id(cur.lastrowid)
    trace_code = log_audit(
        user["email"], user["role"], "CREATE_ORDER", 201, f"Creado {order_code} final={final_amount}", mode, cycle
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

    if cycle == "all_clean" and user["role"] != "admin":
        trace_code = log_audit(user["email"], user["role"], "UPDATE_ORDER_STATUS", 403, f"Denegado {order_code}", mode, cycle)
        raise HTTPException(status_code=403, detail=f"Solo admin puede cambiar estado ({trace_code})")

    existing = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail=f"{order_code} no encontrado")

    conn.execute("UPDATE orders SET status = ? WHERE id = ?", (payload.status, order_id))
    conn.commit()
    trace_code = log_audit(user["email"], user["role"], "UPDATE_ORDER_STATUS", 200, f"{order_code} -> {payload.status}", mode, cycle)
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
        trace_code = log_audit(user["email"], user["role"], "DELETE_ORDER", 403, f"Denegado borrar {order_code}", mode, cycle)
        raise HTTPException(status_code=403, detail=f"Solo admin puede borrar ({trace_code})")

    existing = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail=f"{order_code} no encontrado")

    conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    trace_code = log_audit(user["email"], user["role"], "DELETE_ORDER", 200, f"Borrado {order_code}", mode, cycle)
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


@app.get("/db/inspect")
def inspect_database(
    sample_limit: int = Query(default=10, ge=1, le=50),
    x_user_email: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default="buggy"),
    x_clean_token: Optional[str] = Header(default=None),
    x_test_cycle: Optional[str] = Header(default=None),
):
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    cycle = resolve_cycle(x_test_cycle)
    user = get_current_user(x_user_email, x_session_token, mode, cycle)

    if (mode == "clean" or cycle == "all_clean") and user["role"] != "admin":
        trace_code = log_audit(user["email"], user["role"], "DB_INSPECT", 403, "Denegado visor BD", mode, cycle)
        raise HTTPException(status_code=403, detail=f"Solo admin puede inspeccionar BD ({trace_code})")

    counts = {
        "users": conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"],
        "orders": conn.execute("SELECT COUNT(*) AS c FROM orders").fetchone()["c"],
        "audit_logs": conn.execute("SELECT COUNT(*) AS c FROM audit_logs").fetchone()["c"],
    }
    schema = {
        tbl: [
            {"name": r["name"], "type": r["type"], "notnull": bool(r["notnull"])}
            for r in conn.execute(f"PRAGMA table_info({tbl})").fetchall()
        ]
        for tbl in ("users", "orders", "audit_logs")
    }
    recent_orders = [serialize_order(r) for r in conn.execute("SELECT * FROM orders ORDER BY id DESC LIMIT ?", (sample_limit,)).fetchall()]
    recent_logs = [serialize_audit(r) for r in conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (sample_limit,)).fetchall()]

    trace_code = log_audit(user["email"], user["role"], "DB_INSPECT", 200, f"Inspección BD orders={counts['orders']}", mode, cycle)
    return {
        "cycle": cycle,
        "lab_mode": mode,
        "db_path": DB_PATH,
        "counts": counts,
        "schema": schema,
        "recent_orders": recent_orders,
        "recent_logs": recent_logs,
        "trace_code": trace_code,
    }


@app.post("/test-data/generate")
def generate_synthetic_data(
    payload: SyntheticBatchRequest,
    x_user_email: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None),
    x_lab_mode: Optional[str] = Header(default="buggy"),
    x_clean_token: Optional[str] = Header(default=None),
    x_test_cycle: Optional[str] = Header(default=None),
):
    mode = resolve_lab_mode(x_lab_mode, x_clean_token)
    cycle = resolve_cycle(x_test_cycle)
    user = get_current_user(x_user_email, x_session_token, mode, cycle)
    if user["role"] != "admin":
        trace_code = log_audit(user["email"], user["role"], "GEN_SYNTHETIC_DATA", 403, "Denegado sintéticos", mode, cycle)
        raise HTTPException(status_code=403, detail=f"Solo admin puede generar sintéticos ({trace_code})")

    templates = {
        "normal": [
            ("cliente1@ejemplo.com", 150.0, 5.0, 1, "[BUENO] Sintético normal descuento bajo"),
            ("cliente2@ejemplo.com", 240.0, 10.0, 1, "[BUENO] Sintético normal estándar"),
        ],
        "extremos": [
            ("cliente1@ejemplo.com", 100.0, 0.0, 1, "[EXTREMO] Descuento 0%"),
            ("cliente2@ejemplo.com", 500.0, 15.0, 1, "[EXTREMO] Umbral 15%"),
            ("cliente1@ejemplo.com", 1000.0, 25.0, 0, "[EXTREMO] Descuento 25% (>15%)"),
            ("cliente2@ejemplo.com", 750.0, 100.0, 0, "[EXTREMO] Descuento 100%"),
        ],
        "rgpd": [
            ("cliente2@ejemplo.com", 420.0, 20.0, 0, "[MALO-RGPD] Tel 600000111 DNI-00000001A consent=0"),
            ("correo-roto-sin-arroba", -50.0, 130.0, 9, "[MALO-CAMPOS] Registro anómalo para auditoría"),
        ],
    }
    pool = templates["normal"] + templates["extremos"] + templates["rgpd"] if payload.profile == "mixto" else templates[payload.profile]

    created_codes = []
    for idx in range(payload.count):
        cust, amt, disc, consent, note = pool[idx % len(pool)]
        final_amt = compute_final_amount(amt, disc, mode, cycle)
        cur = conn.execute(
            """
            INSERT INTO orders (
                owner_email, customer_email, amount, discount_pct,
                final_amount, status, marketing_consent, notes
            )
            VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
            """,
            (user["email"], cust, amt, disc, final_amt, consent, f"{note} [#{idx + 1}]"),
        )
        created_codes.append(fmt_order_id(cur.lastrowid))

    conn.commit()
    trace_code = log_audit(
        user["email"], user["role"], "GEN_SYNTHETIC_DATA", 201, f"Generados {len(created_codes)} ({payload.profile})", mode, cycle
    )
    return {
        "cycle": cycle,
        "lab_mode": mode,
        "profile": payload.profile,
        "generated_count": len(created_codes),
        "order_codes": created_codes,
        "trace_code": trace_code,
    }

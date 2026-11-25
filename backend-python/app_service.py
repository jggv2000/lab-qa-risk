from __future__ import annotations

import json
import random
import time
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ai_risk_advisor import evaluate_order_risk
from database import DatabaseManager
from version_switches import DEFAULT_VERSION, VERSION_CONFIG, get_version_profile, is_flag_enabled

app = FastAPI(title="Risk-Based Testing Lab API", version="3.5")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db = DatabaseManager()
LAST_API_RESPONSE: Dict[str, Any] = {
    "status_code": 200,
    "method": "GET",
    "path": "/api/health",
    "body": {"status": "ok", "version": DEFAULT_VERSION},
}


# --- Modelos de entrada ---
class LoginRequest(BaseModel):
    usuario: str
    password: str


class UserProfileUpdate(BaseModel):
    correo: str
    ciudad: str
    telefono: str
    acepta_rgpd: bool = False


class OrderCreate(BaseModel):
    titulo: str
    importe: float
    cliente_id: Optional[int] = None


class OrderStatusUpdate(BaseModel):
    nuevo_estado: str


class AdminConfigUpdate(BaseModel):
    session_timeout_seconds: int = Field(ge=5, le=3600)
    max_failed_attempts: int = Field(ge=1, le=20)


class SyntheticDataRequest(BaseModel):
    cantidad_pedidos: int = Field(ge=1, le=500, default=20)
    cantidad_usuarios_extra: int = Field(ge=0, le=100, default=0)
    calidad: str = Field(pattern="^(bien_creados|mal_creados)$")


class ImportDataRequest(BaseModel):
    payload: Dict[str, Any]


# --- Helpers de versión, sesión y trazabilidad ---
def resolve_version(x_lab_version: Optional[str]) -> str:
    if x_lab_version and x_lab_version in VERSION_CONFIG:
        return x_lab_version
    return db.get_active_version() or DEFAULT_VERSION


def record_response(response: Response, status_code: int, method: str, path: str, body: Any) -> Any:
    global LAST_API_RESPONSE
    response.status_code = status_code
    LAST_API_RESPONSE = {
        "status_code": status_code,
        "method": method,
        "path": path,
        "body": body,
    }
    return body


def log_audit(version: str, actor: str, role: str, action: str, detail: str) -> None:
    if is_flag_enabled(version, "skip_traceability"):
        return
    db.add_trace(actor=actor, role=role, action=action, detail=f"[{version}] {detail}")


def require_session(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    version = resolve_version(x_lab_version)
    token = x_session_token or request.headers.get("x-session-token") or request.query_params.get("token")
    if not token:
        body = {"error": "Sesión no iniciada"}
        raise HTTPException(
            status_code=401,
            detail=record_response(response, 401, request.method, request.url.path, body),
        )

    session = db.get_session(token)
    if not session:
        body = {"error": "Sesión inválida o cerrada"}
        raise HTTPException(
            status_code=401,
            detail=record_response(response, 401, request.method, request.url.path, body),
        )

    timeout_sec = db.get_settings()["session_timeout_seconds"]
    elapsed = time.time() - session["last_activity"]
    if not is_flag_enabled(version, "session_no_timeout") and elapsed > timeout_sec:
        db.delete_session(token)
        body = {"error": "Sesión caducada por inactividad"}
        raise HTTPException(
            status_code=401,
            detail=record_response(response, 401, request.method, request.url.path, body),
        )

    db.touch_session(token, time.time())
    user = db.get_user_by_id(session["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return {"user": user, "version": version, "token": token}


# --- Interfaz estática y salud ---
@app.get("/")
def serve_index() -> FileResponse:
    return FileResponse("static/index.html")


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/api/health")
def health_check(request: Request, response: Response, x_lab_version: Optional[str] = Header(default=None)):
    version = resolve_version(x_lab_version)
    return record_response(
        response,
        200,
        request.method,
        request.url.path,
        {"status": "ok", "version": version},
    )


# --- Endpoints de versión y última respuesta ---
@app.get("/api/version")
def get_version_info(request: Request, response: Response, x_lab_version: Optional[str] = Header(default=None)):
    version = resolve_version(x_lab_version)
    profile = get_version_profile(version)
    body = {
        "active_version": version,
        "version": version,
        "counts": profile["counts"],
        "total_errors": profile["total_errors"],
        "flags": profile["flags"],
    }
    return record_response(response, 200, request.method, request.url.path, body)


@app.post("/api/version/{version}")
def set_version_info(version: str, request: Request, response: Response):
    if version not in VERSION_CONFIG:
        body = {"error": "Versión no soportada (use v3.1 a v3.5)"}
        return record_response(response, 400, request.method, request.url.path, body)
    db.set_active_version(version)
    log_audit(version, "system", "system", "VERSION_SWITCH", f"Versión activa cambiada a {version}")
    return record_response(response, 200, request.method, request.url.path, {"active_version": version})


@app.get("/api/last-response")
def get_last_response(request: Request, response: Response):
    return record_response(response, 200, request.method, request.url.path, LAST_API_RESPONSE)


# --- Autenticación y bloqueo ---
@app.post("/api/auth/login")
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    x_lab_version: Optional[str] = Header(default=None),
):
    version = resolve_version(x_lab_version)
    user = db.get_user_by_login(payload.usuario)
    settings = db.get_settings()
    max_attempts = settings["max_failed_attempts"]

    if not user:
        log_audit(version, payload.usuario, "anonymous", "LOGIN_FAIL", "Usuario inexistente")
        body = {"error": "Credenciales inválidas"}
        return record_response(response, 401, request.method, request.url.path, body)

    if user["locked"]:
        log_audit(version, user["username"], user["role"], "LOGIN_BLOCKED", "Intento en cuenta bloqueada")
        body = {"error": "Usuario bloqueado. Debe desbloquearlo un administrador."}
        return record_response(response, 403, request.method, request.url.path, body)

    password_ok = user["password"] == payload.password
    if is_flag_enabled(version, "owasp_weak_auth_input") and payload.password in ("admin123", "1234", "admin"):
        password_ok = True

    if not password_ok:
        attempts = user["failed_attempts"] + 1
        locked = attempts >= max_attempts
        db.set_user_login_state(user["id"], attempts, locked)
        log_audit(version, user["username"], user["role"], "LOGIN_FAIL", f"Intento {attempts}/{max_attempts}")
        body = {
            "error": "Contraseña incorrecta",
            "failed_attempts": attempts,
            "max_failed_attempts": max_attempts,
            "locked": locked,
        }
        return record_response(response, 401, request.method, request.url.path, body)

    db.set_user_login_state(user["id"], 0, False)
    token = db.create_session(user["id"], time.time())
    log_audit(version, user["username"], user["role"], "LOGIN_SUCCESS", "Inicio de sesión correcto")

    user_payload = {k: v for k, v in user.items() if k != "password"}
    if is_flag_enabled(version, "expose_password"):
        user_payload["password_leaked"] = user["password"]

    body = {
        "token": token,
        "user": user_payload,
        "session_timeout_seconds": settings["session_timeout_seconds"],
    }
    return record_response(response, 200, request.method, request.url.path, body)


@app.post("/api/auth/logout")
def logout(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    db.delete_session(ctx["token"])
    log_audit(ctx["version"], ctx["user"]["username"], ctx["user"]["role"], "LOGOUT", "Cierre de sesión")
    return record_response(response, 200, request.method, request.url.path, {"message": "Sesión cerrada"})


# --- Usuarios y RGPD ---
@app.get("/api/users")
def list_users(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    if user["role"] != "admin" and not is_flag_enabled(version, "broken_rbac_escalation"):
        log_audit(version, user["username"], user["role"], "ACCESS_DENIED", "Intento de listar usuarios")
        body = {"error": "Solo el administrador puede consultar todos los usuarios"}
        return record_response(response, 403, request.method, request.url.path, body)

    users = db.get_all_users()
    sanitized = []
    for u in users:
        item = {k: v for k, v in u.items() if k != "password"}
        if is_flag_enabled(version, "expose_password") or is_flag_enabled(version, "pii_exposure_or_no_rgpd"):
            item["password"] = u["password"]
        sanitized.append(item)

    log_audit(version, user["username"], user["role"], "LIST_USERS", f"Consultados {len(sanitized)} usuarios")
    return record_response(response, 200, request.method, request.url.path, {"users": sanitized})


@app.get("/api/users/me")
def get_my_profile(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    u = ctx["user"]
    body_user = {k: v for k, v in u.items() if k != "password"}
    if is_flag_enabled(ctx["version"], "expose_password"):
        body_user["password"] = u["password"]
    return record_response(response, 200, request.method, request.url.path, {"user": body_user})


@app.put("/api/users/me")
def update_my_profile(
    payload: UserProfileUpdate,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    if user["role"] == "viewer" and not is_flag_enabled(version, "viewer_can_modify"):
        body = {"error": "El usuario viewer es de solo lectura"}
        return record_response(response, 403, request.method, request.url.path, body)

    if not is_flag_enabled(version, "pii_exposure_or_no_rgpd") and not payload.acepta_rgpd:
        body = {"error": "Debe aceptar la Política de Privacidad y Protección de Datos (RGPD)"}
        return record_response(response, 400, request.method, request.url.path, body)

    if not is_flag_enabled(version, "weak_field_validation"):
        if "@" not in payload.correo or len(payload.ciudad.strip()) < 2 or len(payload.telefono.strip()) < 6:
            body = {"error": "Datos de usuario inválidos (correo, ciudad o teléfono)"}
            return record_response(response, 400, request.method, request.url.path, body)

    updated = db.update_user_profile(user["id"], payload.correo, payload.ciudad, payload.telefono, payload.acepta_rgpd)
    log_audit(version, user["username"], user["role"], "UPDATE_PROFILE", "Actualización de datos RGPD")
    return record_response(response, 200, request.method, request.url.path, {"user": updated})


@app.post("/api/users/{target_user_id}/unlock")
def unlock_user(
    target_user_id: int,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    if user["role"] != "admin" and not is_flag_enabled(version, "broken_rbac_escalation"):
        body = {"error": "Solo un administrador puede desbloquear usuarios"}
        return record_response(response, 403, request.method, request.url.path, body)

    unlocked = db.unlock_user(target_user_id)
    if not unlocked:
        body = {"error": "Usuario no encontrado"}
        return record_response(response, 404, request.method, request.url.path, body)

    log_audit(version, user["username"], user["role"], "UNLOCK_USER", f"Desbloqueado usuario ID {target_user_id}")
    return record_response(
        response,
        200,
        request.method,
        request.url.path,
        {"message": "Usuario desbloqueado", "user": unlocked},
    )


# --- Pedidos y flujo de estados ---
@app.get("/api/orders")
def list_orders(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    if user["role"] in ("viewer", "admin"):
        orders = db.get_all_orders()
    else:
        orders = db.get_orders_by_owner(user["id"])

    log_audit(version, user["username"], user["role"], "LIST_ORDERS", f"Total pedidos devueltos: {len(orders)}")
    return record_response(response, 200, request.method, request.url.path, {"orders": orders})


@app.get("/api/orders/{order_id}")
def get_order(
    order_id: int,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    order = db.get_order_by_id(order_id)
    if not order:
        body = {"error": "Pedido no encontrado"}
        return record_response(response, 404, request.method, request.url.path, body)

    if user["role"] == "cliente" and order["owner_id"] != user["id"] and not is_flag_enabled(version, "idor"):
        body = {"error": "No puede consultar pedidos de otro cliente"}
        return record_response(response, 403, request.method, request.url.path, body)

    return record_response(response, 200, request.method, request.url.path, {"order": order})


@app.post("/api/orders")
def create_order(
    payload: OrderCreate,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    if user["role"] == "viewer" and not is_flag_enabled(version, "viewer_can_modify"):
        body = {"error": "El rol viewer no puede crear pedidos"}
        return record_response(response, 403, request.method, request.url.path, body)

    if not is_flag_enabled(version, "weak_field_validation") and payload.importe <= 0:
        body = {"error": "El importe del pedido debe ser mayor que cero"}
        return record_response(response, 400, request.method, request.url.path, body)

    owner_id = payload.cliente_id if (user["role"] == "admin" and payload.cliente_id) else user["id"]
    order = db.create_order(owner_id=owner_id, titulo=payload.titulo, importe=payload.importe, estado="En proceso")
    risk_eval = evaluate_order_risk(
        amount=float(payload.importe),
        discount_pct=0.0,
        marketing_consent=1 if user.get("rgpd_accepted") else 0,
        notes=payload.titulo,
        customer_email=user.get("email"),
        version=version,
    )
    log_audit(version, user["username"], user["role"], "CREATE_ORDER", f"Pedido #{order['id']} creado en 'En proceso'")
    return record_response(
        response,
        201,
        request.method,
        request.url.path,
        {"order": order, "risk_evaluation": risk_eval},
    )


@app.patch("/api/orders/{order_id}/status")
def transition_order_status(
    order_id: int,
    payload: OrderStatusUpdate,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]
    role = user["role"]
    target = payload.nuevo_estado

    if role == "viewer" and not is_flag_enabled(version, "viewer_can_modify"):
        body = {"error": "El usuario viewer no puede modificar pedidos"}
        return record_response(response, 403, request.method, request.url.path, body)

    order = db.get_order_by_id(order_id)
    if not order:
        body = {"error": "Pedido no encontrado"}
        return record_response(response, 404, request.method, request.url.path, body)

    if role == "cliente" and order["owner_id"] != user["id"] and not is_flag_enabled(version, "idor"):
        body = {"error": "No puede modificar un pedido ajeno"}
        return record_response(response, 403, request.method, request.url.path, body)

    current = order["estado"]
    if not is_flag_enabled(version, "broken_order_workflow"):
        if role == "cliente":
            if current == "Aprobado" and target == "Rechazado":
                body = {"error": "Un pedido Aprobado no puede ser rechazado por el cliente"}
                return record_response(response, 400, request.method, request.url.path, body)
            if not (current in ("Creado", "En proceso") and target == "Eliminado"):
                body = {"error": "Transición no permitida para el rol cliente"}
                return record_response(response, 403, request.method, request.url.path, body)
        elif role == "admin":
            allowed_from_process = {"Aprobado", "Rechazado", "Eliminado"}
            allowed_from_approved = {"Rechazado", "Eliminado", "Entregado"}
            if current in ("Creado", "En proceso") and target not in allowed_from_process:
                body = {"error": "Estado destino no válido desde En proceso"}
                return record_response(response, 400, request.method, request.url.path, body)
            if current == "Aprobado" and target not in allowed_from_approved:
                body = {"error": "Estado destino no válido desde Aprobado"}
                return record_response(response, 400, request.method, request.url.path, body)

    updated = db.update_order_status(order_id, target)
    log_audit(version, user["username"], role, "ORDER_STATUS", f"Pedido #{order_id}: {current} -> {target}")
    return record_response(response, 200, request.method, request.url.path, {"order": updated})


@app.delete("/api/orders/{order_id}")
def delete_order(
    order_id: int,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    if user["role"] == "viewer" and not is_flag_enabled(version, "viewer_can_modify"):
        body = {"error": "El usuario viewer no puede eliminar pedidos"}
        return record_response(response, 403, request.method, request.url.path, body)

    order = db.get_order_by_id(order_id)
    if not order:
        body = {"error": "Pedido no encontrado"}
        return record_response(response, 404, request.method, request.url.path, body)

    if user["role"] == "cliente" and order["owner_id"] != user["id"] and not is_flag_enabled(version, "idor"):
        body = {"error": "No puede eliminar pedidos de otro cliente"}
        return record_response(response, 403, request.method, request.url.path, body)

    db.delete_order(order_id)
    log_audit(version, user["username"], user["role"], "DELETE_ORDER", f"Eliminado pedido #{order_id}")
    return record_response(response, 200, request.method, request.url.path, {"deleted_id": order_id})


# --- Trazabilidad y rendimiento ---
@app.get("/api/traceability")
def get_traceability(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    traces = db.get_traces()
    return record_response(response, 200, request.method, request.url.path, {"traces": traces})


@app.get("/api/performance/slow-check")
@app.post("/api/performance/check")
def slow_performance_check(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    version = ctx["version"]
    delay = 6.0 if is_flag_enabled(version, "slow_hanging_button") else 0.1
    time.sleep(delay)
    log_audit(version, ctx["user"]["username"], ctx["user"]["role"], "PERF_CHECK", f"Respuesta en {delay}s")
    return record_response(response, 200, request.method, request.url.path, {"elapsed_seconds": delay, "status": "completed"})


# --- Administración: configuración, sintéticos, reset, exportar/importar ---
@app.get("/api/admin/tables")
def get_admin_tables(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    if ctx["user"]["role"] != "admin" and not is_flag_enabled(ctx["version"], "broken_rbac_escalation"):
        return record_response(response, 403, request.method, request.url.path, {"error": "Acceso restringido a administrador"})

    body = {
        "usuarios": db.get_all_users(),
        "pedidos": db.get_all_orders(),
        "trazabilidad": db.get_traces(),
        "settings": db.get_settings(),
    }
    return record_response(response, 200, request.method, request.url.path, body)


@app.put("/api/admin/settings")
def update_admin_settings(
    payload: AdminConfigUpdate,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    if ctx["user"]["role"] != "admin":
        return record_response(response, 403, request.method, request.url.path, {"error": "Solo el administrador puede parametrizar"})

    updated = db.update_settings(payload.session_timeout_seconds, payload.max_failed_attempts)
    log_audit(ctx["version"], ctx["user"]["username"], "admin", "UPDATE_SETTINGS", json.dumps(updated))
    return record_response(response, 200, request.method, request.url.path, {"settings": updated})


@app.post("/api/admin/synthetic-data")
def generate_synthetic_data(
    payload: SyntheticDataRequest,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    if ctx["user"]["role"] != "admin":
        return record_response(response, 403, request.method, request.url.path, {"error": "Solo el administrador puede generar datos"})

    created_users = 0
    for idx in range(payload.cantidad_usuarios_extra):
        is_bad = payload.calidad == "mal_creados"
        db.create_synthetic_user(idx, malformed=is_bad)
        created_users += 1

    clients = [u for u in db.get_all_users() if u["role"] == "cliente"] or db.get_all_users()
    created_orders = 0
    for i in range(payload.cantidad_pedidos):
        owner = clients[i % len(clients)]
        if payload.calidad == "bien_creados":
            titulo = f"Pedido Sintético #{i + 1}"
            importe = round(random.uniform(25.0, 500.0), 2)
        else:
            titulo = "" if i % 2 == 0 else f"Pedido Corrupto <script>alert(1)</script> #{i + 1}"
            importe = -round(random.uniform(10.0, 200.0), 2)
        db.create_order(owner_id=owner["id"], titulo=titulo, importe=importe, estado="En proceso")
        created_orders += 1

    log_audit(
        ctx["version"],
        ctx["user"]["username"],
        "admin",
        "SYNTHETIC_DATA",
        f"calidad={payload.calidad}, usuarios={created_users}, pedidos={created_orders}",
    )
    return record_response(
        response,
        200,
        request.method,
        request.url.path,
        {"created_users": created_users, "created_orders": created_orders, "calidad": payload.calidad},
    )


@app.post("/api/admin/reset")
def reset_data(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    if ctx["user"]["role"] != "admin":
        return record_response(response, 403, request.method, request.url.path, {"error": "Solo el administrador puede reiniciar datos"})

    db.reset_all_data(seed_users=50)
    log_audit(ctx["version"], ctx["user"]["username"], "admin", "RESET_DATA", "Datos reiniciados a 50 usuarios base")
    return record_response(response, 200, request.method, request.url.path, {"message": "Datos reiniciados correctamente"})


@app.get("/api/admin/export")
def export_data(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    if ctx["user"]["role"] != "admin":
        return record_response(response, 403, request.method, request.url.path, {"error": "Solo el administrador puede exportar datos"})

    snapshot = db.export_snapshot()
    log_audit(ctx["version"], ctx["user"]["username"], "admin", "EXPORT_DATA", "Exportación de snapshot JSON")
    return record_response(response, 200, request.method, request.url.path, {"snapshot": snapshot})


@app.post("/api/admin/import")
def import_data(
    payload: ImportDataRequest,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
):
    ctx = require_session(request, response, x_session_token, x_lab_version)
    if ctx["user"]["role"] != "admin":
        return record_response(response, 403, request.method, request.url.path, {"error": "Solo el administrador puede importar datos"})

    snapshot_data = payload.payload.get("snapshot", payload.payload)
    db.import_snapshot(snapshot_data)
    log_audit(ctx["version"], ctx["user"]["username"], "admin", "IMPORT_DATA", "Importación de snapshot JSON")
    return record_response(response, 200, request.method, request.url.path, {"message": "Datos cargados correctamente"})

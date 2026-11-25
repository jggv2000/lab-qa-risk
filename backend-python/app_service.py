from __future__ import annotations

import json
import random
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from database import DatabaseManager
from version_switches import (
    DEFAULT_VERSION,
    VERSION_CONFIG,
    get_version_profile,
    is_flag_enabled,
)

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
    "body": {"status": "ok", "default_version": DEFAULT_VERSION},
}


# --- Modelos de entrada ---
class LoginRequest(BaseModel):
    usuario: str
    password: str


class ProfileUpdateRequest(BaseModel):
    correo: str
    ciudad: str
    telefono: str
    acepta_rgpd: bool = False


class OrderCreateRequest(BaseModel):
    titulo: str
    importe: float
    cliente_id: Optional[int] = None


class OrderStatusRequest(BaseModel):
    nuevo_estado: str


class AdminSettingsRequest(BaseModel):
    session_timeout_seconds: int = Field(ge=5, le=3600)
    max_failed_attempts: int = Field(ge=1, le=20)


class SyntheticDataRequest(BaseModel):
    cantidad_pedidos: int = Field(default=20, ge=1, le=500)
    cantidad_usuarios_extra: int = Field(default=0, ge=0, le=100)
    calidad: str = Field(pattern="^(bien_creados|mal_creados)$")


class ImportSnapshotRequest(BaseModel):
    snapshot: Dict[str, Any]


# --- Utilidades de versión, respuesta HTTP+JSON y trazabilidad ---
def resolve_version(x_lab_version: Optional[str]) -> str:
    if x_lab_version and x_lab_version in VERSION_CONFIG:
        return x_lab_version
    return db.get_active_version() or DEFAULT_VERSION


def record_http_json(
    response: Response,
    status_code: int,
    method: str,
    path: str,
    body: Any,
) -> Any:
    global LAST_API_RESPONSE
    response.status_code = status_code
    LAST_API_RESPONSE = {
        "status_code": status_code,
        "method": method,
        "path": path,
        "body": body,
    }
    return body


def raise_recorded_http(
    request: Request,
    response: Response,
    status_code: int,
    body: Any,
) -> None:
    recorded = record_http_json(response, status_code, request.method, request.url.path, body)
    raise HTTPException(status_code=status_code, detail=recorded)


def write_trace(version: str, actor: str, role: str, action: str, detail: str) -> None:
    if is_flag_enabled(version, "skip_traceability"):
        return
    db.add_trace(actor=actor, role=role, action=action, detail=f"[{version}] {detail}")


def get_active_session_context(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = None,
    x_lab_version: Optional[str] = None,
) -> Dict[str, Any]:
    version = resolve_version(x_lab_version)
    token = x_session_token or request.headers.get("x-session-token") or request.query_params.get("token")
    if not token:
        raise_recorded_http(request, response, 401, {"error": "Sesión no iniciada"})

    session = db.get_session(token)
    if not session:
        raise_recorded_http(request, response, 401, {"error": "Sesión no válida o cerrada"})

    settings = db.get_settings()
    timeout_sec = int(settings.get("session_timeout_seconds", 60))
    elapsed = time.time() - float(session["last_activity"])

    if not is_flag_enabled(version, "session_no_timeout") and elapsed > timeout_sec:
        db.delete_session(token)
        write_trace(version, str(session["user_id"]), "session", "SESSION_EXPIRED", f"Inactividad > {timeout_sec}s")
        raise_recorded_http(request, response, 401, {"error": "La sesión ha caducado por inactividad"})

    db.touch_session(token, time.time())
    user = db.get_user_by_id(int(session["user_id"]))
    if not user:
        raise_recorded_http(request, response, 401, {"error": "Usuario de sesión no encontrado"})

    return {"user": user, "version": version, "token": token, "settings": settings}


def serialize_user(user: Dict[str, Any], version: str, include_sensitive: bool = False) -> Dict[str, Any]:
    clean = {k: v for k, v in user.items() if k != "password"}
    if include_sensitive and (
        is_flag_enabled(version, "expose_password") or is_flag_enabled(version, "pii_exposure_or_no_rgpd")
    ):
        clean["password"] = user.get("password", "")
    return clean


# --- UI estática y salud ---
@app.get("/")
def serve_index() -> FileResponse:
    return FileResponse("static/index.html")


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/api/health")
def health(request: Request, response: Response, x_lab_version: Optional[str] = Header(default=None)) -> Any:
    version = resolve_version(x_lab_version)
    return record_http_json(
        response,
        200,
        request.method,
        request.url.path,
        {"status": "ok", "active_version": version},
    )


@app.get("/api/last-response")
def get_last_response(request: Request, response: Response) -> Any:
    return record_http_json(response, 200, request.method, request.url.path, LAST_API_RESPONSE)


# --- Selector de versión (v3.1 a v3.5) ---
@app.get("/api/version")
def get_version(
    request: Request,
    response: Response,
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    version = resolve_version(x_lab_version)
    profile = get_version_profile(version)
    payload = {
        "active_version": version,
        "available_versions": list(VERSION_CONFIG.keys()),
        "counts": profile["counts"],
        "total_errors": profile["total_errors"],
        "flags": profile["flags"],
    }
    return record_http_json(response, 200, request.method, request.url.path, payload)


@app.post("/api/version/{version}")
def set_version(version: str, request: Request, response: Response) -> Any:
    if version not in VERSION_CONFIG:
        return record_http_json(
            response,
            400,
            request.method,
            request.url.path,
            {"error": "Versión inválida. Valores permitidos: v3.1, v3.2, v3.3, v3.4, v3.5"},
        )
    db.set_active_version(version)
    write_trace(version, "system", "system", "SET_VERSION", f"Versión activa establecida en {version}")
    profile = get_version_profile(version)
    return record_http_json(
        response,
        200,
        request.method,
        request.url.path,
        {"active_version": version, "counts": profile["counts"], "total_errors": profile["total_errors"]},
    )


# --- Autenticación, bloqueo y cierre de sesión ---
@app.post("/api/auth/login")
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    version = resolve_version(x_lab_version)
    settings = db.get_settings()
    max_attempts = int(settings.get("max_failed_attempts", 5))
    timeout_sec = int(settings.get("session_timeout_seconds", 60))

    user = db.get_user_by_login(payload.usuario.strip())
    if not user:
        write_trace(version, payload.usuario, "anonymous", "LOGIN_FAILED", "Usuario no encontrado")
        return record_http_json(response, 401, request.method, request.url.path, {"error": "Credenciales incorrectas"})

    if bool(user.get("locked", False)):
        write_trace(version, user["username"], user["role"], "LOGIN_BLOCKED", "Usuario bloqueado por intentos fallidos")
        return record_http_json(
            response,
            403,
            request.method,
            request.url.path,
            {"error": "Usuario bloqueado. Solicite desbloqueo al administrador.", "locked": True},
        )

    valid_password = user["password"] == payload.password
    if is_flag_enabled(version, "owasp_weak_auth_input") and payload.password in ("1234", "admin", "password"):
        valid_password = True

    if not valid_password:
        attempts = int(user.get("failed_attempts", 0)) + 1
        locked = attempts >= max_attempts
        db.set_user_login_state(int(user["id"]), failed_attempts=attempts, locked=locked)
        write_trace(
            version,
            user["username"],
            user["role"],
            "LOGIN_FAILED",
            f"Intento {attempts}/{max_attempts} | locked={locked}",
        )
        return record_http_json(
            response,
            401,
            request.method,
            request.url.path,
            {
                "error": "Contraseña incorrecta",
                "failed_attempts": attempts,
                "max_failed_attempts": max_attempts,
                "locked": locked,
            },
        )

    db.set_user_login_state(int(user["id"]), failed_attempts=0, locked=False)
    token = db.create_session(int(user["id"]), time.time())
    write_trace(version, user["username"], user["role"], "LOGIN_SUCCESS", "Sesión iniciada")

    user_info = serialize_user(user, version, include_sensitive=True)
    if is_flag_enabled(version, "expose_password"):
        user_info["password_visible"] = user["password"]

    return record_http_json(
        response,
        200,
        request.method,
        request.url.path,
        {
            "token": token,
            "user": user_info,
            "session_timeout_seconds": timeout_sec,
            "max_failed_attempts": max_attempts,
        },
    )


@app.post("/api/auth/logout")
def logout(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    db.delete_session(ctx["token"])
    write_trace(ctx["version"], ctx["user"]["username"], ctx["user"]["role"], "LOGOUT", "Sesión cerrada")
    return record_http_json(response, 200, request.method, request.url.path, {"message": "Sesión cerrada correctamente"})


# --- Perfil de usuario, RGPD, listado de usuarios y desbloqueo ---
@app.get("/api/users/me")
def get_me(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    return record_http_json(
        response,
        200,
        request.method,
        request.url.path,
        {"user": serialize_user(ctx["user"], ctx["version"], include_sensitive=True)},
    )


@app.put("/api/users/me")
def update_me(
    payload: ProfileUpdateRequest,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    if user["role"] == "viewer" and not is_flag_enabled(version, "viewer_can_modify"):
        return record_http_json(
            response,
            403,
            request.method,
            request.url.path,
            {"error": "El rol viewer no puede modificar datos"},
        )

    if not is_flag_enabled(version, "pii_exposure_or_no_rgpd") and not payload.acepta_rgpd:
        return record_http_json(
            response,
            400,
            request.method,
            request.url.path,
            {"error": "Debe aceptar la Política de Privacidad y Protección de Datos (RGPD)"},
        )

    if not is_flag_enabled(version, "weak_field_validation"):
        if "@" not in payload.correo or len(payload.ciudad.strip()) < 2 or len(payload.telefono.strip()) < 6:
            return record_http_json(
                response,
                400,
                request.method,
                request.url.path,
                {"error": "Revise correo, ciudad y teléfono antes de guardar"},
            )

    updated = db.update_user_profile(
        int(user["id"]),
        correo=payload.correo.strip(),
        ciudad=payload.ciudad.strip(),
        telefono=payload.telefono.strip(),
        acepta_rgpd=bool(payload.acepta_rgpd),
    )
    write_trace(version, user["username"], user["role"], "UPDATE_PROFILE", f"RGPD={payload.acepta_rgpd}")
    return record_http_json(
        response,
        200,
        request.method,
        request.url.path,
        {"user": serialize_user(updated, version, include_sensitive=True)},
    )


@app.get("/api/users")
def list_users(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    if user["role"] != "admin" and not is_flag_enabled(version, "broken_rbac_escalation"):
        write_trace(version, user["username"], user["role"], "FORBIDDEN", "Intento de ver todos los usuarios")
        return record_http_json(
            response,
            403,
            request.method,
            request.url.path,
            {"error": "Solo el administrador puede ver los datos de todos los usuarios"},
        )

    users = [serialize_user(u, version, include_sensitive=True) for u in db.get_all_users()]
    write_trace(version, user["username"], user["role"], "LIST_USERS", f"Total usuarios: {len(users)}")
    return record_http_json(response, 200, request.method, request.url.path, {"users": users})


@app.post("/api/users/{target_user_id}/unlock")
def unlock_user(
    target_user_id: int,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    if user["role"] != "admin" and not is_flag_enabled(version, "broken_rbac_escalation"):
        write_trace(version, user["username"], user["role"], "FORBIDDEN", f"Intento de desbloquear ID {target_user_id}")
        return record_http_json(
            response,
            403,
            request.method,
            request.url.path,
            {"error": "Solo el usuario administrador puede desbloquear usuarios"},
        )

    unlocked = db.unlock_user(target_user_id)
    if not unlocked:
        return record_http_json(response, 404, request.method, request.url.path, {"error": "Usuario no encontrado"})

    write_trace(version, user["username"], user["role"], "UNLOCK_USER", f"Usuario #{target_user_id} desbloqueado")
    return record_http_json(
        response,
        200,
        request.method,
        request.url.path,
        {"message": "Usuario desbloqueado", "user": serialize_user(unlocked, version, include_sensitive=True)},
    )


# --- Pedidos y flujo de estados ---
@app.get("/api/orders")
def list_orders(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    if user["role"] in ("viewer", "admin"):
        orders = db.get_all_orders()
    else:
        orders = db.get_orders_by_owner(int(user["id"]))

    write_trace(version, user["username"], user["role"], "LIST_ORDERS", f"Devueltos {len(orders)} pedidos")
    return record_http_json(response, 200, request.method, request.url.path, {"orders": orders})


@app.get("/api/orders/{order_id}")
def get_order(
    order_id: int,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    order = db.get_order_by_id(order_id)
    if not order:
        return record_http_json(response, 404, request.method, request.url.path, {"error": "Pedido no encontrado"})

    if user["role"] == "cliente" and int(order["owner_id"]) != int(user["id"]) and not is_flag_enabled(version, "idor"):
        return record_http_json(response, 403, request.method, request.url.path, {"error": "Acceso denegado a pedido ajeno"})

    return record_http_json(response, 200, request.method, request.url.path, {"order": order})


@app.post("/api/orders")
def create_order(
    payload: OrderCreateRequest,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    if user["role"] == "viewer" and not is_flag_enabled(version, "viewer_can_modify"):
        return record_http_json(response, 403, request.method, request.url.path, {"error": "El rol viewer no puede crear pedidos"})

    if not is_flag_enabled(version, "weak_field_validation"):
        if not payload.titulo.strip() or payload.importe <= 0:
            return record_http_json(
                response,
                400,
                request.method,
                request.url.path,
                {"error": "El título es obligatorio y el importe debe ser mayor que 0"},
            )

    owner_id = int(payload.cliente_id) if (user["role"] == "admin" and payload.cliente_id) else int(user["id"])
    order = db.create_order(owner_id=owner_id, titulo=payload.titulo.strip(), importe=float(payload.importe), estado="En proceso")
    write_trace(version, user["username"], user["role"], "CREATE_ORDER", f"Pedido #{order['id']} creado (En proceso)")
    return record_http_json(response, 201, request.method, request.url.path, {"order": order})


@app.patch("/api/orders/{order_id}/status")
def update_order_status(
    order_id: int,
    payload: OrderStatusRequest,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]
    role = user["role"]
    target = payload.nuevo_estado.strip()

    if role == "viewer" and not is_flag_enabled(version, "viewer_can_modify"):
        return record_http_json(response, 403, request.method, request.url.path, {"error": "El rol viewer no puede modificar pedidos"})

    order = db.get_order_by_id(order_id)
    if not order:
        return record_http_json(response, 404, request.method, request.url.path, {"error": "Pedido no encontrado"})

    if role == "cliente" and int(order["owner_id"]) != int(user["id"]) and not is_flag_enabled(version, "idor"):
        return record_http_json(response, 403, request.method, request.url.path, {"error": "No puede modificar pedidos de otro usuario"})

    current = order["estado"]
    if not is_flag_enabled(version, "broken_order_workflow"):
        if role == "cliente":
            if current == "Aprobado" and target == "Rechazado":
                return record_http_json(
                    response,
                    400,
                    request.method,
                    request.url.path,
                    {"error": "Si el pedido está Aprobado, el cliente ya no puede rechazarlo"},
                )
            if not (current in ("Creado", "En proceso") and target == "Eliminado"):
                return record_http_json(
                    response,
                    403,
                    request.method,
                    request.url.path,
                    {"error": "El cliente solo puede eliminar un pedido creado/en proceso mientras no esté aprobado"},
                )
        elif role == "admin":
            if current in ("Creado", "En proceso") and target not in {"Aprobado", "Rechazado", "Eliminado"}:
                return record_http_json(response, 400, request.method, request.url.path, {"error": "Transición no válida"})
            if current == "Aprobado" and target not in {"Rechazado", "Eliminado", "Entregado"}:
                return record_http_json(response, 400, request.method, request.url.path, {"error": "Transición no válida desde Aprobado"})
            if current not in ("Creado", "En proceso", "Aprobado") and target not in {"Eliminado"}:
                return record_http_json(response, 400, request.method, request.url.path, {"error": "Estado actual no admite esa transición"})

    updated = db.update_order_status(order_id, target)
    write_trace(version, user["username"], role, "ORDER_STATUS", f"Pedido #{order_id}: {current} -> {target}")
    return record_http_json(response, 200, request.method, request.url.path, {"order": updated})


@app.delete("/api/orders/{order_id}")
def delete_order(
    order_id: int,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    if user["role"] == "viewer" and not is_flag_enabled(version, "viewer_can_modify"):
        return record_http_json(response, 403, request.method, request.url.path, {"error": "El rol viewer no puede eliminar pedidos"})

    order = db.get_order_by_id(order_id)
    if not order:
        return record_http_json(response, 404, request.method, request.url.path, {"error": "Pedido no encontrado"})

    if user["role"] == "cliente" and int(order["owner_id"]) != int(user["id"]) and not is_flag_enabled(version, "idor"):
        return record_http_json(response, 403, request.method, request.url.path, {"error": "No puede eliminar pedidos de otro usuario"})

    db.delete_order(order_id)
    write_trace(version, user["username"], user["role"], "DELETE_ORDER", f"Pedido #{order_id} eliminado")
    return record_http_json(response, 200, request.method, request.url.path, {"deleted_order_id": order_id})


# --- Trazabilidad y prueba de rendimiento ---
@app.get("/api/traceability")
def list_traceability(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    traces = db.get_traces()
    return record_http_json(response, 200, request.method, request.url.path, {"traces": traces})


@app.post("/api/performance/check")
def performance_check(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    version = ctx["version"]
    sleep_sec = 6.0 if is_flag_enabled(version, "slow_hanging_button") else 0.15
    time.sleep(sleep_sec)
    write_trace(version, ctx["user"]["username"], ctx["user"]["role"], "PERF_CHECK", f"Duración {sleep_sec}s")
    return record_http_json(
        response,
        200,
        request.method,
        request.url.path,
        {"status": "ok", "elapsed_seconds": sleep_sec, "hanging_simulated": is_flag_enabled(version, "slow_hanging_button")},
    )


# --- Administración: tablas, parámetros, datos sintéticos, reinicio, exportar/importar ---
@app.get("/api/admin/tables")
def admin_tables(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    user = ctx["user"]
    version = ctx["version"]

    if user["role"] != "admin" and not is_flag_enabled(version, "broken_rbac_escalation"):
        return record_http_json(response, 403, request.method, request.url.path, {"error": "Acceso exclusivo para administrador"})

    payload = {
        "usuarios": [serialize_user(u, version, include_sensitive=True) for u in db.get_all_users()],
        "pedidos": db.get_all_orders(),
        "trazabilidad": db.get_traces(),
        "settings": db.get_settings(),
    }
    return record_http_json(response, 200, request.method, request.url.path, payload)


@app.put("/api/admin/settings")
def update_settings(
    payload: AdminSettingsRequest,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    if ctx["user"]["role"] != "admin":
        return record_http_json(response, 403, request.method, request.url.path, {"error": "Solo el administrador puede cambiar parámetros"})

    updated = db.update_settings(
        session_timeout_seconds=payload.session_timeout_seconds,
        max_failed_attempts=payload.max_failed_attempts,
    )
    write_trace(ctx["version"], ctx["user"]["username"], "admin", "UPDATE_SETTINGS", json.dumps(updated))
    return record_http_json(response, 200, request.method, request.url.path, {"settings": updated})


@app.post("/api/admin/synthetic-data")
def synthetic_data(
    payload: SyntheticDataRequest,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    if ctx["user"]["role"] != "admin":
        return record_http_json(response, 403, request.method, request.url.path, {"error": "Solo el administrador puede generar datos sintéticos"})

    malformed = payload.calidad == "mal_creados"
    extra_users = 0
    for idx in range(payload.cantidad_usuarios_extra):
        db.create_synthetic_user(idx=idx, malformed=malformed)
        extra_users += 1

    all_users = db.get_all_users()
    pool = [u for u in all_users if u["role"] == "cliente"] or all_users
    created_orders = 0
    for i in range(payload.cantidad_pedidos):
        owner = pool[i % len(pool)]
        if malformed:
            titulo = "" if i % 2 == 0 else f"Pedido Inválido #{i + 1}"
            importe = -round(random.uniform(5.0, 250.0), 2)
        else:
            titulo = f"Pedido Sintético #{i + 1}"
            importe = round(random.uniform(20.0, 450.0), 2)
        db.create_order(owner_id=int(owner["id"]), titulo=titulo, importe=importe, estado="En proceso")
        created_orders += 1

    write_trace(
        ctx["version"],
        ctx["user"]["username"],
        "admin",
        "SYNTHETIC_DATA",
        f"calidad={payload.calidad}, usuarios={extra_users}, pedidos={created_orders}",
    )
    return record_http_json(
        response,
        200,
        request.method,
        request.url.path,
        {"created_users": extra_users, "created_orders": created_orders, "calidad": payload.calidad},
    )


@app.post("/api/admin/reset")
def reset_data(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    if ctx["user"]["role"] != "admin":
        return record_http_json(response, 403, request.method, request.url.path, {"error": "Solo el administrador puede reiniciar los datos"})

    db.reset_all_data(seed_users=50)
    write_trace(ctx["version"], ctx["user"]["username"], "admin", "RESET_DATA", "Datos reiniciados a 50 usuarios")
    return record_http_json(response, 200, request.method, request.url.path, {"message": "Datos reiniciados correctamente"})


@app.get("/api/admin/export")
def export_data(
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    if ctx["user"]["role"] != "admin":
        return record_http_json(response, 403, request.method, request.url.path, {"error": "Solo el administrador puede guardar/exportar los datos"})

    snapshot = db.export_snapshot()
    write_trace(ctx["version"], ctx["user"]["username"], "admin", "EXPORT_DATA", "Fichero/snapshot de datos generado")
    return record_http_json(response, 200, request.method, request.url.path, {"snapshot": snapshot})


@app.post("/api/admin/import")
def import_data(
    payload: ImportSnapshotRequest,
    request: Request,
    response: Response,
    x_session_token: Optional[str] = Header(default=None),
    x_lab_version: Optional[str] = Header(default=None),
) -> Any:
    ctx = get_active_session_context(request, response, x_session_token, x_lab_version)
    if ctx["user"]["role"] != "admin":
        return record_http_json(response, 403, request.method, request.url.path, {"error": "Solo el administrador puede cargar datos"})

    db.import_snapshot(payload.snapshot)
    write_trace(ctx["version"], ctx["user"]["username"], "admin", "IMPORT_DATA", "Datos cargados desde fichero")
    return record_http_json(response, 200, request.method, request.url.path, {"message": "Datos cargados correctamente"})

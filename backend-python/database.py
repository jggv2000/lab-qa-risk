from __future__ import annotations

import copy
import json
import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from version_switches import DEFAULT_VERSION, VERSION_CONFIG

CITIES = [
    "Madrid",
    "Barcelona",
    "Valencia",
    "Sevilla",
    "Bilbao",
    "Zaragoza",
    "Málaga",
    "Granada",
]


class DatabaseManager:
    def __init__(self, db_path: str = "lab_qa_risk.db") -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()
        self._ensure_seeded()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin', 'cliente', 'viewer')),
                    city TEXT NOT NULL,
                    phone TEXT NOT NULL,
                    rgpd_accepted INTEGER NOT NULL DEFAULT 1,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    last_activity REAL NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    amount REAL NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS traceability (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS app_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            conn.commit()

    def _ensure_seeded(self) -> None:
        with self._lock, self._connect() as conn:
            count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
            if count == 0:
                self._seed_data_locked(conn, total_users=50)
                conn.commit()

    def _seed_data_locked(self, conn: sqlite3.Connection, total_users: int = 50) -> None:
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM orders")
        conn.execute("DELETE FROM traceability")
        conn.execute("DELETE FROM users")
        conn.execute("DELETE FROM app_meta")

        # Usuario 1: administrador principal solicitado
        users_to_insert = [
            (
                "instructor",
                "instructor@lab.local",
                "CleanMode2026!",
                "admin",
                "Madrid",
                "+34 600 100 001",
                1,
                0,
                0,
            )
        ]

        # Completar hasta 50 usuarios (distribuidos en admin, cliente y viewer)
        for idx in range(2, max(total_users, 2) + 1):
            if idx <= 5:
                role = "admin"
            elif idx <= 35:
                role = "cliente"
            else:
                role = "viewer"

            username = f"usuario{idx:02d}"
            email = f"usuario{idx:02d}@lab.local"
            password = f"LabPass{idx:02d}!"
            city = CITIES[(idx - 1) % len(CITIES)]
            phone = f"+34 610 {idx:03d} {100 + idx:03d}"
            rgpd = 1 if idx % 5 != 0 else 0
            users_to_insert.append((username, email, password, role, city, phone, rgpd, 0, 0))

        conn.executemany(
            """
            INSERT INTO users (username, email, password, role, city, phone, rgpd_accepted, failed_attempts, locked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            users_to_insert,
        )

        # Pedidos iniciales de ejemplo en 'En proceso' para clientes
        client_rows = conn.execute("SELECT id FROM users WHERE role = 'cliente' ORDER BY id LIMIT 6").fetchall()
        now_ts = time.time()
        for i, row in enumerate(client_rows, start=1):
            conn.execute(
                "INSERT INTO orders (owner_id, title, amount, status, created_at) VALUES (?, ?, ?, ?, ?)",
                (row["id"], f"Pedido Inicial #{i}", round(50.0 * i, 2), "En proceso", now_ts - (100 * i)),
            )

        settings = {"session_timeout_seconds": 60, "max_failed_attempts": 5}
        conn.execute("INSERT INTO app_meta (key, value) VALUES (?, ?)", ("settings", json.dumps(settings)))
        conn.execute("INSERT INTO app_meta (key, value) VALUES (?, ?)", ("active_version", DEFAULT_VERSION))

        conn.execute(
            "INSERT INTO traceability (timestamp, actor, role, action, detail) VALUES (?, ?, ?, ?, ?)",
            (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "system",
                "system",
                "SEED_INIT",
                f"Inicializados {len(users_to_insert)} usuarios y datos base",
            ),
        )

    def reset_all_data(self, seed_users: int = 50) -> None:
        with self._lock, self._connect() as conn:
            self._seed_data_locked(conn, total_users=seed_users)
            conn.commit()

    # --- Versión activa y parámetros ---
    def get_active_version(self) -> str:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT value FROM app_meta WHERE key = 'active_version'").fetchone()
            if row and row["value"] in VERSION_CONFIG:
                return str(row["value"])
            return DEFAULT_VERSION

    def set_active_version(self, version: str) -> None:
        if version not in VERSION_CONFIG:
            return
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO app_meta (key, value) VALUES ('active_version', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (version,),
            )
            conn.commit()

    def get_settings(self) -> Dict[str, int]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT value FROM app_meta WHERE key = 'settings'").fetchone()
            if not row:
                return {"session_timeout_seconds": 60, "max_failed_attempts": 5}
            data = json.loads(row["value"])
            return {
                "session_timeout_seconds": int(data.get("session_timeout_seconds", 60)),
                "max_failed_attempts": int(data.get("max_failed_attempts", 5)),
            }

    def update_settings(self, session_timeout_seconds: int, max_failed_attempts: int) -> Dict[str, int]:
        updated = {
            "session_timeout_seconds": int(session_timeout_seconds),
            "max_failed_attempts": int(max_failed_attempts),
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO app_meta (key, value) VALUES ('settings', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (json.dumps(updated),),
            )
            conn.commit()
        return updated

    # --- Usuarios y sesiones ---
    @staticmethod
    def _row_to_user(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if not row:
            return None
        return {
            "id": int(row["id"]),
            "username": row["username"],
            "email": row["email"],
            "password": row["password"],
            "role": row["role"],
            "city": row["city"],
            "phone": row["phone"],
            "rgpd_accepted": bool(row["rgpd_accepted"]),
            "failed_attempts": int(row["failed_attempts"]),
            "locked": bool(row["locked"]),
        }

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return self._row_to_user(row)

    def get_user_by_login(self, identifier: str) -> Optional[Dict[str, Any]]:
        clean = identifier.strip().lower()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE lower(username) = ? OR lower(email) = ?",
                (clean, clean),
            ).fetchone()
            return self._row_to_user(row)

    def get_all_users(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY id ASC").fetchall()
            return [self._row_to_user(r) for r in rows if r is not None]

    def set_user_login_state(self, user_id: int, failed_attempts: int, locked: bool) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked = ? WHERE id = ?",
                (int(failed_attempts), 1 if locked else 0, user_id),
            )
            conn.commit()

    def unlock_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked = 0 WHERE id = ?",
                (user_id,),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return self._row_to_user(row)

    def update_user_profile(
        self,
        user_id: int,
        correo: str,
        ciudad: str,
        telefono: str,
        acepta_rgpd: bool,
    ) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE users SET email = ?, city = ?, phone = ?, rgpd_accepted = ? WHERE id = ?",
                (correo, ciudad, telefono, 1 if acepta_rgpd else 0, user_id),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return self._row_to_user(row)

    def create_synthetic_user(self, idx: int, malformed: bool = False) -> Dict[str, Any]:
        suffix = f"{int(time.time())}_{idx}_{uuid.uuid4().hex[:4]}"
        with self._lock, self._connect() as conn:
            if malformed:
                username = f"bad_user_{suffix}"
                email = f"sin_arroba_{suffix}"
                password = "123"
                role = "cliente"
                city = ""
                phone = "00"
                rgpd = 0
            else:
                username = f"sint_cliente_{suffix}"
                email = f"{username}@lab.local"
                password = f"SynthPass_{idx + 1}!"
                role = "cliente"
                city = CITIES[idx % len(CITIES)]
                phone = f"+34 620 {idx % 900 + 100:03d} {idx % 900 + 100:03d}"
                rgpd = 1

            cur = conn.execute(
                """
                INSERT INTO users (username, email, password, role, city, phone, rgpd_accepted, failed_attempts, locked)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)
                """,
                (username, email, password, role, city, phone, rgpd),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
            return self._row_to_user(row)  # type: ignore[return-value]

    def create_session(self, user_id: int, now_ts: float) -> str:
        token = uuid.uuid4().hex
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO sessions (token, user_id, last_activity) VALUES (?, ?, ?)",
                (token, user_id, now_ts),
            )
            conn.commit()
        return token

    def get_session(self, token: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
            if not row:
                return None
            return {
                "token": row["token"],
                "user_id": int(row["user_id"]),
                "last_activity": float(row["last_activity"]),
            }

    def touch_session(self, token: str, now_ts: float) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("UPDATE sessions SET last_activity = ? WHERE token = ?", (now_ts, token))
            conn.commit()

    def delete_session(self, token: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()

    # --- Pedidos ---
    @staticmethod
    def _row_to_order(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": int(row["id"]),
            "owner_id": int(row["owner_id"]),
            "titulo": row["title"],
            "importe": float(row["amount"]),
            "estado": row["status"],
            "created_at": float(row["created_at"]),
        }

    def get_all_orders(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM orders ORDER BY id DESC").fetchall()
            return [self._row_to_order(r) for r in rows]

    def get_orders_by_owner(self, owner_id: int) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM orders WHERE owner_id = ? ORDER BY id DESC",
                (owner_id,),
            ).fetchall()
            return [self._row_to_order(r) for r in rows]

    def get_order_by_id(self, order_id: int) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
            return self._row_to_order(row) if row else None

    def create_order(self, owner_id: int, titulo: str, importe: float, estado: str = "En proceso") -> Dict[str, Any]:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO orders (owner_id, title, amount, status, created_at) VALUES (?, ?, ?, ?, ?)",
                (owner_id, titulo, importe, estado, time.time()),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM orders WHERE id = ?", (cur.lastrowid,)).fetchone()
            return self._row_to_order(row)

    def update_order_status(self, order_id: int, nuevo_estado: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            conn.execute("UPDATE orders SET status = ? WHERE id = ?", (nuevo_estado, order_id))
            conn.commit()
            row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
            return self._row_to_order(row) if row else None

    def delete_order(self, order_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
            conn.commit()

    # --- Trazabilidad ---
    def add_trace(self, actor: str, role: str, action: str, detail: str) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO traceability (timestamp, actor, role, action, detail) VALUES (?, ?, ?, ?, ?)",
                (ts, actor, role, action, detail),
            )
            conn.commit()

    def get_traces(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM traceability ORDER BY id DESC").fetchall()
            return [
                {
                    "id": int(r["id"]),
                    "timestamp": r["timestamp"],
                    "actor": r["actor"],
                    "role": r["role"],
                    "action": r["action"],
                    "detail": r["detail"],
                }
                for r in rows
            ]

    # --- Exportar / importar snapshot ---
    def export_snapshot(self) -> Dict[str, Any]:
        with self._lock, self._connect() as conn:
            users = [dict(r) for r in conn.execute("SELECT * FROM users ORDER BY id ASC").fetchall()]
            orders = [dict(r) for r in conn.execute("SELECT * FROM orders ORDER BY id ASC").fetchall()]
            traces = [dict(r) for r in conn.execute("SELECT * FROM traceability ORDER BY id ASC").fetchall()]
            return {
                "exported_at": time.time(),
                "active_version": self.get_active_version(),
                "settings": self.get_settings(),
                "users": users,
                "orders": orders,
                "traceability": traces,
            }

    def import_snapshot(self, snapshot: Dict[str, Any]) -> None:
        users = snapshot.get("users", [])
        orders = snapshot.get("orders", [])
        traces = snapshot.get("traceability", [])
        settings = snapshot.get("settings", {"session_timeout_seconds": 60, "max_failed_attempts": 5})
        version = snapshot.get("active_version", DEFAULT_VERSION)

        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM sessions")
            conn.execute("DELETE FROM orders")
            conn.execute("DELETE FROM traceability")
            conn.execute("DELETE FROM users")

            for u in users:
                conn.execute(
                    """
                    INSERT INTO users (id, username, email, password, role, city, phone, rgpd_accepted, failed_attempts, locked)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        u.get("id"),
                        u["username"],
                        u["email"],
                        u["password"],
                        u["role"],
                        u.get("city", "Madrid"),
                        u.get("phone", "+34 600 000 000"),
                        1 if u.get("rgpd_accepted", True) else 0,
                        int(u.get("failed_attempts", 0)),
                        1 if u.get("locked", False) else 0,
                    ),
                )

            for o in orders:
                conn.execute(
                    "INSERT INTO orders (id, owner_id, title, amount, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        o.get("id"),
                        int(o["owner_id"]),
                        o.get("title", o.get("titulo", "Pedido")),
                        float(o.get("amount", o.get("importe", 0.0))),
                        o.get("status", o.get("estado", "En proceso")),
                        float(o.get("created_at", time.time())),
                    ),
                )

            for t in traces:
                conn.execute(
                    "INSERT INTO traceability (id, timestamp, actor, role, action, detail) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        t.get("id"),
                        t.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
                        t.get("actor", "system"),
                        t.get("role", "system"),
                        t.get("action", "IMPORT"),
                        t.get("detail", ""),
                    ),
                )

            if version in VERSION_CONFIG:
                conn.execute(
                    """
                    INSERT INTO app_meta (key, value) VALUES ('active_version', ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (version,),
                )

            conn.execute(
                """
                INSERT INTO app_meta (key, value) VALUES ('settings', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (json.dumps(settings),),
            )
            conn.commit()

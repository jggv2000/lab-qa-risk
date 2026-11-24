import sqlite3

# Usuarios iniciales del laboratorio (7 cuentas): 1 viewer, 5 clientes y 1 administrador
SEED_USERS = [
    ("viewer@ejemplo.com", "Viewer123!", "viewer"),         # Solo lectura global de pedidos
    ("cliente1@ejemplo.com", "Cliente123!", "customer"), # Crea pedidos y solo ve los suyos
    ("cliente2@ejemplo.com", "Cliente123!", "customer"), # Sirve para probar aislamiento entre clientes
    ("cliente3@ejemplo.com", "Cliente123!", "customer"),
    ("cliente4@ejemplo.com", "Cliente123!", "customer"),
    ("cliente5@ejemplo.com", "Cliente123!", "customer"),
    ("admin@ejemplo.com", "Admin123!", "admin"),         # Ve todo, cambia estados y elimina pedidos
]


def init_db(db_path: str = "lab_orders.db") -> sqlite3.Connection:
    # Abre conexión a SQLite; check_same_thread=False permite reutilizar en entorno de pruebas/API
    conn = sqlite3.connect(db_path, check_same_thread=False)
    # Permite acceder a columnas por nombre (ej. row["role"]) en lugar de solo por índice
    conn.row_factory = sqlite3.Row

    # Tabla de usuarios con restricción CHECK para limitar roles a viewer, customer o admin
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('viewer', 'customer', 'admin'))
        )
        """
    )

    # Tabla de pedidos con validaciones a nivel de base de datos (importe, descuento y estados permitidos)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_email TEXT NOT NULL,
            customer_email TEXT NOT NULL,
            amount REAL NOT NULL CHECK (amount > 0),
            discount_pct REAL NOT NULL DEFAULT 0 CHECK (discount_pct >= 0 AND discount_pct <= 100),
            final_amount REAL NOT NULL CHECK (final_amount >= 0),
            status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'cancelled')),
            marketing_consent INTEGER NOT NULL DEFAULT 0,
            notes TEXT NOT NULL DEFAULT ''
        )
        """
    )

    # Inserta los usuarios semilla de forma idempotente (si ya existen, no duplica ni falla)
    for email, password, role in SEED_USERS:
        conn.execute(
            """
            INSERT OR IGNORE INTO users (email, password, role)
            VALUES (?, ?, ?)
            """,
            (email, password, role),
        )

    conn.commit()
    return conn

"""
storage/db.py
=============
Capa de persistencia de los hallazgos en SQLite (storage/findings.db).

La tabla incluye ya los campos que usara el modulo de IA en la fase siguiente
del proyecto (ai_explanation, ai_severity, reviewed), aunque de momento se
rellenan con valores por defecto.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "findings.db")


def conectar():
    return sqlite3.connect(DB_PATH)


def init_db():
    """Crea la tabla de hallazgos si no existe."""
    con = conectar()
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            tipo          TEXT NOT NULL,     -- SQLi, XSS reflejado, etc.
            url           TEXT NOT NULL,
            detalle       TEXT,              -- parametro / cabecera afectada
            evidencia     TEXT,              -- payload o prueba del hallazgo
            severidad     TEXT,              -- severidad base (prior por tipo)
            ai_explanation TEXT DEFAULT '',  -- la rellenara la IA (fase 2)
            ai_severity    TEXT DEFAULT '',  -- la rellenara la IA (fase 2)
            reviewed       INTEGER DEFAULT 0,-- 0 = pendiente de revision IA
            creado         TEXT
        )
        """
    )
    con.commit()
    con.close()


def limpiar():
    """Vacia la tabla (para escaneos repetibles)."""
    con = conectar()
    cur = con.cursor()
    cur.execute("DELETE FROM findings")
    con.commit()
    con.close()


def guardar_hallazgo(tipo, url, detalle, evidencia, severidad):
    """Inserta un hallazgo. Evita duplicados exactos (mismo tipo+url+detalle)."""
    con = conectar()
    cur = con.cursor()
    cur.execute(
        "SELECT 1 FROM findings WHERE tipo=? AND url=? AND detalle=?",
        (tipo, url, detalle),
    )
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO findings (tipo, url, detalle, evidencia, severidad, creado) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (tipo, url, detalle, evidencia, severidad, datetime.now().isoformat(timespec="seconds")),
        )
    con.commit()
    con.close()


def listar_hallazgos():
    con = conectar()
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM findings ORDER BY id")
    filas = [dict(f) for f in cur.fetchall()]
    con.close()
    return filas


def resumen_por_tipo():
    con = conectar()
    cur = con.cursor()
    cur.execute("SELECT tipo, COUNT(*) FROM findings GROUP BY tipo ORDER BY tipo")
    filas = cur.fetchall()
    con.close()
    return filas

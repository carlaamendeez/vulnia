"""
target/app.py
=============
Mini aplicacion web DELIBERADAMENTE vulnerable, construida como banco de pruebas
para el escaner de vulnerabilidades web con IA (asignatura Proyectos de
Ciberseguridad).

AVISO: este codigo es inseguro A PROPOSITO. Es un objetivo de pruebas en local;
no debe desplegarse en un entorno real ni expuesto a Internet.

Vulnerabilidades incluidas (coinciden con lo que detecta el scanner):
  1. SQL Injection en el login  -> permite bypass de autenticacion.
  2. XSS reflejado               -> en el buscador (parametro ?q=).
  3. XSS almacenado              -> en los comentarios.
  4. Cookie de sesion insegura   -> sin HttpOnly, sin Secure, sin SameSite.
  5. Cabeceras de seguridad ausentes -> sin CSP, X-Frame-Options,
     X-Content-Type-Options ni HSTS.
"""

import sqlite3
import os
from flask import Flask, request, make_response, redirect, url_for, render_template

app = Flask(__name__)

# Base de datos propia del target (usuarios de prueba). Es independiente de
# storage/findings.db, que usa el scanner para guardar hallazgos.
DB_PATH = os.path.join(os.path.dirname(__file__), "target.db")


def init_db():
    """Crea la tabla de usuarios y los usuarios de prueba si no existen."""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    cur.execute("DELETE FROM users")
    usuarios = [
        ("carla", "carla1234"),
        ("admin", "admin123"),
        ("invitado", "invitado"),
    ]
    cur.executemany("INSERT INTO users (username, password) VALUES (?, ?)", usuarios)
    con.commit()
    con.close()


# Comentarios en memoria para el XSS almacenado (se reinician al arrancar).
comentarios = []


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Login VULNERABLE a SQL Injection.

    La consulta se construye concatenando directamente la entrada del usuario,
    por lo que un payload como  ' OR '1'='1  en el usuario rompe la logica y
    permite entrar sin credenciales validas.
    """
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ---- VULNERABILIDAD: SQLi (concatenacion sin parametrizar) ----
        query = (
            "SELECT * FROM users WHERE username = '%s' AND password = '%s'"
            % (username, password)
        )
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        try:
            cur.execute(query)
            fila = cur.fetchone()
        except sqlite3.Error:
            fila = None
        con.close()

        if fila:
            # ---- VULNERABILIDAD: cookie de sesion insegura ----
            # Sin HttpOnly, sin Secure, sin SameSite -> accesible por JS y
            # expuesta a robo de sesion.
            resp = make_response(redirect(url_for("panel")))
            resp.set_cookie("session_id", "s3ssion-" + username)
            return resp
        error = "Credenciales incorrectas"
    return render_template("login.html", error=error)


@app.route("/panel")
def panel():
    usuario = request.cookies.get("session_id", "")
    if not usuario:
        return redirect(url_for("login"))
    return render_template("panel.html", usuario=usuario)


@app.route("/buscar")
def buscar():
    """
    Buscador VULNERABLE a XSS reflejado.

    El parametro q se incrusta en la respuesta sin escapar (|safe en la
    plantilla), de modo que <script>...</script> se ejecuta en el navegador.
    """
    q = request.args.get("q", "")
    return render_template("buscar.html", q=q)


@app.route("/comentarios", methods=["GET", "POST"])
def comentarios_view():
    """
    Comentarios VULNERABLES a XSS almacenado.

    Lo que se envia se guarda tal cual y se muestra sin escapar a todos los
    visitantes posteriores.
    """
    if request.method == "POST":
        texto = request.form.get("comentario", "")
        comentarios.append(texto)
        return redirect(url_for("comentarios_view"))
    return render_template("comentarios.html", comentarios=comentarios)


# ---- VULNERABILIDAD: ausencia de cabeceras de seguridad ----
# No se anaden Content-Security-Policy, X-Frame-Options,
# X-Content-Type-Options ni Strict-Transport-Security. El scanner lo detecta.


if __name__ == "__main__":
    init_db()
    # host 127.0.0.1 -> solo accesible en local.
    app.run(host="127.0.0.1", port=5000, debug=False)

"""
scanner/scanner.py
==================
Motor de deteccion. A partir de lo que descubre el crawler:

  1. SQL Injection : prueba payloads de bypass de login en los formularios.
  2. XSS           : inyecta un marcador y comprueba si vuelve sin escapar
                     (reflejado) o si queda almacenado (almacenado).
  3. Cabeceras     : comprueba la ausencia de cabeceras de seguridad por pagina.
  4. Cookies       : HACE LOGIN primero y luego revisa los flags de la cookie
                     de sesion (HttpOnly, Secure, SameSite).  <-- fix aplicado.

Cada hallazgo se guarda en storage/findings.db con una severidad base (prior
por tipo) que el modulo de IA ajustara en la fase siguiente.
"""

import sys
import os
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crawler.crawler import Crawler          # noqa: E402
from storage import db                        # noqa: E402

# Payloads de prueba.
SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1 -- "]
XSS_MARCADOR = "<script>alert('vulnia-xss')</script>"

# Cabeceras de seguridad que deberian estar presentes.
CABECERAS_SEGURIDAD = {
    "Content-Security-Policy": "Media/Alta",
    "X-Frame-Options": "Media",
    "X-Content-Type-Options": "Baja",
    "Strict-Transport-Security": "Media",
}

# Severidad base (prior) por tipo de hallazgo. La IA la revisara despues.
SEVERIDAD_BASE = {
    "SQL Injection": "Alta",
    "XSS reflejado": "Media",
    "XSS almacenado": "Alta",
    "Cookie insegura": "Media",
}

# Credenciales validas conocidas del target (para poder hacer login antes de
# revisar las cookies). En un escaner real serian parametros de configuracion.
CRED_VALIDAS = {"username": "carla", "password": "carla1234"}


class Scanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.crawler = Crawler(self.base_url)
        self.datos = None

    def ejecutar(self):
        db.init_db()
        db.limpiar()
        self.datos = self.crawler.rastrear("/")
        self.probar_sqli()
        self.probar_xss()
        self.revisar_cabeceras()
        self.revisar_cookie_sesion()   # incluye el login previo (fix)

    # ------------------------------------------------------------------ SQLi
    def probar_sqli(self):
        for form in self.datos["formularios"]:
            campos = form["campos"]
            # Un login tipico tiene usuario + contrasena.
            if not any(c in campos for c in ("username", "user", "usuario")):
                continue
            for payload in SQLI_PAYLOADS:
                datos = {c: payload for c in campos}
                sesion = requests.Session()
                try:
                    r = sesion.post(form["url"], data=datos, timeout=5,
                                    allow_redirects=True)
                except requests.RequestException:
                    continue
                # Bypass detectado si acabamos en el panel privado o si se
                # fijo una cookie de sesion sin credenciales validas.
                if "panel" in r.url.lower() or "Panel privado" in r.text \
                        or sesion.cookies.get("session_id"):
                    db.guardar_hallazgo(
                        "SQL Injection", form["url"],
                        "campo de login (payload en %s)" % ", ".join(campos),
                        "payload: %s -> bypass de autenticacion" % payload,
                        SEVERIDAD_BASE["SQL Injection"],
                    )

    # ------------------------------------------------------------------- XSS
    def probar_xss(self):
        for form in self.datos["formularios"]:
            campos = form["campos"]
            metodo = form["method"]
            for campo in campos:
                datos = {c: (XSS_MARCADOR if c == campo else "x") for c in campos}
                sesion = requests.Session()
                try:
                    if metodo == "post":
                        r = sesion.post(form["url"], data=datos, timeout=5)
                        # XSS almacenado: volvemos a pedir la pagina de origen.
                        r2 = sesion.get(form["origen"], timeout=5)
                        reflejado_en = XSS_MARCADOR in r.text
                        almacenado_en = XSS_MARCADOR in r2.text
                        if almacenado_en:
                            db.guardar_hallazgo(
                                "XSS almacenado", form["url"],
                                "campo '%s'" % campo,
                                "marcador persistido y servido sin escapar",
                                SEVERIDAD_BASE["XSS almacenado"],
                            )
                        elif reflejado_en:
                            db.guardar_hallazgo(
                                "XSS reflejado", form["url"],
                                "campo '%s'" % campo,
                                "marcador reflejado sin escapar",
                                SEVERIDAD_BASE["XSS reflejado"],
                            )
                    else:  # get
                        r = sesion.get(form["url"], params=datos, timeout=5)
                        if XSS_MARCADOR in r.text:
                            db.guardar_hallazgo(
                                "XSS reflejado", form["url"],
                                "parametro '%s'" % campo,
                                "marcador reflejado sin escapar",
                                SEVERIDAD_BASE["XSS reflejado"],
                            )
                except requests.RequestException:
                    continue

    # ------------------------------------------------------------- Cabeceras
    def revisar_cabeceras(self):
        for url in self.datos["paginas"]:
            try:
                r = requests.get(url, timeout=5)
            except requests.RequestException:
                continue
            for cabecera, sev in CABECERAS_SEGURIDAD.items():
                if cabecera not in r.headers:
                    db.guardar_hallazgo(
                        "Cabecera de seguridad ausente", url,
                        cabecera, "la respuesta no incluye %s" % cabecera, sev,
                    )

    # --------------------------------------------------------------- Cookies
    def revisar_cookie_sesion(self):
        """
        Fix de la cookie insegura: ANTES se revisaban las cookies sin iniciar
        sesion, por lo que la cookie de sesion nunca llegaba a existir y el
        hallazgo no se disparaba. Ahora hacemos login primero y despues
        inspeccionamos los flags de la cookie que fija la aplicacion.
        """
        sesion = requests.Session()
        url_login = self.base_url + "/login"
        try:
            sesion.post(url_login, data=CRED_VALIDAS, timeout=5)
        except requests.RequestException:
            return

        for cookie in sesion.cookies:
            if cookie.name != "session_id":
                continue
            problemas = []
            # HttpOnly y SameSite viajan en atributos no estandar de http.cookiejar.
            httponly = cookie.has_nonstandard_attr("HttpOnly") or \
                cookie.has_nonstandard_attr("httponly")
            samesite = cookie.has_nonstandard_attr("SameSite") or \
                cookie.has_nonstandard_attr("samesite")
            if not cookie.secure:
                problemas.append("sin Secure")
            if not httponly:
                problemas.append("sin HttpOnly")
            if not samesite:
                problemas.append("sin SameSite")
            if problemas:
                db.guardar_hallazgo(
                    "Cookie insegura", url_login,
                    "cookie 'session_id'",
                    "flags ausentes: " + ", ".join(problemas),
                    SEVERIDAD_BASE["Cookie insegura"],
                )


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
    s = Scanner(base)
    s.ejecutar()

    print("\n=== RESULTADO DEL ESCANEO ===")
    for tipo, n in db.resumen_por_tipo():
        print("  %-30s %d" % (tipo, n))
    total = len(db.listar_hallazgos())
    print("  %-30s %d" % ("TOTAL", total))

    print("\n=== DETALLE ===")
    for h in db.listar_hallazgos():
        print("  [#%d] %s | %s | %s | sev=%s"
              % (h["id"], h["tipo"], h["url"], h["detalle"], h["severidad"]))

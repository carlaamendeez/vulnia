"""
crawler/crawler.py
==================
Rastreador sencillo de la web objetivo. A partir de una URL inicial:

  - Descubre paginas siguiendo los enlaces internos (mismo dominio).
  - Extrae los formularios de cada pagina (action, method y campos).
  - Recoge las cookies que la aplicacion va fijando.

Usa unicamente requests + BeautifulSoup. El resultado es un diccionario que el
scanner consume despues para saber que probar y donde.
"""

from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup


class Crawler:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.dominio = urlparse(self.base_url).netloc
        # Sesion compartida: acumula cookies segun navega.
        self.session = requests.Session()
        self.paginas = set()          # URLs visitadas
        self.formularios = []         # lista de dicts con los formularios
        self.cookies = {}             # cookies observadas (nombre -> valor)

    def es_interno(self, url):
        """True si la URL pertenece al mismo dominio que la web objetivo."""
        return urlparse(url).netloc in ("", self.dominio)

    def rastrear(self, ruta_inicial="/"):
        """Recorre la web en anchura a partir de la ruta inicial."""
        por_visitar = [urljoin(self.base_url + "/", ruta_inicial)]

        while por_visitar:
            url = por_visitar.pop(0)
            if url in self.paginas:
                continue
            try:
                resp = self.session.get(url, timeout=5)
            except requests.RequestException:
                continue

            self.paginas.add(url)
            self._guardar_cookies(resp)

            soup = BeautifulSoup(resp.text, "html.parser")

            # Formularios de esta pagina.
            for form in soup.find_all("form"):
                self.formularios.append(self._parsear_formulario(form, url))

            # Enlaces internos nuevos.
            for a in soup.find_all("a", href=True):
                destino = urljoin(url, a["href"])
                if self.es_interno(destino) and destino not in self.paginas:
                    por_visitar.append(destino)

        return {
            "paginas": sorted(self.paginas),
            "formularios": self.formularios,
            "cookies": self.cookies,
        }

    def _parsear_formulario(self, form, url_origen):
        """Extrae action, method y campos de un formulario."""
        action = form.get("action") or url_origen
        metodo = (form.get("method") or "get").lower()
        campos = []
        for inp in form.find_all(["input", "textarea", "select"]):
            nombre = inp.get("name")
            if nombre:
                campos.append(nombre)
        return {
            "url": urljoin(url_origen, action),
            "method": metodo,
            "campos": campos,
            "origen": url_origen,
        }

    def _guardar_cookies(self, resp):
        for nombre, valor in resp.cookies.items():
            self.cookies[nombre] = valor


if __name__ == "__main__":
    # Prueba manual del crawler.
    c = Crawler("http://127.0.0.1:5000")
    datos = c.rastrear("/")
    print("Paginas descubiertas:")
    for p in datos["paginas"]:
        print("  ", p)
    print("\nFormularios descubiertos:")
    for f in datos["formularios"]:
        print("  ", f)
    print("\nCookies observadas:", datos["cookies"])

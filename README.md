# Escáner de vulnerabilidades web con IA (VulnIA)

Proyecto de la asignatura **Proyectos de Ciberseguridad** (U-TAD, 4º de Ingeniería
de Software, mención ciberseguridad).

Escáner de vulnerabilidades web que rastrea una aplicación objetivo, lanza pruebas
de detección (SQL Injection, XSS, cabeceras de seguridad y cookies) y guarda los
hallazgos en SQLite. En la fase siguiente, un módulo de IA explicará y priorizará
cada hallazgo.

> ⚠️ La carpeta `target/` es una web **deliberadamente vulnerable** usada como banco
> de pruebas en local. No desplegar en producción ni exponer a Internet.

## Estructura

```
vulnia/
├── target/      # Mini web vulnerable en Flask (objetivo de pruebas)
├── crawler/     # Rastreo: descubre páginas, formularios y cookies
├── scanner/     # Detección: SQLi, XSS, cabeceras y cookies
├── storage/     # Persistencia en SQLite (findings.db)
├── docs/        # Evidencias de ejecución
└── requirements.txt
```

## Requisitos

- Python 3.10 o superior
- Dependencias: Flask, requests, beautifulsoup4

## Instalación

```bash
python -m venv venv
# Windows:  venv\Scripts\activate
# Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
```

## Ejecución

En una terminal, levanta la web objetivo:

```bash
python target/app.py
# Queda escuchando en http://127.0.0.1:5000
```

En otra terminal, lanza el escaneo:

```bash
python scanner/scanner.py http://127.0.0.1:5000
```

El escáner imprime un resumen y el detalle de los hallazgos, y los guarda en
`storage/findings.db`.

## Vulnerabilidades que detecta

| Tipo | Dónde | Cómo se detecta |
|---|---|---|
| SQL Injection | Login | Payload de bypass de autenticación |
| XSS reflejado | Buscador (`?q=`) | Marcador reflejado sin escapar |
| XSS almacenado | Comentarios | Marcador persistido y servido sin escapar |
| Cookie insegura | Cookie de sesión | Login previo + revisión de flags (HttpOnly, Secure, SameSite) |
| Cabeceras ausentes | Todas las páginas | Falta de CSP, X-Frame-Options, X-Content-Type-Options, HSTS |

## Estado del desarrollo

- ✅ Mini web vulnerable (target)
- ✅ Crawler (páginas, formularios, cookies)
- ✅ Scanner (SQLi, XSS, cabeceras, cookie con login previo)
- ✅ Persistencia en SQLite con campos preparados para la IA
- ⏳ Módulo de IA (explicación y priorización de hallazgos) — en curso
- ⏳ Panel web para lanzar el escaneo y ver el informe — pendiente

## Nota sobre claves de API

El repositorio no contiene credenciales ni claves de API. Cuando se añada el
módulo de IA con proveedor externo, la clave se leerá de una variable de entorno
(ver `.env.example`), nunca del código.

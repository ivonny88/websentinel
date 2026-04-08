"""
WebSentinel - Motor de monitoreo
"""

import requests
import ssl
import socket
import time
import re
import os
import resend
from datetime import datetime, timezone
from urllib.parse import urlparse

# ── Constantes de seguridad ──────────────────────────────────────────────────
REQUEST_TIMEOUT = 10
MAX_URL_LENGTH  = 253
ALLOWED_SCHEMES = {"http", "https"}
PRIVATE_IP_RANGES = re.compile(
    r"^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)"
)

# ── Validación de URL ────────────────────────────────────────────────────────
def validate_url(url: str) -> tuple[bool, str]:
    url = url.strip()
    if len(url) > MAX_URL_LENGTH * 3:
        return False, "URL demasiado larga."
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "URL con formato incorrecto."
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"Esquema no permitido: {parsed.scheme}."
    host = parsed.hostname or ""
    if not host:
        return False, "No se pudo extraer el dominio."
    if PRIVATE_IP_RANGES.match(host):
        return False, "No se permiten IPs privadas ni localhost."
    try:
        parts = host.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            nums = [int(p) for p in parts]
            if nums[0] in (10, 127) or (nums[0] == 172 and 16 <= nums[1] <= 31) \
                    or (nums[0] == 192 and nums[1] == 168):
                return False, "No se permiten IPs privadas."
    except Exception:
        pass
    return True, url


# ── Check de disponibilidad ──────────────────────────────────────────────────
def check_uptime(url: str) -> dict:
    result = {
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": None,
        "status_code": None,
        "response_time_ms": None,
        "error": None,
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-ES,es;q=0.9",
    }
    try:
        start = time.perf_counter()
        resp = requests.get(
            url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
            headers=headers, verify=True, stream=True,
        )
        resp.close()
        elapsed = (time.perf_counter() - start) * 1000
        result["status_code"] = resp.status_code
        result["response_time_ms"] = round(elapsed, 2)
        result["status"] = "up" if resp.status_code < 400 else "down"
    except requests.exceptions.SSLError:
        result["status"] = "ssl_error"
        result["error"] = "Error SSL: certificado inválido o caducado."
    except requests.exceptions.ConnectionError:
        result["status"] = "down"
        result["error"] = "No se pudo conectar con el servidor."
    except requests.exceptions.Timeout:
        result["status"] = "timeout"
        result["error"] = f"La web tardó más de {REQUEST_TIMEOUT}s en responder."
    except requests.exceptions.TooManyRedirects:
        result["status"] = "down"
        result["error"] = "Demasiadas redirecciones."
    except Exception:
        result["status"] = "error"
        result["error"] = "Error inesperado al comprobar la web."
    return result


# ── Check de certificado SSL ─────────────────────────────────────────────────
def check_ssl(url: str) -> dict:
    result = {
        "url": url,
        "has_ssl": False,
        "days_remaining": None,
        "expiry_date": None,
        "error": None,
    }
    parsed = urlparse(url)
    if parsed.scheme != "https":
        result["error"] = "La web no usa HTTPS."
        return result
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        expiry_str = cert.get("notAfter", "")
        expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        now = datetime.now(timezone.utc)
        days_remaining = (expiry_dt - now).days
        result["has_ssl"] = True
        result["days_remaining"] = days_remaining
        result["expiry_date"] = expiry_dt.strftime("%d/%m/%Y")
    except ssl.SSLCertVerificationError:
        result["error"] = "Certificado SSL inválido o no confiable."
    except socket.timeout:
        result["error"] = "Timeout al comprobar SSL."
    except Exception:
        result["error"] = "No se pudo comprobar el certificado SSL."
    return result


# ── Alerta por email via Resend ──────────────────────────────────────────────
def send_alert_email(
    recipient: str,
    subject: str,
    body_html: str,
) -> tuple[bool, str]:
    email_re = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
    if not email_re.match(recipient):
        return False, "Email de destinatario con formato incorrecto."
    try:
        resend.api_key = os.environ.get("RESEND_API_KEY", "")
        resend.Emails.send({
            "from": "WebSentinel <onboarding@resend.dev>",
            "to": [recipient],
            "subject": subject,
            "html": body_html,
        })
        return True, "Email enviado correctamente."
    except Exception:
        return False, "Error inesperado al enviar el email."


# ── Generar cuerpo del email ─────────────────────────────────────────────────
def build_alert_email_html(url: str, issue: str, detail: str) -> str:
    return f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;
                border:1px solid #e0e0e0;border-radius:8px;overflow:hidden;">
      <div style="background:#0f172a;padding:24px;text-align:center;">
        <h1 style="color:#38bdf8;margin:0;font-size:22px;">🛡️ WebSentinel</h1>
        <p style="color:#94a3b8;margin:4px 0 0;">Monitor de disponibilidad web</p>
      </div>
      <div style="padding:24px;">
        <h2 style="color:#dc2626;">⚠️ Alerta detectada</h2>
        <p><strong>Web:</strong> {url}</p>
        <p><strong>Problema:</strong> {issue}</p>
        <p><strong>Detalle:</strong> {detail}</p>
        <p style="color:#6b7280;font-size:12px;margin-top:32px;">
          Este email fue enviado por WebSentinel.
        </p>
      </div>
    </div>
    """

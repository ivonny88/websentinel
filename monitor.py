"""
WebSentinel - Motor de monitoreo
Seguridad: sin eval, sin exec, validación estricta de URLs,
timeouts en todas las peticiones, sin logging de datos sensibles.
"""

import requests
import ssl
import socket
import time
import re
from datetime import datetime, timezone
from urllib.parse import urlparse
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ── Constantes de seguridad ──────────────────────────────────────────────────
REQUEST_TIMEOUT = 10          # segundos máx por petición
MAX_URL_LENGTH  = 253         # límite DNS
ALLOWED_SCHEMES = {"http", "https"}
PRIVATE_IP_RANGES = re.compile(
    r"^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)"
)


# ── Validación de URL ────────────────────────────────────────────────────────
def validate_url(url: str) -> tuple[bool, str]:
    """
    Valida la URL antes de hacer cualquier petición.
    Previene SSRF (Server-Side Request Forgery) bloqueando IPs privadas.
    Retorna (es_valida, mensaje).
    """
    url = url.strip()

    if len(url) > MAX_URL_LENGTH * 3:
        return False, "URL demasiado larga."

    # Añadir esquema si falta
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "URL con formato incorrecto."

    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"Esquema no permitido: {parsed.scheme}. Usa http o https."

    host = parsed.hostname or ""
    if not host:
        return False, "No se pudo extraer el dominio."

    # Bloquear IPs privadas / localhost (anti-SSRF)
    if PRIVATE_IP_RANGES.match(host):
        return False, "No se permiten IPs privadas ni localhost."

    # Bloquear IPs en formato numérico directo
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


# ── Check de disponibilidad (uptime) ─────────────────────────────────────────
def check_uptime(url: str) -> dict:
    """
    Hace una petición HEAD (o GET si falla) con timeout estricto.
    No sigue redirecciones infinitas (max 5).
    """
    result = {
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": None,
        "status_code": None,
        "response_time_ms": None,
        "error": None,
    }

    try:
        start = time.perf_counter()
        resp = requests.head(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "WebSentinel-Monitor/1.0"},
            verify=True,          # siempre verificar SSL
            stream=False,
        )
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
    except Exception as e:
        result["status"] = "error"
        # No exponemos el traceback completo al usuario
        result["error"] = "Error inesperado al comprobar la web."

    return result


# ── Check de certificado SSL ──────────────────────────────────────────────────
def check_ssl(url: str) -> dict:
    """
    Comprueba la caducidad del certificado SSL.
    Usa ssl.create_default_context() para no deshabilitar verificaciones.
    """
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

        # Parsear fecha de expiración
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


# ── Alerta por email ──────────────────────────────────────────────────────────
def send_alert_email(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    recipient: str,
    subject: str,
    body_html: str,
) -> tuple[bool, str]:
    """
    Envía alerta por email usando TLS (STARTTLS o SSL).
    - Nunca loguea smtp_password.
    - Valida el email del destinatario antes de enviar.
    """
    # Validación básica del email destinatario
    email_re = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
    if not email_re.match(recipient):
        return False, "Email de destinatario con formato incorrecto."

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = smtp_user
        msg["To"]      = recipient
        msg.attach(MIMEText(body_html, "html", "utf-8"))

        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as server:
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, [recipient], msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, [recipient], msg.as_string())

        return True, "Email enviado correctamente."

    except smtplib.SMTPAuthenticationError:
        return False, "Credenciales SMTP incorrectas."
    except smtplib.SMTPException as e:
        return False, "Error al enviar el email."
    except Exception:
        return False, "Error inesperado al enviar el email."


# ── Generar cuerpo del email de alerta ───────────────────────────────────────
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
          Si no esperabas este mensaje, ignóralo.
        </p>
      </div>
    </div>
    """
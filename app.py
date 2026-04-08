"""
WebSentinel - Interfaz Streamlit
Seguridad aplicada:
  - st.secrets para credenciales (nunca en código)
  - Rate limiting manual por sesión
  - Sanitización de inputs
  - Sin mostrar stack traces al usuario
"""

import streamlit as st
import time
from datetime import datetime, timezone

from monitor import (
    validate_url,
    check_uptime,
    check_ssl,
    send_alert_email,
    build_alert_email_html,
)

# ── Configuración de la página ───────────────────────────────────────────────
st.set_page_config(
    page_title="WebSentinel — Monitor para PYMEs",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ── Estilos personalizados ───────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=IBM+Plex+Mono:wght@400;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Space Grotesk', sans-serif;
}

/* Header */
.ws-header {
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
    border-radius: 16px;
    padding: 32px 24px;
    text-align: center;
    margin-bottom: 24px;
    border: 1px solid #1e40af;
}
.ws-header h1 {
    color: #38bdf8;
    font-size: 2.4rem;
    margin: 0;
    letter-spacing: -1px;
}
.ws-header p {
    color: #94a3b8;
    margin: 6px 0 0;
    font-size: 1rem;
}

/* Cards de resultado */
.result-card {
    border-radius: 12px;
    padding: 20px;
    margin: 10px 0;
    border-left: 4px solid;
}
.result-up    { background:#f0fdf4; border-color:#22c55e; }
.result-down  { background:#fef2f2; border-color:#ef4444; }
.result-warn  { background:#fffbeb; border-color:#f59e0b; }
.result-info  { background:#eff6ff; border-color:#3b82f6; }

/* Métrica grande */
.big-metric {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 2rem;
    font-weight: 600;
}

/* Badge de estado */
.badge {
    display:inline-block;
    padding:4px 12px;
    border-radius:999px;
    font-size:0.8rem;
    font-weight:600;
}
.badge-green  { background:#dcfce7; color:#15803d; }
.badge-red    { background:#fee2e2; color:#dc2626; }
.badge-yellow { background:#fef9c3; color:#a16207; }
.badge-blue   { background:#dbeafe; color:#1d4ed8; }

/* Ocultar menú hamburguesa de Streamlit */
#MainMenu, footer, header { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# ── Rate limiting por sesión (anti-abuso) ────────────────────────────────────
MAX_CHECKS_PER_SESSION = 20
if "check_count" not in st.session_state:
    st.session_state.check_count = 0
if "history" not in st.session_state:
    st.session_state.history = []
if "last_check_time" not in st.session_state:
    st.session_state.last_check_time = 0


def rate_limit_ok() -> bool:
    """Permite máx 1 check cada 5 segundos y máx 20 por sesión."""
    now = time.time()
    if st.session_state.check_count >= MAX_CHECKS_PER_SESSION:
        return False
    if now - st.session_state.last_check_time < 5:
        return False
    return True


# ── Header ───────────────────────────────────────────────────────────────────
st.markdown("""
<div class="ws-header">
  <h1>🛡️ WebSentinel</h1>
  <p>Monitor de disponibilidad para PYMEs españolas</p>
</div>
""", unsafe_allow_html=True)


# ── Tabs ─────────────────────────────────────────────────────────────────────
tab_check, tab_history, tab_config, tab_info = st.tabs([
    "🔍 Comprobar web",
    "📋 Historial",
    "⚙️ Configurar alertas",
    "ℹ️ Planes",
])


# ════════════════════════════════════════════════════════════════════════════
# TAB 1 — COMPROBAR WEB
# ════════════════════════════════════════════════════════════════════════════
with tab_check:
    st.markdown("### Introduce la URL de tu web")

    col_url, col_btn = st.columns([4, 1])
    with col_url:
        raw_url = st.text_input(
            "URL",
            placeholder="miweb.com o https://miweb.com",
            label_visibility="collapsed",
            max_chars=300,
        )
    with col_btn:
        check_btn = st.button("Analizar", type="primary", use_container_width=True)

    # Opciones avanzadas
    with st.expander("⚙️ Opciones"):
        threshold_ms = st.slider(
            "Umbral de velocidad lenta (ms)",
            min_value=500, max_value=10000, value=3000, step=500,
        )
        ssl_warn_days = st.slider(
            "Avisar si el SSL caduca en menos de (días)",
            min_value=7, max_value=60, value=30, step=7,
        )

    # ── Lógica de análisis ───────────────────────────────────────────────────
    if check_btn and raw_url:

        # Rate limiting
        if not rate_limit_ok():
            if st.session_state.check_count >= MAX_CHECKS_PER_SESSION:
                st.error("Has alcanzado el límite de comprobaciones de esta sesión. Recarga la página.")
            else:
                st.warning("Espera 5 segundos entre comprobaciones.")
            st.stop()

        # Validar URL (anti-SSRF)
        is_valid, url_or_error = validate_url(raw_url)
        if not is_valid:
            st.error(f"⛔ URL no válida: {url_or_error}")
            st.stop()

        url = url_or_error

        with st.spinner("Analizando tu web..."):
            uptime_result = check_uptime(url)
            ssl_result    = check_ssl(url)
            
        st.session_state.check_count += 1
        st.session_state.last_check_time = time.time()

        # Guardar en historial
        st.session_state.history.append({
            "timestamp": datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC"),
            "url": url,
            "status": uptime_result["status"],
            "status_code": uptime_result.get("status_code"),
            "response_time_ms": uptime_result.get("response_time_ms"),
            "ssl_days": ssl_result.get("days_remaining"),
        })

        st.markdown("---")
        st.markdown("### 📊 Resultados")

        # ── Uptime ──────────────────────────────────────────────────────────
        st.markdown("#### Disponibilidad")
        status = uptime_result["status"]
        rt     = uptime_result.get("response_time_ms")
        code   = uptime_result.get("status_code")

        if status == "up":
            badge = '<span class="badge badge-green">✅ ONLINE</span>'
            card_cls = "result-up"
            msg = f"La web responde correctamente."
        elif status == "timeout":
            badge = '<span class="badge badge-yellow">⏱️ TIMEOUT</span>'
            card_cls = "result-warn"
            msg = uptime_result.get("error", "")
        else:
            badge = '<span class="badge badge-red">❌ CAÍDA</span>'
            card_cls = "result-down"
            msg = uptime_result.get("error", "No responde.")

        speed_info = ""
        if rt:
            if rt > threshold_ms:
                speed_badge = f'<span class="badge badge-yellow">🐢 Lenta: {rt:.0f}ms</span>'
            else:
                speed_badge = f'<span class="badge badge-green">⚡ Rápida: {rt:.0f}ms</span>'
            speed_info = f"<br>{speed_badge}"

        code_info = f"&nbsp;&nbsp;Código HTTP: <code>{code}</code>" if code else ""

        st.markdown(f"""
        <div class="result-card {card_cls}">
          {badge}{code_info}{speed_info}
          <p style="margin:10px 0 0;">{msg}</p>
        </div>
        """, unsafe_allow_html=True)

        # ── SSL ─────────────────────────────────────────────────────────────
        st.markdown("#### Certificado SSL")

        if ssl_result.get("error"):
            st.markdown(f"""
            <div class="result-card result-down">
              <span class="badge badge-red">❌ SSL</span>
              <p style="margin:10px 0 0;">{ssl_result['error']}</p>
            </div>
            """, unsafe_allow_html=True)
        elif ssl_result.get("has_ssl"):
            days = ssl_result["days_remaining"]
            expiry = ssl_result["expiry_date"]
            if days < 0:
                ssl_badge   = '<span class="badge badge-red">❌ CADUCADO</span>'
                ssl_cls     = "result-down"
                ssl_msg     = f"El certificado caducó hace {abs(days)} días."
            elif days < ssl_warn_days:
                ssl_badge   = f'<span class="badge badge-yellow">⚠️ Caduca pronto</span>'
                ssl_cls     = "result-warn"
                ssl_msg     = f"Caduca el {expiry} — quedan {days} días. ¡Renuévalo!"
            else:
                ssl_badge   = '<span class="badge badge-green">✅ Válido</span>'
                ssl_cls     = "result-up"
                ssl_msg     = f"Caduca el {expiry} — quedan {days} días."

            st.markdown(f"""
            <div class="result-card {ssl_cls}">
              {ssl_badge}
              <p style="margin:10px 0 0;">{ssl_msg}</p>
            </div>
            """, unsafe_allow_html=True)

        # ── Aviso de alerta email ────────────────────────────────────────────
        alert_cfg = st.session_state.get("alert_config", {})
        if alert_cfg.get("email") and (status != "up" or (rt and rt > threshold_ms)):
            st.info("📧 Configuraste alertas por email. Ve a ⚙️ Configurar alertas para enviar el aviso.")


# ════════════════════════════════════════════════════════════════════════════
# TAB 2 — HISTORIAL
# ════════════════════════════════════════════════════════════════════════════
with tab_history:
    st.markdown("### 📋 Historial de comprobaciones")

    if not st.session_state.history:
        st.info("Aún no has hecho ninguna comprobación en esta sesión.")
    else:
        # Mostrar en orden inverso (más reciente primero)
        for entry in reversed(st.session_state.history):
            status = entry["status"]
            emoji  = "✅" if status == "up" else ("⏱️" if status == "timeout" else "❌")
            rt     = entry.get("response_time_ms")
            rt_str = f"{rt:.0f}ms" if rt else "—"
            ssl_d  = entry.get("ssl_days")
            ssl_str = f"{ssl_d}d" if ssl_d is not None else "—"

            st.markdown(f"""
            <div style="border:1px solid #e2e8f0;border-radius:8px;
                        padding:12px 16px;margin:6px 0;background:#f8fafc;">
              <span style="font-size:1.1rem;">{emoji}</span>
              <strong style="margin-left:8px;">{entry['url']}</strong>
              <span style="float:right;color:#64748b;font-size:0.85rem;">
                {entry['timestamp']}
              </span>
              <br>
              <span style="color:#64748b;font-size:0.85rem;">
                Velocidad: <strong>{rt_str}</strong> &nbsp;|&nbsp;
                SSL: <strong>{ssl_str}</strong>
              </span>
            </div>
            """, unsafe_allow_html=True)

        if st.button("🗑️ Limpiar historial"):
            st.session_state.history = []
            st.rerun()


# ════════════════════════════════════════════════════════════════════════════
# TAB 3 — CONFIGURAR ALERTAS
# ════════════════════════════════════════════════════════════════════════════
with tab_config:
    st.markdown("### ⚙️ Configurar alertas por email")
    st.info("""
    **Plan Free** — Alertas manuales (comprueba tú cuando quieras).  
    **Plan Pro 9€/mes** — Monitoreo automático cada 5 min + alertas instantáneas.
    """)

    with st.form("alert_form"):
        st.markdown("#### Tus datos de contacto")
        alert_email = st.text_input(
            "Tu email",
            placeholder="tucorreo@ejemplo.com",
            max_chars=254,
        )

        st.markdown("#### URL a monitorear")
        test_url = st.text_input(
            "URL de tu web",
            placeholder="https://miweb.com",
            max_chars=300,
        )

        submitted = st.form_submit_button(
            "💾 Guardar y enviar email de prueba", type="primary"
        )

    if submitted:
        errors = []
        import re
        email_re = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
        if not email_re.match(alert_email):
            errors.append("El email no es válido.")

        if test_url:
            is_valid, url_or_error = validate_url(test_url)
            if not is_valid:
                errors.append(f"URL no válida: {url_or_error}")

        if errors:
            for e in errors:
                st.error(e)
        else:
            st.session_state.alert_config = {
                "email": alert_email,
            }

            html_body = build_alert_email_html(
                url=test_url or "—",
                issue="Email de prueba",
                detail="Tu configuración de alertas funciona correctamente. 🎉",
            )
            with st.spinner("Enviando email de prueba..."):
                ok, msg = send_alert_email(
                    recipient=alert_email,
                    subject="🛡️ WebSentinel — Prueba de alerta",
                    body_html=html_body,
                )
            if ok:
                st.success(f"✅ Configuración guardada. {msg}")
            else:
                st.error(f"❌ {msg}")
# ════════════════════════════════════════════════════════════════════════════
# TAB 4 — PLANES
# ════════════════════════════════════════════════════════════════════════════
with tab_info:
    st.markdown("### 📦 Planes de WebSentinel")

    col_free, col_pro = st.columns(2)

    with col_free:
        st.markdown("""
        <div style="border:2px solid #e2e8f0;border-radius:16px;padding:24px;text-align:center;">
          <h3 style="margin:0;color:#0f172a;">Free</h3>
          <p style="font-size:2rem;font-weight:700;color:#0f172a;margin:8px 0;">0€</p>
          <p style="color:#64748b;font-size:0.9rem;">para siempre</p>
          <hr>
          <ul style="text-align:left;color:#374151;line-height:2;">
            <li>✅ 1 web monitorizada</li>
            <li>✅ Comprobación manual</li>
            <li>✅ Check de SSL</li>
            <li>✅ Check de velocidad</li>
            <li>✅ Historial de sesión</li>
            <li>❌ Monitoreo automático</li>
            <li>❌ Alertas WhatsApp</li>
            <li>❌ Reportes semanales</li>
          </ul>
        </div>
        """, unsafe_allow_html=True)

    with col_pro:
        st.markdown("""
        <div style="border:2px solid #3b82f6;border-radius:16px;padding:24px;text-align:center;
                    background:linear-gradient(135deg,#eff6ff,#fff);">
          <span style="background:#3b82f6;color:white;padding:2px 12px;border-radius:999px;
                       font-size:0.8rem;">MÁS POPULAR</span>
          <h3 style="margin:8px 0 0;color:#0f172a;">Pro</h3>
          <p style="font-size:2rem;font-weight:700;color:#1d4ed8;margin:8px 0;">9€<span style="font-size:1rem;font-weight:400;">/mes</span></p>
          <p style="color:#64748b;font-size:0.9rem;">cancela cuando quieras</p>
          <hr>
          <ul style="text-align:left;color:#374151;line-height:2;">
            <li>✅ Hasta 5 webs</li>
            <li>✅ Monitoreo automático cada 5 min</li>
            <li>✅ Alertas por email instantáneas</li>
            <li>✅ Alertas por WhatsApp</li>
            <li>✅ Reporte semanal</li>
            <li>✅ Historial de 30 días</li>
            <li>✅ Soporte prioritario</li>
          </ul>
          <a href="https://gumroad.com" target="_blank"
             style="display:block;background:#1d4ed8;color:white;padding:12px;
                    border-radius:8px;text-decoration:none;font-weight:600;margin-top:8px;">
            Conseguir Pro →
          </a>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("""
    <p style="text-align:center;color:#64748b;font-size:0.85rem;">
    🛡️ WebSentinel — Hecho en España para PYMEs españolas<br>
    ¿Preguntas? Escríbenos por Instagram <strong>@websentinel</strong>
    </p>
    """, unsafe_allow_html=True)
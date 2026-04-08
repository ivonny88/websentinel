# 🛡️ WebSentinel

Monitor de disponibilidad web para PYMEs españolas.

## ¿Qué hace?
- Comprueba si tu web está caída
- Mide el tiempo de carga
- Verifica el certificado SSL y su fecha de caducidad
- Envía alertas por email cuando detecta problemas

## Stack
- Python 3.11+
- Streamlit
- requests (HTTP checks)
- ssl + socket (SSL checks)
- smtplib (alertas email)

## Instalación local

```bash
git clone https://github.com/TU_USUARIO/websentinel
cd websentinel
pip install -r requirements.txt
streamlit run app.py
```

## Despliegue en Streamlit Cloud

1. Sube el repositorio a GitHub (sin el archivo `secrets.toml`)
2. Ve a [share.streamlit.io](https://share.streamlit.io)
3. Conecta tu repo y despliega

## Seguridad implementada

- ✅ Validación estricta de URLs (anti-SSRF)
- ✅ Bloqueo de IPs privadas y localhost
- ✅ Rate limiting por sesión
- ✅ Timeouts en todas las peticiones
- ✅ Verificación SSL forzada (verify=True)
- ✅ Sin logging de contraseñas
- ✅ Secrets gestionados con st.secrets
- ✅ Sin eval() ni exec()
- ✅ Validación de emails con regex
- ✅ Límite de longitud en todos los inputs

## Estructura

```
websentinel/
├── app.py           # Interfaz Streamlit
├── monitor.py       # Motor de monitoreo (lógica pura)
├── requirements.txt
├── .gitignore       # Protege secrets.toml
└── README.md
```

## Modelo de negocio

| Plan | Precio | Webs | Monitoreo |
|------|--------|------|-----------|
| Free | 0€ | 1 | Manual |
| Pro | 9€/mes | 5 | Automático cada 5 min |

Cobra con [Gumroad](https://gumroad.com) — sin web, sin servidor propio.
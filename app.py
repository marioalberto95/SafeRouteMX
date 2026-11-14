from flask import Flask, render_template, request, redirect, session, jsonify, flash
import re
from flask_mail import Mail, Message
import random
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
from firebase_admin import credentials, firestore, messaging
import os
import uuid
import json
from werkzeug.utils import secure_filename
import cloudinary
import cloudinary.uploader
import threading
from flask import url_for
import requests
import secrets
from datetime import datetime, timedelta
import time
import hmac
from html import escape as esc
app = Flask(__name__)
# En Render agrega la variable SECRET_KEY con un texto largo y aleatorio.
# Si no existe, usa el valor anterior para que nada se rompa.
app.secret_key = os.environ.get("SECRET_KEY", "saferoute_secret_key")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# La cookie solo viaja por HTTPS cuando corre en Render (en tu PC con http sigue funcionando).
app.config["SESSION_COOKIE_SECURE"] = bool(os.environ.get("RENDER"))
# La sesión se cierra sola tras 30 minutos sin actividad.
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
# Tamaño máximo de cualquier petición (fotos incluidas): 8 MB.
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
if app.secret_key == "saferoute_secret_key":
    print("AVISO: define SECRET_KEY en Render; estás usando la clave por defecto.", flush=True)

# ======================
# CONFIGURACIÓN CLOUDINARY
# ======================
cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET"),
    secure=True
)
# ======================
# CONFIGURACIÓN CORREO
# ======================
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp-relay.brevo.com")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_TIMEOUT"] = 10

app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER", app.config["MAIL_USERNAME"])
mail = Mail(app)
# ======================
# FUNCIÓN PARA ENVIAR CORREO DEL ESTADO DEL REPORTE
# ======================
def enviar_correo_estado_reporte(correo, nombre, reporte, estado, seguimiento, comentario):
    brevo_api_key = os.environ.get("BREVO_API_KEY")

    if not brevo_api_key:
        return

    payload = {
        "sender": {
            "name": "SafeRoute MX",
            "email": app.config["MAIL_DEFAULT_SENDER"]
        },
        "to": [
            {
                "email": correo,
                "name": nombre or "Usuario SafeRoute"
            }
        ],
        "subject": "Actualización de tu reporte - SafeRoute MX",
        "htmlContent": f"""
            <h2>Hola {esc(nombre or "Usuario SafeRoute")}</h2>
            <p>Tu reporte ha sido actualizado por el administrador.</p>

            <h3>Detalles del reporte</h3>
            <p><b>Tipo:</b> {esc(str(reporte.get("tipo", "Sin tipo")))}</p>
            <p><b>Ubicación:</b> {esc(str(reporte.get("ubicacion", "Sin ubicación")))}</p>
            <p><b>Gravedad:</b> {esc(str(reporte.get("gravedad", "Sin gravedad")))}</p>

            <h3>Estado actual</h3>
            <p><b>Estado:</b> {esc(str(estado))}</p>
            <p><b>Seguimiento:</b> {esc(str(seguimiento))}</p>
            <p><b>Comentario del administrador:</b> {esc(str(comentario or "Sin comentario"))}</p>

            <p>Gracias por contribuir a la seguridad de la comunidad.</p>
        """
    }

    try:
        respuesta = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "accept": "application/json",
                "api-key": brevo_api_key,
                "content-type": "application/json"
            },
            json=payload,
            timeout=10
        )
        print("BREVO ESTADO REPORTE:", respuesta.status_code, respuesta.text, flush=True)

    except Exception as e:
        print("ERROR NOTIFICANDO ESTADO REPORTE:", e, flush=True)
# ======================
# SEGURIDAD: CSRF, CÓDIGOS, LÍMITE DE INTENTOS, IMÁGENES
# ======================
RUTAS_SIN_CSRF = {"static", "registrar_token_dispositivo", "registrar_token_reloj"}


def obtener_csrf():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


@app.context_processor
def inyectar_csrf():
    return {"csrf_token": obtener_csrf}


def calcular_stats_perfil():
    """Datos extra para la página de perfil (se llama desde la plantilla)."""
    correo = session.get("usuario")
    stats = {"total": 0, "aprobados": 0, "pendientes": 0, "rechazados": 0, "comentarios": 0}

    if not correo:
        return stats

    try:
        for doc in db.collection("reportes").where("usuario", "==", correo).stream():
            estado = doc.to_dict().get("estado", "Pendiente")
            stats["total"] += 1
            if estado == "Rechazado":
                stats["rechazados"] += 1
            elif doc.to_dict().get("aprobado"):
                stats["aprobados"] += 1
            else:
                stats["pendientes"] += 1

        stats["comentarios"] = sum(
            1 for _ in db.collection("comentarios").where("autor_correo", "==", correo).stream()
        )
    except Exception as e:
        print("ERROR STATS PERFIL:", e, flush=True)

    return stats


@app.context_processor
def inyectar_stats_perfil():
    return {"perfil_stats": calcular_stats_perfil}


@app.before_request
def proteger_csrf():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None

    if request.endpoint in RUTAS_SIN_CSRF:
        return None

    enviado = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    esperado = session.get("_csrf") or ""

    if not esperado or not hmac.compare_digest(str(enviado), str(esperado)):
        if request.path.startswith("/chatbot"):
            return jsonify({"respuesta": "Tu sesión expiró. Recarga la página e inténtalo de nuevo."}), 400
        return (
            "<h3>La página expiró o la petición no es válida.</h3>"
            "<p>Regresa, recarga la página e inténtalo de nuevo. "
            "<a href='/'>Ir al inicio</a></p>",
            400,
        )
    return None


@app.errorhandler(413)
def archivo_muy_grande(e):
    return (
        "<h3>El archivo es demasiado grande (máximo 5 MB por imagen).</h3>"
        "<p><a href='javascript:history.back()'>Regresar</a></p>",
        413,
    )


# ---- Códigos de 6 dígitos con caducidad y límite de intentos ----
CODIGO_VIGENCIA_SEG = 15 * 60
CODIGO_MAX_INTENTOS = 5
CODIGO_BLOQUEO_SEG = 15 * 60
CODIGO_REENVIO_SEG = 60


def generar_codigo():
    return str(secrets.randbelow(900000) + 100000)


def datos_codigo_nuevo(prefijo, codigo, caduca=True):
    datos = {
        prefijo: codigo,
        prefijo + "_intentos": 0,
        prefijo + "_enviado": time.time(),
    }
    datos[prefijo + "_expira"] = time.time() + CODIGO_VIGENCIA_SEG if caduca else firestore.DELETE_FIELD
    return datos


def puede_reenviar_codigo(usuario, prefijo):
    enviado = usuario.get(prefijo + "_enviado") or 0
    return (time.time() - enviado) >= CODIGO_REENVIO_SEG


def validar_codigo(doc_ref, usuario, prefijo, codigo):
    """Devuelve (True, None) si el código es correcto, o (False, mensaje)."""
    ahora = time.time()

    bloqueo = usuario.get(prefijo + "_bloqueo") or 0
    if bloqueo > ahora:
        minutos = int((bloqueo - ahora) // 60) + 1
        return False, f"Demasiados intentos. Espera {minutos} minuto(s) e inténtalo de nuevo."

    guardado = usuario.get(prefijo) or ""
    if not guardado:
        return False, "No hay un código activo. Solicita uno nuevo."

    expira = usuario.get(prefijo + "_expira")
    if expira and ahora > expira:
        return False, "El código expiró. Solicita uno nuevo."

    if not codigo or not hmac.compare_digest(str(guardado), str(codigo)):
        intentos = (usuario.get(prefijo + "_intentos") or 0) + 1

        if intentos >= CODIGO_MAX_INTENTOS:
            doc_ref.update({
                prefijo + "_intentos": 0,
                prefijo + "_bloqueo": ahora + CODIGO_BLOQUEO_SEG,
            })
            return False, "Demasiados intentos incorrectos. Espera 15 minutos e inténtalo de nuevo."

        doc_ref.update({prefijo + "_intentos": intentos})
        restantes = CODIGO_MAX_INTENTOS - intentos
        return False, f"El código ingresado no es correcto. Te quedan {restantes} intento(s)."

    return True, None


def limpiar_codigo(prefijo):
    return {
        prefijo: "",
        prefijo + "_intentos": 0,
        prefijo + "_expira": firestore.DELETE_FIELD,
        prefijo + "_bloqueo": firestore.DELETE_FIELD,
    }


# ---- Límite de intentos de contraseña (login y reloj) ----
LOGIN_MAX_INTENTOS = 5
LOGIN_BLOQUEO_SEG = 15 * 60


def login_bloqueado(usuario):
    return (usuario.get("bloqueo_login") or 0) > time.time()


def registrar_fallo_login(doc_ref, usuario):
    intentos = (usuario.get("intentos_login") or 0) + 1

    if intentos >= LOGIN_MAX_INTENTOS:
        doc_ref.update({
            "intentos_login": 0,
            "bloqueo_login": time.time() + LOGIN_BLOQUEO_SEG,
        })
    else:
        doc_ref.update({"intentos_login": intentos})


def limpiar_fallos_login(doc_ref, usuario):
    if usuario.get("intentos_login") or usuario.get("bloqueo_login"):
        doc_ref.update({
            "intentos_login": 0,
            "bloqueo_login": firestore.DELETE_FIELD,
        })


def buscar_usuarios_por_correo(correo, correo_original=None):
    """Busca por correo con una consulta (no recorre toda la colección)."""
    docs = list(db.collection("usuarios").where("correo", "==", correo).stream())

    if not docs and correo_original and correo_original != correo:
        docs = list(db.collection("usuarios").where("correo", "==", correo_original).stream())

    return docs


# ---- Imágenes ----
IMAGEN_MAX_BYTES = 5 * 1024 * 1024


def _tipo_imagen(cabecera):
    if cabecera.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if cabecera.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if cabecera[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if cabecera[:4] == b"RIFF" and cabecera[8:12] == b"WEBP":
        return "webp"
    return None


def procesar_imagen(archivo, carpeta, public_id=None):
    """Valida (contenido real, tamaño) y sube a Cloudinary. Devuelve (url, error)."""
    cabecera = archivo.stream.read(12)
    archivo.stream.seek(0, os.SEEK_END)
    tamano = archivo.stream.tell()
    archivo.stream.seek(0)

    if _tipo_imagen(cabecera) is None:
        return None, "El archivo debe ser una imagen válida (JPG, PNG, GIF o WEBP)."

    if tamano > IMAGEN_MAX_BYTES:
        return None, "La imagen es demasiado grande. El máximo es 5 MB."

    opciones = {"folder": carpeta, "resource_type": "image"}
    if public_id:
        opciones["public_id"] = public_id
        opciones["overwrite"] = True

    try:
        resultado = cloudinary.uploader.upload(archivo, **opciones)
    except Exception as e:
        print("ERROR CLOUDINARY:", e, flush=True)
        return None, "No se pudo subir la imagen. Intenta de nuevo."

    return resultado.get("secure_url"), None


def leer_coordenadas(latitud, longitud):
    try:
        lat = float(latitud)
        lng = float(longitud)
    except (TypeError, ValueError):
        return None

    if not (-90 <= lat <= 90 and -180 <= lng <= 180):
        return None

    return lat, lng


# ======================
# COMPROBACION 
# ====================== 
@app.before_request
def verificar_sesion_unica():

    # Permitir archivos CSS, JS e imágenes
    if request.endpoint == "static":
        return None

    # Rutas que no necesitan iniciar sesión
    rutas_publicas = {
        "index",
        "login",
        "registro",
        "verificar",
        "recuperar_password",
        "restablecer_password"
    }

    if request.endpoint in rutas_publicas:
        return None

    # Si no hay una sesión iniciada, las propias rutas
    # seguirán controlando el acceso como hasta ahora.
    if "usuario" not in session:
        return None

    user_id = session.get("user_id")
    token_local = session.get("token_sesion")

    if not user_id or not token_local:
        session.clear()

        return redirect(
            url_for(
                "login",
                sesion="invalida"
            )
        )

    usuario_doc = db.collection("usuarios").document(user_id).get()

    if not usuario_doc.exists:
        session.clear()
        return redirect("/login")

    usuario = usuario_doc.to_dict()
    token_guardado = usuario.get("token_sesion_activa")

    # Si otro dispositivo inició sesión, el token guardado cambia.
    if not token_guardado or token_guardado != token_local:
        session.clear()

        return redirect(
            url_for(
                "login",
                sesion="otro_dispositivo"
            )
        )

    return None

@app.after_request
def evitar_cache_paginas(response):

    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, private, max-age=0"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    return response
# ======================
# FIREBASE
# ======================
firebase_config = os.environ.get("FIREBASE_KEY")

if firebase_config:
    firebase_dict = json.loads(firebase_config)
    cred = credentials.Certificate(firebase_dict)
else:
    cred = credentials.Certificate("firebase_key.json")

firebase_admin.initialize_app(cred)
db = firestore.client()

# ======================
# NOTIFICACIONES PUSH (Firebase Cloud Messaging)
# ======================
def _enviar_push_a_documento(doc, titulo, cuerpo, datos=None):
    """Manda una notificación a todos los dispositivos guardados en usuarios/{doc}.fcm_tokens"""
    tokens = doc.to_dict().get("fcm_tokens", []) or []
    for token in tokens:
        try:
            messaging.send(messaging.Message(
                token=token,
                notification=messaging.Notification(title=titulo, body=cuerpo),
                data={k: str(v) for k, v in (datos or {}).items()},
                android=messaging.AndroidConfig(
                    priority="high",
                    notification=messaging.AndroidNotification(channel_id="reportes")
                )
            ))
            print("PUSH ENVIADO a", doc.id, flush=True)
        except messaging.UnregisteredError:
            # El dispositivo ya no existe (app desinstalada): limpiar el token
            db.collection("usuarios").document(doc.id).update({
                "fcm_tokens": firestore.ArrayRemove([token])
            })
        except Exception as e:
            print("ERROR PUSH:", e, flush=True)


def enviar_push_a_usuario(correo, titulo, cuerpo, datos=None):
    try:
        for doc in db.collection("usuarios").where("correo", "==", correo).limit(1).stream():
            _enviar_push_a_documento(doc, titulo, cuerpo, datos)
    except Exception as e:
        print("ERROR PUSH USUARIO:", e, flush=True)


def avisar_estado_reporte_push(reporte_id, estado):
    """Busca al dueño del reporte y le manda la notificación del nuevo estado."""
    try:
        doc = db.collection("reportes").document(reporte_id).get()
        if doc.exists:
            reporte = doc.to_dict()
            correo = reporte.get("usuario")
            if correo:
                enviar_push_a_usuario(
                    correo,
                    "Tu reporte fue actualizado",
                    f"Estado: {estado}",
                    {"tipo": "estado_reporte", "reporte_id": reporte_id}
                )
                enviar_correo_estado_reporte(
                    correo,
                    reporte.get("nombre_usuario", "Usuario SafeRoute"),
                    reporte,
                    estado,
                    reporte.get("seguimiento", ""),
                    reporte.get("comentario_admin", "")
                )
    except Exception as e:
        print("ERROR AVISO ESTADO PUSH:", e, flush=True)


def enviar_correo_simple(correo, nombre, asunto, html):
    """Envía un correo por la API de Brevo. Devuelve True si salió bien."""
    brevo_api_key = os.environ.get("BREVO_API_KEY")

    if not brevo_api_key:
        print("BREVO_API_KEY no configurada: no se envió el correo", flush=True)
        return False

    try:
        respuesta = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "accept": "application/json",
                "api-key": brevo_api_key,
                "content-type": "application/json"
            },
            json={
                "sender": {"name": "SafeRoute MX", "email": app.config["MAIL_DEFAULT_SENDER"]},
                "to": [{"email": correo, "name": nombre or "SafeRoute MX"}],
                "subject": asunto,
                "htmlContent": html
            },
            timeout=10
        )
        print("BREVO CORREO:", asunto, "->", correo, respuesta.status_code, respuesta.text, flush=True)
        return respuesta.status_code in [200, 201, 202]
    except Exception as e:
        print("ERROR CORREO:", e, flush=True)
        return False


def _detalle_reporte_html(reporte):
    return f"""
        <p><b>Tipo:</b> {esc(str(reporte.get("tipo", "")))}</p>
        <p><b>Ubicación:</b> {esc(str(reporte.get("ubicacion", "")))}</p>
        <p><b>Gravedad:</b> {esc(str(reporte.get("gravedad", "")))}</p>
        <p><b>Descripción:</b> {esc(str(reporte.get("descripcion", "")))}</p>
    """


def avisar_reporte_por_correo(reporte, editado=False):
    """Confirma al usuario su reporte nuevo/editado y avisa a los administradores.
    Corre en segundo plano para no hacer lenta la página."""

    def tarea():
        try:
            accion = "editado y enviado de nuevo a revisión" if editado else "recibido y enviado a revisión"
            nombre = reporte.get("nombre_usuario") or "Usuario SafeRoute"
            correo = reporte.get("usuario")

            # Notificaciones al reloj/celular: al usuario y a los administradores
            resumen = f"{reporte.get('tipo', 'Reporte')} - {reporte.get('ubicacion', '')}"

            if correo:
                enviar_push_a_usuario(
                    correo,
                    "Reporte editado" if editado else "Reporte recibido",
                    "Quedó en revisión. Te avisaremos cuando lo revise el administrador."
                )

            enviar_push_a_admins(
                "Reporte editado por revisar" if editado else "Nuevo reporte en SafeRoute MX",
                resumen
            )

            if correo:
                enviar_correo_simple(
                    correo,
                    nombre,
                    "Tu reporte fue " + ("editado" if editado else "recibido") + " - SafeRoute MX",
                    f"""
                    <h2>Hola {esc(nombre)}</h2>
                    <p>Tu reporte fue {accion}. Te avisaremos por correo cuando el administrador lo revise.</p>
                    <h3>Detalles</h3>
                    {_detalle_reporte_html(reporte)}
                    <p>Gracias por contribuir a la seguridad de la comunidad.</p>
                    """
                )

            for doc in db.collection("usuarios").where("rol", "==", "admin").stream():
                admin = doc.to_dict()
                if admin.get("correo"):
                    enviar_correo_simple(
                        admin["correo"],
                        admin.get("nombre"),
                        ("Reporte editado" if editado else "Nuevo reporte") + " por revisar - SafeRoute MX",
                        f"""
                        <h2>{'Reporte editado' if editado else 'Nuevo reporte'} pendiente de revisión</h2>
                        <p>Enviado por: {esc(str(nombre))} ({esc(str(correo or ''))})</p>
                        {_detalle_reporte_html(reporte)}
                        <p>Entra a SafeRoute MX → Reportes para aprobarlo o rechazarlo.</p>
                        """
                    )
        except Exception as e:
            print("ERROR AVISO REPORTE CORREO:", e, flush=True)

    threading.Thread(target=tarea, daemon=True).start()


def describir_dispositivo(user_agent):
    ua = (user_agent or "").lower()

    if "iphone" in ua:
        sistema = "iPhone (iOS)"
    elif "ipad" in ua:
        sistema = "iPad (iOS)"
    elif "android" in ua:
        sistema = "Android"
    elif "windows" in ua:
        sistema = "Windows"
    elif "mac os" in ua or "macintosh" in ua:
        sistema = "Mac"
    elif "linux" in ua:
        sistema = "Linux"
    else:
        sistema = "Dispositivo desconocido"

    if "edg/" in ua or "edge" in ua:
        navegador = "Edge"
    elif "opr/" in ua or "opera" in ua:
        navegador = "Opera"
    elif "firefox" in ua:
        navegador = "Firefox"
    elif "chrome" in ua or "crios" in ua:
        navegador = "Chrome"
    elif "safari" in ua:
        navegador = "Safari"
    elif "wv" in ua:
        navegador = "App SafeRoute"
    else:
        navegador = "Navegador desconocido"

    return f"{navegador} en {sistema}"


def avisar_inicio_otro_dispositivo(correo, nombre, dispositivo, ip):
    """Correo de seguridad: se abrió tu cuenta en otro dispositivo. Corre en segundo plano."""

    def tarea():
        try:
            try:
                from zoneinfo import ZoneInfo
                ahora = datetime.now(ZoneInfo("America/Mexico_City"))
            except Exception:
                ahora = datetime.utcnow()

            fecha = ahora.strftime("%d/%m/%Y %H:%M")

            enviar_correo_simple(
                correo,
                nombre,
                "Alerta de seguridad: inicio de sesión en otro dispositivo - SafeRoute MX",
                f"""
                <h2>Hola {esc(nombre or 'Usuario SafeRoute')}</h2>
                <p>Se inició sesión en tu cuenta de SafeRoute MX desde <b>otro dispositivo</b>
                mientras tenías una sesión abierta. Por seguridad, la sesión anterior se cerró.</p>
                <p><b>Dispositivo:</b> {esc(dispositivo)}<br>
                <b>Fecha y hora (CDMX):</b> {esc(fecha)}<br>
                <b>Dirección IP:</b> {esc(ip or 'No disponible')}</p>
                <p>Si fuiste tú, no tienes que hacer nada.</p>
                <p><b>Si no fuiste tú</b>, entra a SafeRoute MX, elige "¿Olvidaste tu contraseña?"
                y cámbiala de inmediato.</p>
                """
            )
        except Exception as e:
            print("ERROR AVISO OTRO DISPOSITIVO:", e, flush=True)

    threading.Thread(target=tarea, daemon=True).start()


def enviar_push_a_admins(titulo, cuerpo, datos=None):
    try:
        for doc in db.collection("usuarios").where("rol", "==", "admin").stream():
            _enviar_push_a_documento(doc, titulo, cuerpo, datos)
    except Exception as e:
        print("ERROR PUSH ADMINS:", e, flush=True)

# ======================
# INICIO
# ======================
@app.route("/")
def inicio():
    return render_template("index.html")
# ======================
# LOGIN
# ======================
def cerrar_sesion_silenciosa():
    """Cierra la sesión actual (igual que /logout) pero sin redirigir."""
    user_id = session.get("user_id")
    token_local = session.get("token_sesion")

    if user_id and token_local:
        try:
            usuario_ref = db.collection("usuarios").document(user_id)
            usuario_doc = usuario_ref.get()

            if usuario_doc.exists:
                token_guardado = usuario_doc.to_dict().get("token_sesion_activa")

                if token_guardado == token_local:
                    usuario_ref.update({
                        "token_sesion_activa": firestore.DELETE_FIELD
                    })
        except Exception as e:
            print("ERROR CERRANDO SESION:", e, flush=True)

    session.clear()


@app.route("/login", methods=["GET", "POST"])
def login():

    # Si alguien con la sesión abierta regresa a la pantalla de login
    # (por ejemplo con la flecha "atrás"), la sesión se cierra.
    if request.method == "GET" and "usuario" in session:
        cerrar_sesion_silenciosa()

    if request.method == "POST":
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not correo or not password:
            return render_template(
                "login.html",
                error="Ingresa tu correo y contraseña."
            )

        correo_original = request.form.get("correo", "").strip()

        for doc in buscar_usuarios_por_correo(correo, correo_original):
            usuario = doc.to_dict()
            doc_ref = db.collection("usuarios").document(doc.id)

            correo_db = usuario.get("correo", "").strip().lower()
            password_db = usuario.get("password", "")
            rol_db = usuario.get("rol", "usuario").strip().lower()

            if login_bloqueado(usuario):
                return render_template(
                    "login.html",
                    error="Demasiados intentos fallidos. Espera 15 minutos e inténtalo de nuevo."
                )

            if check_password_hash(password_db, password):

                if not usuario.get("verificado", False):
                    session.clear()
                    session["correo_verificacion"] = correo_db

                    return render_template(
                        "verificar_codigo.html",
                        error="Debes verificar tu correo antes de iniciar sesión."
                    )

                # Elimina cualquier sesión anterior del navegador actual
                session.clear()
                session.permanent = True

                # Token único para esta sesión
                token_sesion = secrets.token_urlsafe(32)

                session["usuario"] = correo_db
                session["nombre"] = usuario.get("nombre", "")
                session["rol"] = rol_db
                session["user_id"] = doc.id
                session["foto_perfil"] = usuario.get("foto_perfil", "")
                session["token_sesion"] = token_sesion

                # Al guardar un token nuevo, cualquier sesión anterior
                # de esta cuenta queda invalidada.
                user_agent = request.headers.get("User-Agent", "")[:300]
                dispositivo = describir_dispositivo(user_agent)
                ip_cliente = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                              or request.remote_addr)

                # Si había una sesión abierta en OTRO dispositivo, se avisa por correo.
                if usuario.get("token_sesion_activa") and usuario.get("ultimo_dispositivo") != user_agent:
                    avisar_inicio_otro_dispositivo(
                        correo_db, usuario.get("nombre", ""), dispositivo, ip_cliente
                    )

                datos_login = {
                    "token_sesion_activa": token_sesion,
                    "ultimo_dispositivo": user_agent,
                    "fecha_ultimo_login": firestore.SERVER_TIMESTAMP
                }
                if usuario.get("intentos_login") or usuario.get("bloqueo_login"):
                    datos_login["intentos_login"] = 0
                    datos_login["bloqueo_login"] = firestore.DELETE_FIELD

                doc_ref.update(datos_login)

                if rol_db == "admin":
                    return redirect("/admin")

                return redirect("/dashboard")

            registrar_fallo_login(doc_ref, usuario)

        return render_template(
            "login.html",
            error="Correo o contraseña incorrectos. Verifica tus datos."
        )

    return render_template("login.html")
# ======================
# RECUPERAR CONTRASEÑA DESDE LOGIN
# ======================
def enviar_correo_recuperacion_password(correo, nombre, codigo):
    brevo_api_key = os.environ.get("BREVO_API_KEY")

    if not brevo_api_key:
        print("BREVO_API_KEY no configurada", flush=True)
        return False

    payload = {
        "sender": {
            "name": "SafeRoute MX",
            "email": app.config["MAIL_DEFAULT_SENDER"]
        },
        "to": [
            {
                "email": correo,
                "name": nombre or "Usuario SafeRoute"
            }
        ],
        "subject": "Código para restablecer tu contraseña - SafeRoute MX",
        "htmlContent": f"""
            <h2>Hola {nombre or "Usuario SafeRoute"}</h2>
            <p>Recibimos una solicitud para restablecer la contraseña de tu cuenta.</p>
            <p>Tu código de verificación es:</p>
            <h1>{codigo}</h1>
            <p>Ingresa este código en SafeRoute MX para crear una nueva contraseña.</p>
            <p>Si tú no solicitaste este cambio, ignora este correo.</p>
        """
    }

    try:
        respuesta = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "accept": "application/json",
                "api-key": brevo_api_key,
                "content-type": "application/json"
            },
            json=payload,
            timeout=10
        )

        print("BREVO RECUPERACION STATUS:", respuesta.status_code, flush=True)
        print("BREVO RECUPERACION RESPONSE:", respuesta.text, flush=True)

        return respuesta.status_code in [200, 201, 202]

    except Exception as e:
        print("ERROR BREVO RECUPERACION:", e, flush=True)
        return False


@app.route("/recuperar_password", methods=["GET", "POST"])
def recuperar_password():

    if request.method == "POST":
        correo = request.form.get("correo", "").strip().lower()

        usuario_doc = None
        usuario = None

        for doc in buscar_usuarios_por_correo(correo):
            usuario_doc = doc
            usuario = doc.to_dict()
            break

        if not usuario_doc:
            return render_template(
                "recuperar_password.html",
                error="No existe una cuenta registrada con ese correo."
            )

        if not puede_reenviar_codigo(usuario, "codigo_recuperacion"):
            return render_template(
                "recuperar_password.html",
                error="Espera un minuto antes de pedir otro código."
            )

        codigo = generar_codigo()

        db.collection("usuarios").document(usuario_doc.id).update(
            datos_codigo_nuevo("codigo_recuperacion", codigo)
        )

        session["correo_recuperacion"] = correo

        demo_mode = os.environ.get("DEMO_MODE", "").strip().lower()

        if demo_mode in ["true", "1", "yes", "si"]:
            return render_template(
                "restablecer_password.html",
                codigo_demo=codigo
            )

        enviado = enviar_correo_recuperacion_password(
            correo,
            usuario.get("nombre", "Usuario SafeRoute"),
            codigo
        )

        if not enviado:
            return render_template(
                "restablecer_password.html",
                codigo_demo=codigo,
                error="No se pudo enviar el correo. Usa este código temporalmente."
            )

        return render_template(
            "restablecer_password.html",
            exito="Te enviamos un código a tu correo para restablecer tu contraseña."
        )

    return render_template("recuperar_password.html")


@app.route("/restablecer_password", methods=["GET", "POST"])
def restablecer_password():

    correo = session.get("correo_recuperacion")

    if not correo:
        return redirect("/recuperar_password")

    if request.method == "POST":
        codigo = request.form.get("codigo", "").replace(" ", "").strip()
        password_nueva = request.form.get("password_nueva", "")
        password_confirmar = request.form.get("password_confirmar", "")

        patron_password = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.#_-])[A-Za-z\d@$!%*?&.#_-]{8,}$"

        for doc in buscar_usuarios_por_correo(correo):
            usuario = doc.to_dict()
            doc_ref = db.collection("usuarios").document(doc.id)

            ok, mensaje = validar_codigo(doc_ref, usuario, "codigo_recuperacion", codigo)

            if not ok:
                return render_template(
                    "restablecer_password.html",
                    error=mensaje
                )

            if not re.match(patron_password, password_nueva):
                return render_template(
                    "restablecer_password.html",
                    error="La contraseña debe tener mínimo 8 caracteres, una mayúscula, una minúscula, un número y un símbolo."
                )

            if password_nueva != password_confirmar:
                return render_template(
                    "restablecer_password.html",
                    error="Las contraseñas no coinciden."
                )

            cambios = {
                "password": generate_password_hash(password_nueva),
                # Cierra cualquier sesión que estuviera abierta con la contraseña vieja
                "token_sesion_activa": firestore.DELETE_FIELD,
                "intentos_login": 0,
                "bloqueo_login": firestore.DELETE_FIELD,
            }
            cambios.update(limpiar_codigo("codigo_recuperacion"))
            doc_ref.update(cambios)

            session.pop("correo_recuperacion", None)

            return render_template(
                "login.html",
                exito="Contraseña actualizada correctamente. Ya puedes iniciar sesión."
            )

        return render_template(
            "restablecer_password.html",
            error="No se pudo validar el código. Solicita uno nuevo."
        )

    return render_template("restablecer_password.html")

# ======================
# REGISTRO USUARIO
# ======================
@app.route("/registro", methods=["GET", "POST"])
def registro():

    # Igual que en el login: volver aquí con la sesión abierta la cierra.
    if request.method == "GET" and "usuario" in session:
        cerrar_sesion_silenciosa()

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "")
        confirmar = request.form.get("confirmar_password", "")

        patron_nombre = r"^[A-Za-zÁÉÍÓÚáéíóúÑñ\s]{3,60}$"
        patron_password = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.#_-])[A-Za-z\d@$!%*?&.#_-]{8,}$"

        if not re.match(patron_nombre, nombre):
            return render_template("registro.html", error="El nombre solo debe contener letras y espacios. Mínimo 3 caracteres.")

        if len(nombre.split()) < 2:
            return render_template("registro.html", error="Escribe tu nombre completo, por ejemplo: Juan Pérez.")

        if not re.match(r"^[A-Za-z0-9._%+\-]+@gmail\.com$", correo):
            return render_template("registro.html", error="Solo se aceptan correos de Gmail. Escribe un correo que termine en @gmail.com.")

        if not re.match(patron_password, password):
            return render_template("registro.html", error="La contraseña debe tener mínimo 8 caracteres, una mayúscula, una minúscula, un número y un símbolo.")

        if password != confirmar:
            return render_template("registro.html", error="Las contraseñas no coinciden.")

        usuarios = db.collection("usuarios").where("correo", "==", correo).stream()

        for doc in usuarios:
            return render_template("registro.html", error="Este correo ya está registrado.")

        codigo = generar_codigo()

        usuario = {
            "nombre": nombre,
            "correo": correo,
            "password": generate_password_hash(password),
            "rol": "usuario",
            "verificado": False,
            "codigo_verificacion": codigo,
            "codigo_verificacion_intentos": 0
        }

        demo_mode = os.environ.get("DEMO_MODE", "").strip().lower()

        if demo_mode in ["true", "1", "yes", "si"]:
            db.collection("usuarios").add(usuario)
            session["correo_verificacion"] = correo
            return render_template("verificar_codigo.html", codigo_demo=codigo)

        brevo_api_key = os.environ.get("BREVO_API_KEY")

        payload = {
            "sender": {
                "name": "SafeRoute MX",
                "email": app.config["MAIL_DEFAULT_SENDER"]
            },
            "to": [{"email": correo, "name": nombre}],
            "subject": "Código de verificación - SafeRoute MX",
            "htmlContent": f"""
                <h2>Hola {esc(nombre)}</h2>
                <p>Bienvenido a SafeRoute MX.</p>
                <p>Tu código de verificación es:</p>
                <h1>{codigo}</h1>
                <p>Ingresa este código en la plataforma para activar tu cuenta.</p>
                <p>Gracias por usar SafeRoute MX.</p>
            """
        }

        try:
            respuesta = requests.post(
                "https://api.brevo.com/v3/smtp/email",
                headers={
                    "accept": "application/json",
                    "api-key": brevo_api_key,
                    "content-type": "application/json"
                },
                json=payload,
                timeout=10
            )

            print("BREVO STATUS:", respuesta.status_code, flush=True)
            print("BREVO RESPONSE:", respuesta.text, flush=True)

            if respuesta.status_code not in [200, 201, 202]:
                return render_template("registro.html", error="No se pudo enviar el correo de verificación. Intenta de nuevo.")

        except Exception as e:
            print("ERROR BREVO API:", e, flush=True)
            return render_template("registro.html", error="No se pudo enviar el correo de verificación. Intenta de nuevo.")

        db.collection("usuarios").add(usuario)
        session["correo_verificacion"] = correo

        return redirect("/verificar")

    return render_template("registro.html")

@app.route("/verificar", methods=["GET", "POST"])
def verificar():

    correo = session.get("correo_verificacion")

    if not correo:
        return redirect("/registro")

    if request.method == "POST":

        codigo = request.form.get("codigo", "").replace(" ", "").strip()

        for doc in buscar_usuarios_por_correo(correo):
            usuario = doc.to_dict()
            doc_ref = db.collection("usuarios").document(doc.id)

            ok, mensaje = validar_codigo(doc_ref, usuario, "codigo_verificacion", codigo)

            if not ok:
                return render_template(
                    "verificar_codigo.html",
                    error=mensaje
                )

            cambios = {"verificado": True}
            cambios.update(limpiar_codigo("codigo_verificacion"))
            doc_ref.update(cambios)

            session.pop("correo_verificacion", None)

            return render_template(
                "login.html",
                exito="Correo verificado correctamente. Ya puedes iniciar sesión."
            )

        return render_template(
            "verificar_codigo.html",
            error="No se pudo validar el código."
        )

    return render_template("verificar_codigo.html")
# ======================
# DASHBOARD USUARIO
# ======================
@app.route("/dashboard")
def dashboard():

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") == "admin":
        return redirect("/admin")

    usuario_actual = session.get("usuario")

    # Obtener información del usuario (incluye la foto de perfil)
    usuario = None

    usuarios = db.collection("usuarios").where("correo", "==", usuario_actual).stream()

    for doc in usuarios:
        usuario = doc.to_dict()
        usuario["id"] = doc.id
        break

    reportes = []

    docs = db.collection("reportes").where("usuario", "==", usuario_actual).stream()

    riesgo_alto = 0
    riesgo_medio = 0
    riesgo_bajo = 0

    for doc in docs:

        reporte = doc.to_dict()
        reporte["id"] = doc.id

        reportes.append(reporte)

        gravedad = reporte.get("gravedad", "")

        if gravedad == "Alta":
            riesgo_alto += 1

        elif gravedad == "Media":
            riesgo_medio += 1

        elif gravedad == "Baja":
            riesgo_bajo += 1

    return render_template(
        "usuario/dashboard.html",
        usuario=usuario,
        reportes=reportes,
        total_reportes=len(reportes),
        riesgo_alto=riesgo_alto,
        riesgo_medio=riesgo_medio,
        riesgo_bajo=riesgo_bajo
    )
# ======================
# MAPA GENERAL PUBLICO
# ======================
# ======================
# MAPA GENERAL PUBLICO
# ======================
@app.route("/mapa")
def mapa():

    usuarios_por_correo = {}

    usuarios_docs = db.collection("usuarios").stream()

    for user_doc in usuarios_docs:

        user = user_doc.to_dict()

        correo = user.get("correo", "").strip().lower()

        usuarios_por_correo[correo] = {
            "nombre": user.get("nombre", "Usuario SafeRoute"),
            "foto_perfil": user.get("foto_perfil", "")
        }

    reportes = []

    docs = (
        db.collection("reportes")
        .where("aprobado", "==", True)
        .stream()
    )

    for doc in docs:

        reporte = doc.to_dict()
        reporte["id"] = doc.id

        try:

            reporte["latitud"] = float(reporte["latitud"])
            reporte["longitud"] = float(reporte["longitud"])

            correo = reporte.get("usuario", "").strip().lower()

            datos = usuarios_por_correo.get(correo, {})

            reporte["nombre_usuario"] = datos.get("nombre", "Usuario SafeRoute")
            reporte["foto_usuario"] = datos.get("foto_perfil", "")

            reporte["foto_reporte"] = reporte.get("foto_reporte", "")

            # El correo de quien reportó no se envía al navegador de los demás usuarios
            reporte.pop("usuario", None)

            reportes.append(reporte)

        except:
            pass

    reportes.sort(key=lambda r: r.get("fecha", ""), reverse=True)

    return render_template(
        "usuario/mapa.html",
        reportes=reportes
    )

# ======================
# REPORTAR USUARIO
# ======================
@app.route("/reportar", methods=["GET", "POST"])
def reportar():

    if "usuario" not in session:
        return redirect("/login")

    if request.method == "POST":
        tipo = request.form.get("tipo", "").strip()[:60]
        descripcion = request.form.get("descripcion", "").strip()[:1500]
        fecha = request.form.get("fecha", "").strip()[:30]
        ubicacion = request.form.get("ubicacion", "").strip()[:300]
        gravedad = request.form.get("gravedad", "").strip()[:20]
        latitud = request.form.get("latitud")
        longitud = request.form.get("longitud")

        foto_reporte = request.files.get("foto_reporte")
        url_foto_reporte = ""

        coords = leer_coordenadas(latitud, longitud)

        if not coords:
            return render_template(
                "usuario/reportar.html",
                exito=False,
                error="Debes seleccionar una ubicación en el mapa."
            )

        if foto_reporte and foto_reporte.filename != "":
            url_foto_reporte, error_foto = procesar_imagen(
                foto_reporte, "saferoutemx/reportes"
            )

            if error_foto:
                return render_template(
                    "usuario/reportar.html",
                    exito=False,
                    error=error_foto
                )

        reporte = {
            "tipo": tipo,
            "descripcion": descripcion,
            "fecha": fecha,
            "ubicacion": ubicacion,
            "gravedad": gravedad,
            "latitud": coords[0],
            "longitud": coords[1],
            "usuario": session.get("usuario"),
            "nombre_usuario": session.get("nombre"),
            "foto_usuario": session.get("foto_perfil", ""),
            "foto_reporte": url_foto_reporte,

            "aprobado": False,
            "estado": "Pendiente",
            "seguimiento": "Sin seguimiento",
            "comentario_admin": "",
            "fecha_actualizacion": "",
            "creado_desde": "formulario"
        }

        db.collection("reportes").add(reporte)

        avisar_reporte_por_correo(reporte)

        return render_template("usuario/reportar.html", exito=True)

    return render_template("usuario/reportar.html", exito=False)

# ======================
# DASHBOARD ADMIN
# ======================
@app.route("/admin")
def admin_dashboard():

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    reportes = list(db.collection("reportes").stream())
    usuarios = list(db.collection("usuarios").stream())

    return render_template(
        "admin/dashboard.html",
        total_reportes=len(reportes),
        total_usuarios=len(usuarios)
    )


# ======================
# REPORTES ADMIN
# ======================
@app.route("/admin/reportes")
def admin_reportes():

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    reportes = []
    docs = db.collection("reportes").stream()

    for doc in docs:
        reporte = doc.to_dict()
        reporte["id"] = doc.id
        reportes.append(reporte)

    reportes.sort(key=lambda r: (
        r.get("aprobado", False),
        r.get("estado", "Pendiente")
    ))

    return render_template("admin/reportes.html", reportes=reportes)
@app.route("/admin/reportes/actualizar_estado/<id>", methods=["POST"])
def actualizar_estado_reporte(id):

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    estado = request.form.get("estado", "Pendiente")
    seguimiento = request.form.get("seguimiento", "Sin seguimiento")
    comentario_admin = request.form.get("comentario_admin", "").strip()

    estados_validos = [
        "Pendiente",
        "Aprobado",
        "Rechazado",
        "En seguimiento",
        "Resuelto"
    ]

    if estado not in estados_validos:
        estado = "Pendiente"

    aprobado = estado in ["Aprobado", "En seguimiento", "Resuelto"]

    reporte_ref = db.collection("reportes").document(id)
    reporte_doc = reporte_ref.get()

    if not reporte_doc.exists:
        return redirect("/admin/reportes")

    reporte = reporte_doc.to_dict()

    datos_actualizados = {
        "estado": estado,
        "seguimiento": seguimiento,
        "comentario_admin": comentario_admin,
        "aprobado": aprobado,
        "fecha_actualizacion": firestore.SERVER_TIMESTAMP
    }

    # Cuando el administrador ya tomó una decisión,
    # deja de aparecer como pendiente de nueva revisión.
    if estado != "Pendiente":
        datos_actualizados["requiere_revision"] = False
        datos_actualizados["editado_por_usuario"] = False

    reporte_ref.update(datos_actualizados)

    correo_usuario = reporte.get("usuario")
    nombre_usuario = reporte.get(
        "nombre_usuario",
        "Usuario SafeRoute"
    )

    if correo_usuario:
        enviar_correo_estado_reporte(
            correo_usuario,
            nombre_usuario,
            reporte,
            estado,
            seguimiento,
            comentario_admin
        )
        enviar_push_a_usuario(
            correo_usuario,
            "Tu reporte fue actualizado",
            f"Estado: {estado}",
            {"tipo": "estado_reporte", "reporte_id": id}
        )

    return redirect("/admin/reportes")

@app.route("/admin/reportes/aprobar/<id>", methods=["POST"])
def aprobar_reporte(id):

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    db.collection("reportes").document(id).update({
        "aprobado": True,
        "estado": "Aprobado",
        "seguimiento": "Reporte aprobado para la comunidad",
        "requiere_revision": False,
        "editado_por_usuario": False,
        "fecha_actualizacion": firestore.SERVER_TIMESTAMP
    })

    avisar_estado_reporte_push(id, "Aprobado")

    return redirect("/admin/reportes")

@app.route("/admin/reportes/rechazar/<id>", methods=["POST"])
def rechazar_reporte(id):

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    db.collection("reportes").document(id).update({
        "aprobado": False,
        "estado": "Rechazado",
        "seguimiento": "Reporte no aprobado para publicación",
        "requiere_revision": False,
        "editado_por_usuario": False,
        "fecha_actualizacion": firestore.SERVER_TIMESTAMP
    })

    avisar_estado_reporte_push(id, "Rechazado")

    return redirect("/admin/reportes")

@app.route("/admin/reportes/eliminar/<id>", methods=["POST"])
def eliminar_reporte(id):

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    db.collection("reportes").document(id).delete()
    borrar_comentarios_de_reporte(id)

    return redirect("/admin/reportes")


# ======================
# USUARIOS ADMIN
# ======================
@app.route("/admin/usuarios")
def admin_usuarios():

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    usuarios = []
    docs = db.collection("usuarios").stream()

    for doc in docs:
        usuario = doc.to_dict()
        usuario["id"] = doc.id
        usuarios.append(usuario)

    return render_template("admin/usuarios.html", usuarios=usuarios)

@app.route("/admin/usuarios/eliminar/<id>", methods=["POST"])
def eliminar_usuario(id):

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    usuario_ref = db.collection("usuarios").document(id)
    usuario_doc = usuario_ref.get()

    if not usuario_doc.exists:
        flash("El usuario no existe o ya fue eliminado.", "warning")
        return redirect("/admin/usuarios")

    usuario = usuario_doc.to_dict()
    correo_usuario = usuario.get("correo", "").strip().lower()
    rol_usuario = usuario.get("rol", "")

    if rol_usuario == "admin":
        flash("No puedes eliminar un usuario administrador.", "danger")
        return redirect("/admin/usuarios")

    if correo_usuario:
        reportes = db.collection("reportes").where("usuario", "==", correo_usuario).stream()

        for reporte in reportes:
            borrar_comentarios_de_reporte(reporte.id)
            reporte.reference.delete()

        borrar_comentarios_de_usuario(correo_usuario)

    usuario_ref.delete()

    flash("Usuario eliminado correctamente.", "success")
    return redirect("/admin/usuarios")

# ======================
# ESTADÍSTICAS ADMIN
# ======================
@app.route("/admin/estadisticas")
def admin_estadisticas():

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    reportes = []
    docs = db.collection("reportes").stream()

    riesgo_alto = 0
    riesgo_medio = 0
    riesgo_bajo = 0

    for doc in docs:
        reporte = doc.to_dict()
        reportes.append(reporte)

        gravedad = reporte.get("gravedad", "")

        if gravedad == "Alta":
            riesgo_alto += 1
        elif gravedad == "Media":
            riesgo_medio += 1
        elif gravedad == "Baja":
            riesgo_bajo += 1

    return render_template(
        "admin/estadisticas.html",
        total_reportes=len(reportes),
        riesgo_alto=riesgo_alto,
        riesgo_medio=riesgo_medio,
        riesgo_bajo=riesgo_bajo
    )

@app.route("/usuario/reporte/eliminar/<id>", methods=["POST"])
def usuario_eliminar_reporte(id):

    if "usuario" not in session:
        return redirect("/login")

    doc_ref = db.collection("reportes").document(id)
    doc = doc_ref.get()

    if not doc.exists:
        return redirect("/dashboard")

    reporte = doc.to_dict()

    if reporte.get("usuario") != session.get("usuario"):
        return redirect("/dashboard")

    doc_ref.delete()
    borrar_comentarios_de_reporte(id)

    return redirect("/dashboard")


@app.route("/usuario/reporte/editar/<id>", methods=["GET", "POST"])
def usuario_editar_reporte(id):

    if "usuario" not in session:
        return redirect("/login")

    doc_ref = db.collection("reportes").document(id)
    doc = doc_ref.get()

    if not doc.exists:
        return redirect("/dashboard")

    reporte = doc.to_dict()

    if reporte.get("usuario") != session.get("usuario"):
        return redirect("/dashboard")

    if request.method == "POST":

        latitud = request.form.get("latitud")
        longitud = request.form.get("longitud")

        coords = leer_coordenadas(latitud, longitud)

        if not coords:
            reporte["id"] = doc.id

            return render_template(
                "usuario/editar_reporte.html",
                reporte=reporte,
                error="Debes seleccionar una ubicación válida en el mapa."
            )

        foto_reporte = request.files.get("foto_reporte")
        url_foto_reporte = reporte.get("foto_reporte", "")

        if foto_reporte and foto_reporte.filename != "":

            nueva_url, error_foto = procesar_imagen(
                foto_reporte, "saferoutemx/reportes"
            )

            if error_foto:
                reporte["id"] = doc.id

                return render_template(
                    "usuario/editar_reporte.html",
                    reporte=reporte,
                    error=error_foto
                )

            url_foto_reporte = nueva_url

        datos_actualizados = {
            "tipo": request.form.get("tipo", "").strip()[:60],
            "descripcion": request.form.get("descripcion", "").strip()[:1500],
            "fecha": request.form.get("fecha", "").strip()[:30],
            "ubicacion": request.form.get("ubicacion", "").strip()[:300],
            "gravedad": request.form.get("gravedad", "").strip()[:20],
            "latitud": coords[0],
            "longitud": coords[1],
            "usuario": session.get("usuario"),
            "foto_reporte": url_foto_reporte,

            # Regresa a revisión administrativa
            "aprobado": False,
            "estado": "Pendiente",
            "seguimiento": "Reporte editado y enviado nuevamente a revisión",
            "comentario_admin": "",
            "editado_por_usuario": True,
            "requiere_revision": True,
            "fecha_actualizacion": firestore.SERVER_TIMESTAMP
        }

        doc_ref.update(datos_actualizados)

        reporte_editado = dict(reporte)
        reporte_editado.update({
            k: v for k, v in datos_actualizados.items()
            if k != "fecha_actualizacion"
        })
        avisar_reporte_por_correo(reporte_editado, editado=True)

        return redirect("/mis-reportes")

    reporte["id"] = doc.id

    return render_template(
        "usuario/editar_reporte.html",
        reporte=reporte
    )

@app.route("/mis-reportes")
def mis_reportes():

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") == "admin":
        return redirect("/admin")

    reportes = []

    docs = db.collection("reportes").where("usuario", "==", session.get("usuario")).stream()

    for doc in docs:
        reporte = doc.to_dict()
        reporte["id"] = doc.id
        reportes.append(reporte)

    return render_template("usuario/mis_reportes.html", reportes=reportes)
@app.route("/admin/mapa")
def admin_mapa():

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    reportes = []
    docs = db.collection("reportes").stream()

    for doc in docs:
        reporte = doc.to_dict()

        if "latitud" in reporte and "longitud" in reporte:
            reportes.append(reporte)

    return render_template("admin/mapa.html", reportes=reportes)

# ======================
# PERFIL
# ======================
@app.route("/perfil", methods=["GET", "POST"])
def perfil():

    if "usuario" not in session:
        return redirect("/login")

    user_id = session.get("user_id")

    if not user_id:
        return redirect("/logout")

    usuario_ref = db.collection("usuarios").document(user_id)
    usuario_doc = usuario_ref.get()

    if not usuario_doc.exists:
        return redirect("/logout")

    usuario = usuario_doc.to_dict()

    def contar_reportes():
        total = 0
        docs = db.collection("reportes").where("usuario", "==", session.get("usuario")).stream()

        for doc in docs:
            total += 1

        return total

    if request.method == "POST":

        nombre = request.form.get("nombre", "").strip()
        foto = request.files.get("foto")

        if not re.match(r"^[A-Za-zÁÉÍÓÚáéíóúÑñ\s]{3,60}$", nombre):
            return render_template(
                "usuario/perfil.html",
                usuario=usuario,
                total_reportes=contar_reportes(),
                error="El nombre solo debe contener letras y espacios (mínimo 3 caracteres)."
            )

        datos_actualizados = {
            "nombre": nombre
        }

        if foto and foto.filename != "":

            ruta_foto, error_foto = procesar_imagen(
                foto,
                "saferoutemx/perfiles",
                public_id=f"perfil_{user_id}"
            )

            if error_foto:
                return render_template(
                    "usuario/perfil.html",
                    usuario=usuario,
                    total_reportes=contar_reportes(),
                    error=error_foto
                )

            datos_actualizados["foto_perfil"] = ruta_foto
            session["foto_perfil"] = ruta_foto

        session["nombre"] = nombre
        usuario_ref.update(datos_actualizados)

        usuario_actualizado = usuario_ref.get().to_dict()

        return render_template(
            "usuario/perfil.html",
            usuario=usuario_actualizado,
            total_reportes=contar_reportes(),
            exito="Perfil actualizado correctamente."
        )

    return render_template(
        "usuario/perfil.html",
        usuario=usuario,
        total_reportes=contar_reportes()
    )


def enviar_correo_cambio_password(correo, nombre, codigo):
    brevo_api_key = os.environ.get("BREVO_API_KEY")

    if not brevo_api_key:
        print("BREVO_API_KEY no configurada", flush=True)
        return False

    payload = {
        "sender": {
            "name": "SafeRoute MX",
            "email": app.config["MAIL_DEFAULT_SENDER"]
        },
        "to": [
            {
                "email": correo,
                "name": nombre or "Usuario SafeRoute"
            }
        ],
        "subject": "Código para cambiar tu contraseña - SafeRoute MX",
        "htmlContent": f"""
            <h2>Hola {nombre or "Usuario SafeRoute"}</h2>
            <p>Recibimos una solicitud para cambiar la contraseña de tu cuenta.</p>
            <p>Tu código de verificación es:</p>
            <h1>{codigo}</h1>
            <p>Ingresa este código en SafeRoute MX para actualizar tu contraseña.</p>
            <p>Si tú no solicitaste este cambio, ignora este correo.</p>
        """
    }

    try:
        respuesta = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "accept": "application/json",
                "api-key": brevo_api_key,
                "content-type": "application/json"
            },
            json=payload,
            timeout=10
        )

        print("BREVO PASSWORD STATUS:", respuesta.status_code, flush=True)
        print("BREVO PASSWORD RESPONSE:", respuesta.text, flush=True)

        return respuesta.status_code in [200, 201, 202]

    except Exception as e:
        print("ERROR BREVO CAMBIO PASSWORD:", e, flush=True)
        return False


@app.route("/perfil/solicitar_cambio_password", methods=["POST"])
def solicitar_cambio_password():

    if "usuario" not in session:
        return redirect("/login")

    user_id = session.get("user_id")

    if not user_id:
        return redirect("/logout")

    usuario_ref = db.collection("usuarios").document(user_id)
    usuario_doc = usuario_ref.get()

    if not usuario_doc.exists:
        return redirect("/logout")

    usuario = usuario_doc.to_dict()

    if not puede_reenviar_codigo(usuario, "codigo_cambio_password"):
        return render_template(
            "usuario/verificar_cambio_password.html",
            error="Espera un minuto antes de pedir otro código."
        )

    codigo = generar_codigo()

    usuario_ref.update(
        datos_codigo_nuevo("codigo_cambio_password", codigo)
    )

    session["cambio_password_user_id"] = user_id

    demo_mode = os.environ.get("DEMO_MODE", "").strip().lower()

    if demo_mode in ["true", "1", "yes", "si"]:
        return render_template(
            "usuario/verificar_cambio_password.html",
            codigo_demo=codigo
        )

    enviado = enviar_correo_cambio_password(
        usuario.get("correo"),
        usuario.get("nombre"),
        codigo
    )

    if not enviado:
        return render_template(
            "usuario/verificar_cambio_password.html",
            codigo_demo=codigo,
            error="No se pudo enviar el correo. Usa este código temporalmente."
        )

    return render_template(
        "usuario/verificar_cambio_password.html",
        exito="Te enviamos un código a tu correo para cambiar la contraseña."
    )


@app.route("/perfil/cambiar_password", methods=["POST"])
def cambiar_password_perfil():

    if "usuario" not in session:
        return redirect("/login")

    # Siempre se cambia la contraseña de la cuenta con la sesión abierta.
    user_id = session.get("user_id")

    if not user_id:
        return redirect("/logout")

    codigo = request.form.get("codigo", "").replace(" ", "").strip()
    password_nueva = request.form.get("password_nueva", "")
    password_confirmar = request.form.get("password_confirmar", "")

    patron_password = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.#_-])[A-Za-z\d@$!%*?&.#_-]{8,}$"

    usuario_ref = db.collection("usuarios").document(user_id)
    usuario_doc = usuario_ref.get()

    if not usuario_doc.exists:
        return redirect("/logout")

    usuario = usuario_doc.to_dict()

    ok, mensaje = validar_codigo(usuario_ref, usuario, "codigo_cambio_password", codigo)

    if not ok:
        return render_template(
            "usuario/verificar_cambio_password.html",
            error=mensaje
        )

    if not re.match(patron_password, password_nueva):
        return render_template(
            "usuario/verificar_cambio_password.html",
            error="La contraseña debe tener mínimo 8 caracteres, una mayúscula, una minúscula, un número y un símbolo."
        )

    if password_nueva != password_confirmar:
        return render_template(
            "usuario/verificar_cambio_password.html",
            error="Las contraseñas no coinciden."
        )

    cambios = {"password": generate_password_hash(password_nueva)}
    cambios.update(limpiar_codigo("codigo_cambio_password"))
    usuario_ref.update(cambios)

    session.pop("cambio_password_user_id", None)

    return render_template(
        "usuario/perfil.html",
        usuario=usuario_ref.get().to_dict(),
        total_reportes=len(list(db.collection("reportes").where("usuario", "==", session.get("usuario")).stream())),
        exito="Contraseña actualizada correctamente."
    )
# ======================
# COMENTARIOS DE LA COMUNIDAD (con aprobación del administrador)
# ======================
COMENTARIO_MAX = 500
COMENTARIOS_PENDIENTES_MAX = 3


def ahora_texto():
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo("America/Mexico_City")).strftime("%d/%m/%Y %H:%M")
    except Exception:
        return datetime.utcnow().strftime("%d/%m/%Y %H:%M")


def usuario_acepta_correos(correo):
    """Respeta la preferencia 'recibir correos de comentarios' del perfil."""
    try:
        for doc in buscar_usuarios_por_correo((correo or "").strip().lower()):
            return doc.to_dict().get("notif_correo", True) is not False
    except Exception as e:
        print("ERROR PREFERENCIA CORREO:", e, flush=True)
    return True


def _bloque_comentario_html(c):
    return f"""
        <div style="border-left:4px solid #dc3545;padding:10px 14px;background:#f8f9fa;margin:12px 0;">
            <b>{esc(str(c.get("autor_nombre", "")))}</b><br>
            {esc(str(c.get("texto", "")))}
        </div>
        <p><b>Reporte:</b> {esc(str(c.get("reporte_tipo", "")))} - {esc(str(c.get("reporte_ubicacion", "")))}</p>
    """


def notificar_comentario_nuevo(c):
    """Avisa a los administradores que hay un comentario por revisar."""

    def tarea():
        try:
            enviar_push_a_admins(
                "Nuevo comentario por revisar",
                f"{c.get('autor_nombre', '')}: {str(c.get('texto', ''))[:80]}"
            )

            for doc in db.collection("usuarios").where("rol", "==", "admin").stream():
                admin = doc.to_dict()
                if admin.get("correo"):
                    enviar_correo_simple(
                        admin["correo"],
                        admin.get("nombre"),
                        "Nuevo comentario por revisar - SafeRoute MX",
                        f"""
                        <h2>Hay un comentario pendiente de aprobación</h2>
                        {_bloque_comentario_html(c)}
                        <p>Entra a SafeRoute MX → Comentarios para aprobarlo o rechazarlo.</p>
                        """
                    )
        except Exception as e:
            print("ERROR AVISO COMENTARIO NUEVO:", e, flush=True)

    threading.Thread(target=tarea, daemon=True).start()


def notificar_comentario_aprobado(c, avisar_autor=True):
    """Al aprobarse: avisa al dueño del reporte ('te comentaron') y al autor ('fue aprobado')."""

    def tarea():
        try:
            dueno = (c.get("dueno_correo") or "").strip().lower()
            autor = (c.get("autor_correo") or "").strip().lower()

            if dueno and dueno != autor:
                enviar_push_a_usuario(
                    dueno,
                    "Comentaron tu reporte",
                    f"{c.get('autor_nombre', '')}: {str(c.get('texto', ''))[:80]}",
                    {"tipo": "comentario", "reporte_id": c.get("reporte_id", "")}
                )

                if usuario_acepta_correos(dueno):
                    enviar_correo_simple(
                        dueno,
                        c.get("dueno_nombre"),
                        "Te comentaron un reporte - SafeRoute MX",
                        f"""
                        <h2>Hola {esc(str(c.get("dueno_nombre") or "Usuario SafeRoute"))}</h2>
                        <p>Alguien de la comunidad comentó tu reporte:</p>
                        {_bloque_comentario_html(c)}
                        <p>Puedes verlo en SafeRoute MX → Mapa, abriendo el detalle de tu reporte.</p>
                        """
                    )

            if avisar_autor and autor:
                enviar_push_a_usuario(
                    autor,
                    "Comentario aprobado",
                    "Tu comentario ya es visible para la comunidad.",
                    {"tipo": "comentario_aprobado", "reporte_id": c.get("reporte_id", "")}
                )

                if usuario_acepta_correos(autor):
                    enviar_correo_simple(
                        autor,
                        c.get("autor_nombre"),
                        "Tu comentario fue aprobado - SafeRoute MX",
                        f"""
                        <h2>Hola {esc(str(c.get("autor_nombre") or "Usuario SafeRoute"))}</h2>
                        <p>El administrador aprobó tu comentario. Ya es visible para la comunidad.</p>
                        {_bloque_comentario_html(c)}
                        """
                    )
        except Exception as e:
            print("ERROR AVISO COMENTARIO APROBADO:", e, flush=True)

    threading.Thread(target=tarea, daemon=True).start()


def notificar_comentario_rechazado(c):

    def tarea():
        try:
            autor = (c.get("autor_correo") or "").strip().lower()
            if not autor:
                return

            enviar_push_a_usuario(
                autor,
                "Comentario no aprobado",
                "El administrador no aprobó tu comentario.",
                {"tipo": "comentario_rechazado", "reporte_id": c.get("reporte_id", "")}
            )

            if usuario_acepta_correos(autor):
                enviar_correo_simple(
                    autor,
                    c.get("autor_nombre"),
                    "Tu comentario no fue aprobado - SafeRoute MX",
                    f"""
                    <h2>Hola {esc(str(c.get("autor_nombre") or "Usuario SafeRoute"))}</h2>
                    <p>El administrador no aprobó tu comentario, por lo que no se publicó.
                    Recuerda mantener un trato respetuoso y evitar datos personales.</p>
                    {_bloque_comentario_html(c)}
                    """
                )
        except Exception as e:
            print("ERROR AVISO COMENTARIO RECHAZADO:", e, flush=True)

    threading.Thread(target=tarea, daemon=True).start()


def borrar_comentarios_de_reporte(reporte_id):
    try:
        for doc in db.collection("comentarios").where("reporte_id", "==", reporte_id).stream():
            doc.reference.delete()
    except Exception as e:
        print("ERROR BORRANDO COMENTARIOS DEL REPORTE:", e, flush=True)


def borrar_comentarios_de_usuario(correo):
    try:
        for doc in db.collection("comentarios").where("autor_correo", "==", correo).stream():
            doc.reference.delete()
    except Exception as e:
        print("ERROR BORRANDO COMENTARIOS DEL USUARIO:", e, flush=True)


@app.route("/comentarios/<reporte_id>")
def listar_comentarios(reporte_id):

    if "usuario" not in session:
        return jsonify({"ok": False, "error": "Inicia sesión para ver los comentarios."}), 401

    yo = session.get("usuario")
    es_admin = session.get("rol") == "admin"
    items = []

    for doc in db.collection("comentarios").where("reporte_id", "==", reporte_id).stream():
        c = doc.to_dict()
        propio = c.get("autor_correo") == yo

        # Solo se ven los aprobados; cada quien ve además los suyos pendientes o rechazados.
        if c.get("estado") != "Aprobado" and not propio:
            continue

        items.append({
            "id": doc.id,
            "autor_nombre": c.get("autor_nombre", "Usuario SafeRoute"),
            "autor_foto": c.get("autor_foto", ""),
            "texto": c.get("texto", ""),
            "estado": c.get("estado", "Pendiente"),
            "fecha": c.get("fecha_texto", ""),
            "propio": propio,
            "puede_borrar": propio or es_admin,
            "orden": c.get("creado_ts", 0),
        })

    items.sort(key=lambda x: x["orden"])
    return jsonify({"ok": True, "comentarios": items})


@app.route("/comentarios/crear/<reporte_id>", methods=["POST"])
def crear_comentario(reporte_id):

    if "usuario" not in session:
        return jsonify({"ok": False, "error": "Inicia sesión para comentar."}), 401

    texto = " ".join(request.form.get("texto", "").split())

    if len(texto) < 3:
        return jsonify({"ok": False, "error": "Escribe al menos 3 caracteres."}), 400

    texto = texto[:COMENTARIO_MAX]

    reporte_doc = db.collection("reportes").document(reporte_id).get()

    if not reporte_doc.exists or not reporte_doc.to_dict().get("aprobado"):
        return jsonify({"ok": False, "error": "Este reporte no está disponible para comentar."}), 404

    reporte = reporte_doc.to_dict()
    yo = session.get("usuario")
    es_admin = session.get("rol") == "admin"

    if not es_admin:
        pendientes = sum(
            1 for _ in db.collection("comentarios")
            .where("autor_correo", "==", yo)
            .where("estado", "==", "Pendiente").stream()
        )

        if pendientes >= COMENTARIOS_PENDIENTES_MAX:
            return jsonify({
                "ok": False,
                "error": "Ya tienes 3 comentarios pendientes de aprobación. Espera a que el administrador los revise."
            }), 429

    dueno_correo = (reporte.get("usuario") or "").strip().lower()
    dueno_nombre = reporte.get("nombre_usuario", "")

    if dueno_correo and not dueno_nombre:
        for d in buscar_usuarios_por_correo(dueno_correo):
            dueno_nombre = d.to_dict().get("nombre", "")
            break

    comentario = {
        "reporte_id": reporte_id,
        "reporte_tipo": reporte.get("tipo", ""),
        "reporte_ubicacion": reporte.get("ubicacion", ""),
        "dueno_correo": dueno_correo,
        "dueno_nombre": dueno_nombre,
        "autor_correo": yo,
        "autor_nombre": session.get("nombre", "Usuario SafeRoute"),
        "autor_foto": session.get("foto_perfil", ""),
        "texto": texto,
        # Los comentarios del administrador se publican directamente
        "estado": "Aprobado" if es_admin else "Pendiente",
        "fecha_texto": ahora_texto(),
        "creado_ts": time.time(),
    }

    db.collection("comentarios").add(comentario)

    if es_admin:
        notificar_comentario_aprobado(comentario, avisar_autor=False)
        mensaje = "Comentario publicado."
    else:
        notificar_comentario_nuevo(comentario)
        mensaje = "Comentario enviado. Se publicará cuando el administrador lo apruebe."

    return jsonify({"ok": True, "mensaje": mensaje, "estado": comentario["estado"]})


@app.route("/comentarios/eliminar/<comentario_id>", methods=["POST"])
def eliminar_comentario(comentario_id):

    if "usuario" not in session:
        return jsonify({"ok": False, "error": "Inicia sesión."}), 401

    ref = db.collection("comentarios").document(comentario_id)
    doc = ref.get()

    if not doc.exists:
        return jsonify({"ok": False, "error": "El comentario ya no existe."}), 404

    c = doc.to_dict()

    if c.get("autor_correo") != session.get("usuario") and session.get("rol") != "admin":
        return jsonify({"ok": False, "error": "No puedes eliminar este comentario."}), 403

    ref.delete()
    return jsonify({"ok": True})


@app.route("/admin/comentarios")
def admin_comentarios():

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    filtro = request.args.get("estado", "Pendiente")
    if filtro not in ("Pendiente", "Aprobado", "Rechazado", "Todos"):
        filtro = "Pendiente"

    conteo = {"Pendiente": 0, "Aprobado": 0, "Rechazado": 0}
    comentarios = []

    for doc in db.collection("comentarios").stream():
        c = doc.to_dict()
        c["id"] = doc.id
        estado = c.get("estado", "Pendiente")
        conteo[estado] = conteo.get(estado, 0) + 1

        if filtro == "Todos" or estado == filtro:
            comentarios.append(c)

    comentarios.sort(key=lambda x: x.get("creado_ts", 0), reverse=True)

    return render_template(
        "admin/comentarios.html",
        comentarios=comentarios,
        filtro=filtro,
        conteo=conteo
    )


def _volver_comentarios():
    destino = request.form.get("volver", "")
    return destino if destino.startswith("/admin/comentarios") else "/admin/comentarios"


def _cambiar_estado_comentario(comentario_id, nuevo_estado):
    ref = db.collection("comentarios").document(comentario_id)
    doc = ref.get()

    if not doc.exists:
        flash("El comentario ya no existe.", "warning")
        return None

    c = doc.to_dict()
    ref.update({
        "estado": nuevo_estado,
        "revisado_por": session.get("usuario"),
        "fecha_revision": ahora_texto(),
    })
    c["estado"] = nuevo_estado
    return c


@app.route("/admin/comentarios/aprobar/<comentario_id>", methods=["POST"])
def aprobar_comentario(comentario_id):

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    c = _cambiar_estado_comentario(comentario_id, "Aprobado")

    if c:
        notificar_comentario_aprobado(c)
        flash("Comentario aprobado. Se avisó al dueño del reporte y al autor.", "success")

    return redirect(_volver_comentarios())


@app.route("/admin/comentarios/rechazar/<comentario_id>", methods=["POST"])
def rechazar_comentario(comentario_id):

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    c = _cambiar_estado_comentario(comentario_id, "Rechazado")

    if c:
        notificar_comentario_rechazado(c)
        flash("Comentario rechazado. Se avisó al autor.", "success")

    return redirect(_volver_comentarios())


@app.route("/admin/comentarios/eliminar/<comentario_id>", methods=["POST"])
def admin_eliminar_comentario(comentario_id):

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    db.collection("comentarios").document(comentario_id).delete()
    flash("Comentario eliminado.", "success")
    return redirect(_volver_comentarios())


# ======================
# PERFIL: preferencias, quitar foto y eliminar cuenta
# ======================
def _render_perfil(usuario_ref, **extra):
    usuario = usuario_ref.get().to_dict()
    total = len(list(db.collection("reportes").where("usuario", "==", session.get("usuario")).stream()))
    return render_template("usuario/perfil.html", usuario=usuario, total_reportes=total, **extra)


@app.route("/perfil/preferencias", methods=["POST"])
def perfil_preferencias():

    if "usuario" not in session or not session.get("user_id"):
        return redirect("/login")

    ref = db.collection("usuarios").document(session["user_id"])
    ref.update({"notif_correo": request.form.get("notif_correo") == "on"})

    return _render_perfil(ref, exito="Preferencias guardadas.")


@app.route("/perfil/quitar_foto", methods=["POST"])
def perfil_quitar_foto():

    if "usuario" not in session or not session.get("user_id"):
        return redirect("/login")

    user_id = session["user_id"]
    ref = db.collection("usuarios").document(user_id)

    try:
        cloudinary.uploader.destroy(f"saferoutemx/perfiles/perfil_{user_id}")
    except Exception as e:
        print("ERROR BORRANDO FOTO:", e, flush=True)

    ref.update({"foto_perfil": ""})
    session["foto_perfil"] = ""

    return _render_perfil(ref, exito="Foto de perfil eliminada.")


@app.route("/perfil/eliminar_cuenta", methods=["POST"])
def perfil_eliminar_cuenta():

    if "usuario" not in session or not session.get("user_id"):
        return redirect("/login")

    user_id = session["user_id"]
    ref = db.collection("usuarios").document(user_id)
    doc = ref.get()

    if not doc.exists:
        session.clear()
        return redirect("/login")

    usuario = doc.to_dict()
    correo = (usuario.get("correo") or "").strip().lower()

    if login_bloqueado(usuario):
        return _render_perfil(ref, error="Demasiados intentos fallidos. Espera 15 minutos e inténtalo de nuevo.")

    password = request.form.get("password", "")
    confirmacion = request.form.get("confirmacion", "").strip().upper()

    if confirmacion != "ELIMINAR":
        return _render_perfil(ref, error='Para eliminar tu cuenta escribe la palabra ELIMINAR en el cuadro de confirmación.')

    if not check_password_hash(usuario.get("password", ""), password):
        registrar_fallo_login(ref, usuario)
        return _render_perfil(ref, error="La contraseña es incorrecta. Tu cuenta no fue eliminada.")

    if usuario.get("rol") == "admin":
        admins = list(db.collection("usuarios").where("rol", "==", "admin").stream())
        if len(admins) <= 1:
            return _render_perfil(ref, error="Eres el único administrador. Asigna a otro administrador antes de eliminar tu cuenta.")

    nombre = usuario.get("nombre", "")

    # Reportes y comentarios de la cuenta
    for reporte in db.collection("reportes").where("usuario", "==", correo).stream():
        borrar_comentarios_de_reporte(reporte.id)
        reporte.reference.delete()

    borrar_comentarios_de_usuario(correo)

    try:
        cloudinary.uploader.destroy(f"saferoutemx/perfiles/perfil_{user_id}")
    except Exception as e:
        print("ERROR BORRANDO FOTO:", e, flush=True)

    ref.delete()
    session.clear()

    threading.Thread(
        target=enviar_correo_simple,
        args=(
            correo,
            nombre,
            "Tu cuenta fue eliminada - SafeRoute MX",
            f"""
            <h2>Hola {esc(nombre or 'Usuario SafeRoute')}</h2>
            <p>Tu cuenta de SafeRoute MX, junto con tus reportes y comentarios, fue eliminada correctamente.</p>
            <p>Si no fuiste tú quien lo hizo, comunícate con el administrador.</p>
            """
        ),
        daemon=True
    ).start()

    return render_template("login.html", exito="Tu cuenta fue eliminada correctamente.")


@app.route("/chatbot")
def chatbot():

    if "usuario" not in session:
        return redirect("/login")

    usuario = None
    user_id = session.get("user_id")

    if user_id:
        usuario_doc = db.collection("usuarios").document(user_id).get()

        if usuario_doc.exists:
            usuario = usuario_doc.to_dict()
            usuario["id"] = usuario_doc.id

    return render_template("usuario/chatbot.html", usuario=usuario)

@app.route("/chatbot/preguntar", methods=["POST"])
def chatbot_preguntar():

    if "usuario" not in session:
        return jsonify({"respuesta": "Debes iniciar sesión para usar SafeRoute IA."})

    pregunta_original = request.form.get("pregunta", "").strip()
    pregunta = pregunta_original.lower()

    pregunta = (
        pregunta.replace("á", "a")
        .replace("é", "e")
        .replace("í", "i")
        .replace("ó", "o")
        .replace("ú", "u")
        .replace("¿", "")
        .replace("?", "")
        .replace("¡", "")
        .replace("!", "")
    )

    rol = session.get("rol")
    usuario_actual = session.get("usuario")
    nombre_usuario = session.get("nombre", "usuario")

    def contiene(*palabras):
        return any(palabra in pregunta for palabra in palabras)

    def normalizar_gravedad(texto):
        texto = texto.lower().strip()

        if "alta" in texto or "alto" in texto:
            return "Alta"
        if "media" in texto or "medio" in texto:
            return "Media"
        if "baja" in texto or "bajo" in texto:
            return "Baja"

        return ""

    # ======================================================
    # CREAR REPORTE DESDE CHATBOT
    # ======================================================
    if "chatbot_reporte" in session:
        flujo = session["chatbot_reporte"]
        paso = flujo.get("paso")

        if contiene("cancelar", "salir", "detener"):
            session.pop("chatbot_reporte", None)
            return jsonify({
                "respuesta": "Creación de reporte cancelada. Puedes iniciar otra vez escribiendo: crear reporte."
            })

        if paso == "tipo":
            flujo["tipo"] = pregunta_original
            flujo["paso"] = "descripcion"
            session["chatbot_reporte"] = flujo

            return jsonify({
                "respuesta": "Perfecto. Ahora describe qué ocurrió. Ejemplo: Me robaron cerca del parque."
            })

        if paso == "descripcion":
            flujo["descripcion"] = pregunta_original
            flujo["paso"] = "ubicacion"
            session["chatbot_reporte"] = flujo

            return jsonify({
                "respuesta": "Ahora escribe la ubicación aproximada del incidente. Ejemplo: Centro, cerca del parque principal."
            })

        if paso == "ubicacion":
            flujo["ubicacion"] = pregunta_original
            flujo["paso"] = "gravedad"
            session["chatbot_reporte"] = flujo

            return jsonify({
                "respuesta": "Por último, indica la gravedad: Alta, Media o Baja."
            })

        if paso == "gravedad":
            gravedad = normalizar_gravedad(pregunta_original)

            if gravedad == "":
                return jsonify({
                    "respuesta": "No entendí la gravedad. Responde solamente: Alta, Media o Baja."
                })

            flujo["gravedad"] = gravedad

            reporte = {
                "tipo": flujo.get("tipo", "Reporte"),
                "descripcion": flujo.get("descripcion", "Sin descripción"),
                "fecha": datetime.now().strftime("%Y-%m-%d"),
                "ubicacion": flujo.get("ubicacion", "Sin ubicación"),
                "gravedad": gravedad,

                # Como el chatbot no usa mapa, se guardan coordenadas neutras.
                # El usuario puede editar después el reporte desde Mis Reportes.
                "latitud": 0.0,
                "longitud": 0.0,

                "usuario": session.get("usuario"),
                "nombre_usuario": session.get("nombre"),
                "foto_usuario": session.get("foto_perfil", ""),
                "foto_reporte": "",

                "aprobado": False,
                "estado": "Pendiente",
                "seguimiento": "Sin seguimiento",
                "comentario_admin": "",
                "fecha_actualizacion": "",
                "creado_desde": "chatbot",
                "requiere_ubicacion_mapa": True
            }

            db.collection("reportes").add(reporte)
            avisar_reporte_por_correo(reporte)
            session.pop("chatbot_reporte", None)

            return jsonify({
                "respuesta": (
                    "Listo. He creado tu reporte desde el chatbot.\n\n"
                    f"Tipo: {reporte['tipo']}\n"
                    f"Ubicación: {reporte['ubicacion']}\n"
                    f"Gravedad: {reporte['gravedad']}\n"
                    f"Estado: {reporte['estado']}\n\n"
                    "Importante: como fue creado desde el chatbot, no tiene punto exacto en el mapa. "
                    "Puedes entrar a Mis Reportes y editarlo para agregar la ubicación exacta."
                )
            })

    if contiene("crear reporte", "hacer reporte", "levantar reporte", "generar reporte", "nuevo reporte desde chatbot"):
        session["chatbot_reporte"] = {
            "paso": "tipo"
        }

        return jsonify({
            "respuesta": (
                "Claro. Vamos a crear un reporte.\n\n"
                "Primero dime el tipo de incidente.\n"
                "Ejemplos: Robo, Asalto, Accidente, Zona peligrosa, Vandalismo.\n\n"
                "Puedes escribir 'cancelar' si quieres detener el proceso."
            )
        })

    # ======================================================
    # CONSULTAR DATOS
    # ======================================================
    reportes_docs = list(db.collection("reportes").stream())
    usuarios_docs = list(db.collection("usuarios").stream())

    reportes = []
    usuarios = []

    for doc in reportes_docs:
        r = doc.to_dict()
        r["id"] = doc.id
        reportes.append(r)

    for doc in usuarios_docs:
        u = doc.to_dict()
        u["id"] = doc.id
        usuarios.append(u)

    mis_reportes = [r for r in reportes if r.get("usuario") == usuario_actual]

    total_reportes = len(reportes)
    total_usuarios = len(usuarios)
    total_mis_reportes = len(mis_reportes)

    def contar(lista, campo):
        datos = {}
        for item in lista:
            valor = item.get(campo, "Sin dato") or "Sin dato"
            datos[valor] = datos.get(valor, 0) + 1
        return datos

    def top(diccionario):
        if not diccionario:
            return None, 0
        clave = max(diccionario, key=diccionario.get)
        return clave, diccionario[clave]

    reportes_alto = sum(1 for r in reportes if r.get("gravedad") == "Alta")
    reportes_medio = sum(1 for r in reportes if r.get("gravedad") == "Media")
    reportes_bajo = sum(1 for r in reportes if r.get("gravedad") == "Baja")

    mis_alto = sum(1 for r in mis_reportes if r.get("gravedad") == "Alta")
    mis_medio = sum(1 for r in mis_reportes if r.get("gravedad") == "Media")
    mis_bajo = sum(1 for r in mis_reportes if r.get("gravedad") == "Baja")

    mis_pendientes = sum(1 for r in mis_reportes if r.get("estado", "Pendiente") == "Pendiente")
    mis_aprobados = sum(1 for r in mis_reportes if r.get("estado") == "Aprobado" or r.get("aprobado") == True)
    mis_rechazados = sum(1 for r in mis_reportes if r.get("estado") == "Rechazado")
    mis_seguimiento = sum(1 for r in mis_reportes if r.get("estado") == "En seguimiento")
    mis_resueltos = sum(1 for r in mis_reportes if r.get("estado") == "Resuelto")

    zonas = contar(reportes, "ubicacion")
    tipos = contar(reportes, "tipo")
    mis_zonas = contar(mis_reportes, "ubicacion")
    mis_tipos = contar(mis_reportes, "tipo")
    usuarios_reportes = contar(reportes, "usuario")

    zonas_alto = {}
    for r in reportes:
        if r.get("gravedad") == "Alta":
            ubicacion = r.get("ubicacion", "Sin ubicación") or "Sin ubicación"
            zonas_alto[ubicacion] = zonas_alto.get(ubicacion, 0) + 1

    zona_mas_reportada, total_zona_mas_reportada = top(zonas)
    zona_mas_alta, total_zona_mas_alta = top(zonas_alto)
    tipo_mas_comun, total_tipo_mas_comun = top(tipos)
    mi_zona_mas_reportada, total_mi_zona_mas_reportada = top(mis_zonas)
    mi_tipo_mas_comun, total_mi_tipo_mas_comun = top(mis_tipos)
    usuario_mas_activo, total_usuario_mas_activo = top(usuarios_reportes)

    ultimo_reporte = mis_reportes[-1] if mis_reportes else None

    respuesta = (
        "Puedo ayudarte con SafeRoute MX.\n\n"
        "Puedes preguntarme:\n"
        "• Crear reporte\n"
        "• ¿Cuántos reportes tengo?\n"
        "• ¿Cuál fue mi último reporte?\n"
        "• ¿Mi reporte lleva seguimiento?\n"
        "• ¿Qué zonas debo evitar?\n"
        "• Dame recomendaciones de seguridad\n"
        "• ¿Cómo funciona el mapa?"
    )

    # ======================================================
    # RESPUESTAS GENERALES
    # ======================================================
    if contiene("hola", "buenas", "buenos dias", "buenas tardes", "buenas noches"):
        respuesta = (
            f"Hola, {nombre_usuario}. Soy SafeRoute IA.\n\n"
            "Puedo ayudarte a crear reportes, revisar tus reportes, consultar zonas de riesgo, "
            "explicar el mapa y darte recomendaciones de seguridad."
        )

    elif contiene("que puedo preguntarte", "ayuda", "que haces", "que puedes hacer"):
        respuesta = (
            "Puedes preguntarme cosas como:\n\n"
            "• Crear reporte\n"
            "• ¿Cuántos reportes tengo registrados?\n"
            "• ¿Cuál fue mi último reporte?\n"
            "• ¿Mi reporte lleva seguimiento?\n"
            "• ¿Qué zonas debo evitar?\n"
            "• ¿Cómo funciona el mapa?\n"
            "• Dame recomendaciones de seguridad\n"
            "• ¿Cómo puedo editar o eliminar un reporte?\n"
            "• ¿Cómo protege mis datos SafeRoute MX?"
        )

    elif contiene("gracias"):
        respuesta = "Con gusto. Estoy aquí para ayudarte a usar SafeRoute MX."

    elif contiene("que es saferoute", "para que sirve", "safe route"):
        respuesta = (
            "SafeRoute MX es una plataforma de reportes ciudadanos de seguridad.\n\n"
            "Permite registrar incidentes, consultar zonas de riesgo en el mapa y dar seguimiento a reportes."
        )

    elif contiene("como reporto", "como puedo reportar", "reportar incidente", "nuevo incidente"):
        respuesta = (
            "Puedes reportar de dos formas:\n\n"
            "1. Desde el botón Reportar, seleccionando ubicación exacta en el mapa.\n"
            "2. Desde este chatbot escribiendo: crear reporte.\n\n"
            "Recomendación: para que aparezca bien en el mapa, usa el formulario de Reportar porque permite seleccionar coordenadas exactas."
        )

    elif contiene("mapa", "como funciona el mapa"):
        respuesta = (
            "El mapa muestra reportes aprobados por la administración.\n\n"
            "Colores:\n"
            "• Rojo: riesgo alto.\n"
            "• Amarillo: riesgo medio.\n"
            "• Verde: riesgo bajo.\n\n"
            "Sirve para revisar zonas antes de salir."
        )

    elif contiene("cuantos reportes tengo", "mis reportes", "total de mis reportes"):
        respuesta = (
            f"Tienes {total_mis_reportes} reportes registrados.\n\n"
            f"• Riesgo alto: {mis_alto}\n"
            f"• Riesgo medio: {mis_medio}\n"
            f"• Riesgo bajo: {mis_bajo}"
        )

    elif contiene("ultimo reporte", "reporte mas reciente"):
        if ultimo_reporte:
            respuesta = (
                "Tu último reporte es:\n\n"
                f"Tipo: {ultimo_reporte.get('tipo', 'Sin tipo')}\n"
                f"Ubicación: {ultimo_reporte.get('ubicacion', 'Sin ubicación')}\n"
                f"Gravedad: {ultimo_reporte.get('gravedad', 'Sin gravedad')}\n"
                f"Estado: {ultimo_reporte.get('estado', 'Pendiente')}\n"
                f"Seguimiento: {ultimo_reporte.get('seguimiento', 'Sin seguimiento')}\n"
                f"Descripción: {ultimo_reporte.get('descripcion', 'Sin descripción')}"
            )
        else:
            respuesta = "Todavía no tienes reportes registrados."

    elif contiene("mi actividad", "resumen de mi actividad", "resumen de mis reportes"):
        respuesta = (
            "Resumen de tu actividad:\n\n"
            f"Total de reportes: {total_mis_reportes}\n"
            f"Pendientes: {mis_pendientes}\n"
            f"Aprobados: {mis_aprobados}\n"
            f"Rechazados: {mis_rechazados}\n"
            f"En seguimiento: {mis_seguimiento}\n"
            f"Resueltos: {mis_resueltos}\n\n"
            f"Riesgo alto: {mis_alto}\n"
            f"Riesgo medio: {mis_medio}\n"
            f"Riesgo bajo: {mis_bajo}"
        )

        if mi_zona_mas_reportada:
            respuesta += f"\nZona donde más reportas: {mi_zona_mas_reportada}"

        if mi_tipo_mas_comun:
            respuesta += f"\nIncidente que más reportas: {mi_tipo_mas_comun}"

    elif contiene("seguimiento", "estado de mis reportes", "mi reporte lleva seguimiento"):
        if total_mis_reportes == 0:
            respuesta = "Todavía no tienes reportes registrados."
        else:
            respuesta = (
                "Estado de tus reportes:\n\n"
                f"Pendientes: {mis_pendientes}\n"
                f"Aprobados: {mis_aprobados}\n"
                f"Rechazados: {mis_rechazados}\n"
                f"En seguimiento: {mis_seguimiento}\n"
                f"Resueltos: {mis_resueltos}\n\n"
                "Puedes revisar más detalles en Mis Reportes."
            )

    elif contiene("zona mas peligrosa", "zonas debo evitar", "zona mas conflictiva"):
        if zona_mas_alta:
            respuesta = (
                f"La zona con más reportes de riesgo alto es {zona_mas_alta}.\n\n"
                f"Tiene {total_zona_mas_alta} reportes de riesgo alto.\n\n"
                "Recomendación: evita pasar por esa zona si no es necesario."
            )
        elif zona_mas_reportada:
            respuesta = (
                f"La zona con más reportes es {zona_mas_reportada}, con {total_zona_mas_reportada} reportes."
            )
        else:
            respuesta = "Aún no hay suficientes reportes para identificar zonas peligrosas."

    elif contiene("recomendaciones", "consejos", "seguridad", "caminar seguro", "evitar robos"):
        respuesta = (
            "Recomendaciones de seguridad:\n\n"
            "• Revisa el mapa antes de salir.\n"
            "• Evita calles solas o con poca iluminación.\n"
            "• No uses el celular en zonas de riesgo.\n"
            "• Comparte tu ubicación con alguien de confianza.\n"
            "• Reporta incidentes para ayudar a la comunidad.\n"
            "• En emergencia real llama al 911."
        )

    elif contiene("emergencia", "911", "peligro", "me asaltan", "accidente"):
        respuesta = (
            "Si estás en una emergencia real, llama al 911.\n\n"
            "Después, si estás seguro, puedes registrar el incidente en SafeRoute MX para alertar a la comunidad."
        )

    elif contiene("privacidad", "datos", "protege mis datos"):
        respuesta = (
            "SafeRoute MX protege tus datos de esta forma:\n\n"
            "• La contraseña se guarda cifrada.\n"
            "• Las imágenes se almacenan en Cloudinary.\n"
            "• Firestore guarda los datos del sistema.\n"
            "• Los reportes se muestran públicamente solo si son aprobados."
        )

    elif contiene("editar reporte", "eliminar reporte", "borrar reporte"):
        respuesta = (
            "Para editar o eliminar un reporte:\n\n"
            "1. Entra a Mis Reportes.\n"
            "2. Busca el reporte.\n"
            "3. Usa el botón Editar o Eliminar.\n\n"
            "Si el reporte ya fue revisado, puede requerir nueva revisión."
        )

    # ======================================================
    # ADMIN
    # ======================================================
    if rol == "admin":

        if contiene("cuantos usuarios", "usuarios registrados"):
            respuesta = f"Actualmente hay {total_usuarios} usuarios registrados."

        elif contiene("cuantos reportes existen", "reportes totales", "cuantos reportes hay"):
            respuesta = f"Actualmente hay {total_reportes} reportes registrados en el sistema."

        elif contiene("cuantos reportes de riesgo alto", "riesgo alto hay"):
            respuesta = f"Actualmente hay {reportes_alto} reportes de riesgo alto."

        elif contiene("resumen general", "resumen del sistema"):
            respuesta = (
                "Resumen general del sistema:\n\n"
                f"Usuarios registrados: {total_usuarios}\n"
                f"Reportes totales: {total_reportes}\n"
                f"Riesgo alto: {reportes_alto}\n"
                f"Riesgo medio: {reportes_medio}\n"
                f"Riesgo bajo: {reportes_bajo}"
            )

            if zona_mas_reportada:
                respuesta += f"\nZona con más reportes: {zona_mas_reportada}"

            if tipo_mas_comun:
                respuesta += f"\nIncidente más común: {tipo_mas_comun}"

        elif contiene("usuario mas activo", "quien reporta mas"):
            if usuario_mas_activo:
                respuesta = (
                    "El usuario con más reportes es:\n\n"
                    f"Usuario: {usuario_mas_activo}\n"
                    f"Reportes: {total_usuario_mas_activo}"
                )
            else:
                respuesta = "Aún no hay reportes suficientes para identificar al usuario más activo."

        elif contiene("que puedo hacer como admin", "panel admin"):
            respuesta = (
                "Como administrador puedes:\n\n"
                "• Aprobar o rechazar reportes.\n"
                "• Dar seguimiento a reportes.\n"
                "• Actualizar estados.\n"
                "• Revisar usuarios registrados.\n"
                "• Ver estadísticas.\n"
                "• Consultar el mapa administrativo."
            )

    return jsonify({"respuesta": respuesta})

@app.route("/admin/usuarios/rol/<user_id>", methods=["POST"])
def cambiar_rol_usuario(user_id):
    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    nuevo_rol = request.form.get("rol", "").strip().lower()

    if nuevo_rol not in ["usuario", "admin"]:
        return redirect("/admin/usuarios")

    db.collection("usuarios").document(user_id).update({
        "rol": nuevo_rol
    })

    # Si cambiaste tu propio rol, actualiza la sesión
    if user_id == session.get("user_id"):
        session["rol"] = nuevo_rol

        if nuevo_rol == "usuario":
            return redirect("/dashboard")

    return redirect("/admin/usuarios")
# ======================
# LOGOUT
# ======================
# ======================
# TOKEN DEL DISPOSITIVO (lo manda la app Android)
# ======================
@app.route("/api/token", methods=["POST"])
def registrar_token_dispositivo():
    if "usuario" not in session or not session.get("user_id"):
        return jsonify({"ok": False, "error": "sin sesion"}), 401

    datos = request.get_json(silent=True) or {}
    token = str(datos.get("token", "")).strip()

    if not token:
        return jsonify({"ok": False, "error": "sin token"}), 400

    db.collection("usuarios").document(session["user_id"]).update({
        "fcm_tokens": firestore.ArrayUnion([token])
    })
    return jsonify({"ok": True})


# ======================
# REGISTRO DEL RELOJ (la app Wear OS manda correo + contraseña + token)
# ======================
@app.route("/api/token_reloj", methods=["POST"])
def registrar_token_reloj():
    datos = request.get_json(silent=True) or {}
    correo = str(datos.get("correo", "")).strip().lower()
    password = str(datos.get("password", "")).strip()
    token = str(datos.get("token", "")).strip()

    if not correo or not password or not token:
        return jsonify({"ok": False, "error": "Faltan datos"}), 400

    for doc in buscar_usuarios_por_correo(correo):
        usuario = doc.to_dict()
        doc_ref = db.collection("usuarios").document(doc.id)

        if login_bloqueado(usuario):
            return jsonify({"ok": False, "error": "Demasiados intentos. Espera 15 minutos."}), 429

        if not check_password_hash(usuario.get("password", ""), password):
            registrar_fallo_login(doc_ref, usuario)
            break

        if not usuario.get("verificado", False):
            return jsonify({"ok": False, "error": "Cuenta sin verificar"}), 403

        limpiar_fallos_login(doc_ref, usuario)

        db.collection("usuarios").document(doc.id).update({
            "fcm_tokens": firestore.ArrayUnion([token])
        })
        enviar_push_a_usuario(correo, "SafeRoute MX", "Reloj conectado correctamente")
        return jsonify({"ok": True})

    return jsonify({"ok": False, "error": "Correo o contraseña incorrectos"}), 401


@app.route("/api/probar_push")
def probar_push():
    if "usuario" not in session:
        return redirect("/login")

    enviar_push_a_usuario(
        session["usuario"],
        "SafeRoute MX",
        "Notificación de prueba. Si la ves, todo funciona."
    )
    return jsonify({"ok": True, "mensaje": "Push de prueba enviado"})


@app.route("/logout")
def logout():

    user_id = session.get("user_id")
    token_local = session.get("token_sesion")

    if user_id and token_local:
        usuario_ref = db.collection("usuarios").document(user_id)
        usuario_doc = usuario_ref.get()

        if usuario_doc.exists:
            token_guardado = usuario_doc.to_dict().get(
                "token_sesion_activa"
            )

            if token_guardado == token_local:
                usuario_ref.update({
                    "token_sesion_activa": firestore.DELETE_FIELD
                })

    session.clear()

    respuesta = redirect("/login")

    respuesta.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, private, max-age=0"
    )
    respuesta.headers["Pragma"] = "no-cache"
    respuesta.headers["Expires"] = "0"
    # Pide al navegador borrar su caché del sitio: así la flecha "atrás"
    # ya no puede mostrar páginas privadas guardadas.
    respuesta.headers["Clear-Site-Data"] = '"cache"'

    return respuesta

# ======================
# RUN
# ======================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
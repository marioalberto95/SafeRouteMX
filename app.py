from flask import Flask, render_template, request, redirect, session, jsonify, flash
import re
from flask_mail import Mail, Message
import random
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
from firebase_admin import credentials, firestore
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
from datetime import datetime
app = Flask(__name__)
app.secret_key = "saferoute_secret_key"

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
UPLOAD_FOLDER = "static/uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
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
            <h2>Hola {nombre or "Usuario SafeRoute"}</h2>
            <p>Tu reporte ha sido actualizado por el administrador.</p>

            <h3>Detalles del reporte</h3>
            <p><b>Tipo:</b> {reporte.get("tipo", "Sin tipo")}</p>
            <p><b>Ubicación:</b> {reporte.get("ubicacion", "Sin ubicación")}</p>
            <p><b>Gravedad:</b> {reporte.get("gravedad", "Sin gravedad")}</p>

            <h3>Estado actual</h3>
            <p><b>Estado:</b> {estado}</p>
            <p><b>Seguimiento:</b> {seguimiento}</p>
            <p><b>Comentario del administrador:</b> {comentario or "Sin comentario"}</p>

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
        "no-store, no-cache, must-revalidate, max-age=0"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

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
# INICIO
# ======================
@app.route("/")
def inicio():
    return render_template("index.html")
# ======================
# LOGIN
# ======================
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not correo or not password:
            return render_template(
                "login.html",
                error="Ingresa tu correo y contraseña."
            )

        usuarios = db.collection("usuarios").stream()

        for doc in usuarios:
            usuario = doc.to_dict()

            correo_db = usuario.get("correo", "").strip().lower()
            password_db = usuario.get("password", "")
            rol_db = usuario.get("rol", "usuario").strip().lower()

            if correo_db == correo and check_password_hash(password_db, password):

                if not usuario.get("verificado", False):
                    session.clear()
                    session["correo_verificacion"] = correo_db

                    return render_template(
                        "verificar_codigo.html",
                        error="Debes verificar tu correo antes de iniciar sesión."
                    )

                # Elimina cualquier sesión anterior del navegador actual
                session.clear()

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
                db.collection("usuarios").document(doc.id).update({
                    "token_sesion_activa": token_sesion,
                    "fecha_ultimo_login": firestore.SERVER_TIMESTAMP
                })

                if rol_db == "admin":
                    return redirect("/admin")

                return redirect("/dashboard")

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

        usuarios = db.collection("usuarios").where("correo", "==", correo).stream()

        usuario_doc = None
        usuario = None

        for doc in usuarios:
            usuario_doc = doc
            usuario = doc.to_dict()
            break

        if not usuario_doc:
            return render_template(
                "recuperar_password.html",
                error="No existe una cuenta registrada con ese correo."
            )

        codigo = str(random.randint(100000, 999999))

        db.collection("usuarios").document(usuario_doc.id).update({
            "codigo_recuperacion": codigo
        })

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

        usuarios = db.collection("usuarios").where("correo", "==", correo).stream()

        for doc in usuarios:
            usuario = doc.to_dict()

            if usuario.get("codigo_recuperacion") != codigo:
                return render_template(
                    "restablecer_password.html",
                    error="El código ingresado no es correcto."
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

            db.collection("usuarios").document(doc.id).update({
                "password": generate_password_hash(password_nueva),
                "codigo_recuperacion": ""
            })

            session.pop("correo_recuperacion", None)

            return render_template(
                "login.html",
                exito="Contraseña actualizada correctamente. Ya puedes iniciar sesión."
            )

    return render_template("restablecer_password.html")

# ======================
# REGISTRO USUARIO
# ======================
@app.route("/registro", methods=["GET", "POST"])
def registro():

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

        if not re.match(patron_password, password):
            return render_template("registro.html", error="La contraseña debe tener mínimo 8 caracteres, una mayúscula, una minúscula, un número y un símbolo.")

        if password != confirmar:
            return render_template("registro.html", error="Las contraseñas no coinciden.")

        usuarios = db.collection("usuarios").where("correo", "==", correo).stream()

        for doc in usuarios:
            return render_template("registro.html", error="Este correo ya está registrado.")

        codigo = str(random.randint(100000, 999999))

        usuario = {
            "nombre": nombre,
            "correo": correo,
            "password": generate_password_hash(password),
            "rol": "usuario",
            "verificado": False,
            "codigo_verificacion": codigo
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
                <h2>Hola {nombre}</h2>
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

        usuarios = db.collection("usuarios").where("correo", "==", correo).stream()

        for doc in usuarios:
            usuario = doc.to_dict()

            if usuario.get("codigo_verificacion") == codigo:

                db.collection("usuarios").document(doc.id).update({
                    "verificado": True,
                    "codigo_verificacion": ""
                })

                session.pop("correo_verificacion", None)

                return render_template(
                    "login.html",
                    exito="Correo verificado correctamente. Ya puedes iniciar sesión."
                )

        return render_template(
            "verificar_codigo.html",
            error="El código ingresado no es correcto."
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
        tipo = request.form.get("tipo", "").strip()
        descripcion = request.form.get("descripcion", "").strip()
        fecha = request.form.get("fecha", "").strip()
        ubicacion = request.form.get("ubicacion", "").strip()
        gravedad = request.form.get("gravedad", "").strip()
        latitud = request.form.get("latitud")
        longitud = request.form.get("longitud")

        foto_reporte = request.files.get("foto_reporte")
        url_foto_reporte = ""

        if not latitud or not longitud:
            return render_template(
                "usuario/reportar.html",
                exito=False,
                error="Debes seleccionar una ubicación en el mapa."
            )

        if foto_reporte and foto_reporte.filename != "":
            if not foto_reporte.mimetype.startswith("image/"):
                return render_template(
                    "usuario/reportar.html",
                    exito=False,
                    error="El archivo debe ser una imagen."
                )

            resultado = cloudinary.uploader.upload(
                foto_reporte,
                folder="saferoutemx/reportes",
                resource_type="image"
            )
            url_foto_reporte = resultado.get("secure_url")

        reporte = {
            "tipo": tipo,
            "descripcion": descripcion,
            "fecha": fecha,
            "ubicacion": ubicacion,
            "gravedad": gravedad,
            "latitud": float(latitud),
            "longitud": float(longitud),
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

    return redirect("/admin/reportes")

@app.route("/admin/reportes/eliminar/<id>", methods=["POST"])
def eliminar_reporte(id):

    if "usuario" not in session:
        return redirect("/login")

    if session.get("rol") != "admin":
        return redirect("/dashboard")

    db.collection("reportes").document(id).delete()

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
            reporte.reference.delete()

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

        if not latitud or not longitud:
            reporte["id"] = doc.id

            return render_template(
                "usuario/editar_reporte.html",
                reporte=reporte,
                error="Debes seleccionar una ubicación válida en el mapa."
            )

        foto_reporte = request.files.get("foto_reporte")
        url_foto_reporte = reporte.get("foto_reporte", "")

        if foto_reporte and foto_reporte.filename != "":

            if not foto_reporte.mimetype.startswith("image/"):
                reporte["id"] = doc.id

                return render_template(
                    "usuario/editar_reporte.html",
                    reporte=reporte,
                    error="El archivo seleccionado debe ser una imagen."
                )

            resultado = cloudinary.uploader.upload(
                foto_reporte,
                folder="saferoutemx/reportes",
                resource_type="image"
            )

            url_foto_reporte = resultado.get("secure_url")

        datos_actualizados = {
            "tipo": request.form.get("tipo", "").strip(),
            "descripcion": request.form.get("descripcion", "").strip(),
            "fecha": request.form.get("fecha", "").strip(),
            "ubicacion": request.form.get("ubicacion", "").strip(),
            "gravedad": request.form.get("gravedad", "").strip(),
            "latitud": float(latitud),
            "longitud": float(longitud),
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

        datos_actualizados = {
            "nombre": nombre
        }

        session["nombre"] = nombre

        if foto and foto.filename != "":

            if not foto.mimetype.startswith("image/"):
                return render_template(
                    "usuario/perfil.html",
                    usuario=usuario,
                    total_reportes=contar_reportes(),
                    error="El archivo seleccionado debe ser una imagen."
                )

            resultado = cloudinary.uploader.upload(
                foto,
                folder="saferoutemx/perfiles",
                public_id=f"perfil_{user_id}",
                overwrite=True,
                resource_type="image"
            )

            ruta_foto = resultado.get("secure_url")

            datos_actualizados["foto_perfil"] = ruta_foto
            session["foto_perfil"] = ruta_foto

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
    codigo = str(random.randint(100000, 999999))

    usuario_ref.update({
        "codigo_cambio_password": codigo
    })

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

    user_id = session.get("cambio_password_user_id") or session.get("user_id")

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

    if usuario.get("codigo_cambio_password") != codigo:
        return render_template(
            "usuario/verificar_cambio_password.html",
            error="El código ingresado no es correcto."
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

    usuario_ref.update({
        "password": generate_password_hash(password_nueva),
        "codigo_cambio_password": ""
    })

    session.pop("cambio_password_user_id", None)

    return render_template(
        "usuario/perfil.html",
        usuario=usuario_ref.get().to_dict(),
        total_reportes=len(list(db.collection("reportes").where("usuario", "==", session.get("usuario")).stream())),
        exito="Contraseña actualizada correctamente."
    )
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
        "no-store, no-cache, must-revalidate, max-age=0"
    )
    respuesta.headers["Pragma"] = "no-cache"
    respuesta.headers["Expires"] = "0"

    return respuesta



# ======================
# RUN
# ======================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
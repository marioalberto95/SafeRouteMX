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
import requests
app = Flask(__name__)
app.secret_key = "saferoute_secret_key"
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
                    session["correo_verificacion"] = correo_db
                    return render_template(
                        "verificar_codigo.html",
                        error="Debes verificar tu correo antes de iniciar sesión."
                    )

                session["usuario"] = correo_db
                session["nombre"] = usuario.get("nombre", "")
                session["rol"] = rol_db
                session["user_id"] = doc.id

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

        usuarios = db.collection("usuarios").stream()

        for doc in usuarios:
            usuario_existente = doc.to_dict()

            if usuario_existente.get("correo", "").strip().lower() == correo:
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

        db.collection("usuarios").add(usuario)
        session["correo_verificacion"] = correo

        demo_mode = os.environ.get("DEMO_MODE", "").strip().lower()

        if demo_mode in ["true", "1", "yes", "si"]:
            return render_template("verificar_codigo.html", codigo_demo=codigo)

        brevo_api_key = os.environ.get("BREVO_API_KEY")

        payload = {
            "sender": {
                "name": "SafeRoute MX",
                "email": app.config["MAIL_DEFAULT_SENDER"]
            },
            "to": [
                {
                    "email": correo,
                    "name": nombre
                }
            ],
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
                return render_template(
                    "verificar_codigo.html",
                    codigo_demo=codigo,
                    error="No se pudo enviar el correo. Usa este código temporalmente."
                )

        except Exception as e:
            print("ERROR BREVO API:", e, flush=True)
            return render_template(
                "verificar_codigo.html",
                codigo_demo=codigo,
                error="No se pudo enviar el correo. Usa este código temporalmente."
            )

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
        tipo = request.form.get("tipo")
        descripcion = request.form.get("descripcion")
        fecha = request.form.get("fecha")
        ubicacion = request.form.get("ubicacion")
        gravedad = request.form.get("gravedad")
        latitud = request.form.get("latitud")
        longitud = request.form.get("longitud")

        foto_reporte = request.files.get("foto_reporte")
        url_foto_reporte = ""

        if not latitud or not longitud:
            return render_template("usuario/reportar.html", exito=False, error="Debes seleccionar una ubicación en el mapa.")

        if foto_reporte and foto_reporte.filename != "":
            if not foto_reporte.mimetype.startswith("image/"):
                return render_template("usuario/reportar.html", exito=False, error="El archivo debe ser una imagen.")

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
            "fecha_actualizacion": ""
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
    comentario_admin = request.form.get("comentario_admin", "")

    aprobado = True if estado in ["Aprobado", "En seguimiento", "Resuelto"] else False

    reporte_ref = db.collection("reportes").document(id)
    reporte_doc = reporte_ref.get()

    if not reporte_doc.exists:
        return redirect("/admin/reportes")

    reporte = reporte_doc.to_dict()

    reporte_ref.update({
        "estado": estado,
        "seguimiento": seguimiento,
        "comentario_admin": comentario_admin,
        "aprobado": aprobado,
        "fecha_actualizacion": firestore.SERVER_TIMESTAMP
    })

    correo_usuario = reporte.get("usuario")
    nombre_usuario = reporte.get("nombre_usuario", "Usuario SafeRoute")

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
        doc_ref.update({
            "tipo": request.form.get("tipo"),
            "descripcion": request.form.get("descripcion"),
            "fecha": request.form.get("fecha"),
            "ubicacion": request.form.get("ubicacion"),
            "gravedad": request.form.get("gravedad"),
            "latitud": float(request.form.get("latitud")),
            "longitud": float(request.form.get("longitud")),
            "usuario": session.get("usuario")
        })

        return redirect("/dashboard")

    reporte["id"] = doc.id

    return render_template("usuario/editar_reporte.html", reporte=reporte)

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
        return redirect("/login")

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

    def contar_diccionario(lista, campo):
        datos = {}
        for item in lista:
            valor = item.get(campo, "Sin dato") or "Sin dato"
            datos[valor] = datos.get(valor, 0) + 1
        return datos

    def top_diccionario(diccionario):
        if not diccionario:
            return None, 0
        clave = max(diccionario, key=diccionario.get)
        return clave, diccionario[clave]

    def ultimos(lista, cantidad=3):
        return lista[-cantidad:] if lista else []

    # ======================
    # LEER REPORTES Y USUARIOS
    # ======================
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

    total_reportes = len(reportes)
    total_usuarios = len(usuarios)

    mis_reportes = [r for r in reportes if r.get("usuario") == usuario_actual]
    total_mis_reportes = len(mis_reportes)

    # ======================
    # ESTADOS Y SEGUIMIENTO
    # ======================
    reportes_pendientes = sum(1 for r in reportes if r.get("estado", "Pendiente") == "Pendiente")
    reportes_aprobados = sum(1 for r in reportes if r.get("estado") == "Aprobado" or r.get("aprobado") == True)
    reportes_rechazados = sum(1 for r in reportes if r.get("estado") == "Rechazado")
    reportes_seguimiento = sum(1 for r in reportes if r.get("estado") == "En seguimiento")
    reportes_resueltos = sum(1 for r in reportes if r.get("estado") == "Resuelto")

    mis_pendientes = sum(1 for r in mis_reportes if r.get("estado", "Pendiente") == "Pendiente")
    mis_aprobados = sum(1 for r in mis_reportes if r.get("estado") == "Aprobado" or r.get("aprobado") == True)
    mis_rechazados = sum(1 for r in mis_reportes if r.get("estado") == "Rechazado")
    mis_seguimiento = sum(1 for r in mis_reportes if r.get("estado") == "En seguimiento")
    mis_resueltos = sum(1 for r in mis_reportes if r.get("estado") == "Resuelto")

    # ======================
    # ANÁLISIS GENERAL
    # ======================
    reportes_alto = sum(1 for r in reportes if r.get("gravedad") == "Alta")
    reportes_medio = sum(1 for r in reportes if r.get("gravedad") == "Media")
    reportes_bajo = sum(1 for r in reportes if r.get("gravedad") == "Baja")

    mis_alto = sum(1 for r in mis_reportes if r.get("gravedad") == "Alta")
    mis_medio = sum(1 for r in mis_reportes if r.get("gravedad") == "Media")
    mis_bajo = sum(1 for r in mis_reportes if r.get("gravedad") == "Baja")

    zonas = contar_diccionario(reportes, "ubicacion")
    zonas_alto = {}
    for r in reportes:
        if r.get("gravedad") == "Alta":
            ubicacion = r.get("ubicacion", "Sin ubicación") or "Sin ubicación"
            zonas_alto[ubicacion] = zonas_alto.get(ubicacion, 0) + 1

    tipos = contar_diccionario(reportes, "tipo")
    fechas = contar_diccionario(reportes, "fecha")
    usuarios_reportes = contar_diccionario(reportes, "usuario")

    mis_zonas = contar_diccionario(mis_reportes, "ubicacion")
    mis_tipos = contar_diccionario(mis_reportes, "tipo")
    mis_fechas = contar_diccionario(mis_reportes, "fecha")

    zona_mas_reportada, total_zona_mas_reportada = top_diccionario(zonas)
    zona_mas_alta, total_zona_mas_alta = top_diccionario(zonas_alto)
    tipo_mas_comun, total_tipo_mas_comun = top_diccionario(tipos)
    fecha_mas_reportada, total_fecha_mas_reportada = top_diccionario(fechas)
    usuario_mas_activo, total_usuario_mas_activo = top_diccionario(usuarios_reportes)

    mi_zona_mas_reportada, total_mi_zona_mas_reportada = top_diccionario(mis_zonas)
    mi_tipo_mas_comun, total_mi_tipo_mas_comun = top_diccionario(mis_tipos)
    mi_fecha_mas_activa, total_mi_fecha_mas_activa = top_diccionario(mis_fechas)

    ultimo_reporte = mis_reportes[-1] if mis_reportes else None
    primer_reporte = mis_reportes[0] if mis_reportes else None

    porcentaje_alto = round((reportes_alto / total_reportes) * 100, 1) if total_reportes else 0
    porcentaje_medio = round((reportes_medio / total_reportes) * 100, 1) if total_reportes else 0
    porcentaje_bajo = round((reportes_bajo / total_reportes) * 100, 1) if total_reportes else 0

    respuesta = (
        "Puedo ayudarte con preguntas específicas de SafeRoute MX.\n\n"
        "Puedes preguntarme, por ejemplo:\n"
        "• ¿Cuántos reportes tengo registrados?\n"
        "• ¿Cuál fue mi último reporte?\n"
        "• ¿Mi reporte lleva seguimiento?\n"
        "• ¿Qué zonas debo evitar?\n"
        "• ¿Cómo puedo reportar un incidente?\n"
        "• ¿Cómo protege mis datos SafeRoute MX?"
    )

    # ======================
    # CONVERSACIÓN BÁSICA
    # ======================
    if contiene("hola", "buenas", "buen dia", "buenos dias", "buenas tardes", "buenas noches"):
        respuesta = (
            f"Hola, {nombre_usuario}. Soy SafeRoute IA.\n\n"
            "Puedo ayudarte a:\n"
            "• Revisar tus reportes.\n"
            "• Analizar zonas de riesgo.\n"
            "• Explicar cómo usar el mapa.\n"
            "• Darte recomendaciones de seguridad.\n"
            "• Consultar estadísticas del sistema.\n\n"
            "Puedes preguntarme, por ejemplo: '¿Cuál es la zona más peligrosa?' o 'Dame un resumen de mis reportes'."
        )

    elif contiene("quien eres", "que eres", "que puedes hacer", "ayuda", "ayudame"):
        respuesta = (
            "Soy SafeRoute IA, el asistente inteligente de SafeRoute MX.\n\n"
            "Estoy diseñado para ayudarte a consultar información del sistema, explicar funciones, analizar reportes y darte orientación de seguridad.\n\n"
            "Puedo responder preguntas sobre reportes, mapa, perfil, riesgos, usuarios, estadísticas y recomendaciones."
        )

    elif contiene("gracias", "muchas gracias"):
        respuesta = "Con gusto. Estoy aquí para ayudarte a usar SafeRoute MX de forma más segura."

    elif contiene("adios", "hasta luego", "nos vemos", "bye"):
        respuesta = "Hasta luego. Recuerda revisar el mapa antes de salir y reportar cualquier incidente importante."

    # ======================
    # USO DEL SISTEMA
    # ======================
    elif contiene("que es saferoute", "para que sirve", "como funciona saferoute", "safe route"):
        respuesta = (
            "SafeRoute MX es una plataforma de reportes ciudadanos de seguridad.\n\n"
            "Sirve para registrar incidentes, consultar zonas de riesgo en el mapa y apoyar a otros usuarios con información actualizada.\n\n"
            "El sistema clasifica los reportes por nivel de riesgo: bajo, medio y alto."
        )

    elif contiene("como reporto", "reportar", "nuevo incidente", "registrar reporte", "hacer reporte"):
        respuesta = (
            "Para reportar un incidente:\n\n"
            "1. Entra a 'Reportar'.\n"
            "2. Selecciona el tipo de incidente.\n"
            "3. Escribe una descripción clara.\n"
            "4. Selecciona la ubicación en el mapa o busca una dirección.\n"
            "5. Agrega una foto si tienes evidencia del incidente.\n"
            "6. Elige la gravedad.\n"
            "7. Guarda el reporte.\n\n"
            "Después de enviarlo, el reporte queda pendiente para revisión del administrador. Cuando sea aprobado o tenga seguimiento, recibirás una notificación."
        )

    elif contiene("como edito", "editar reporte", "modificar reporte", "cambiar reporte"):
        respuesta = (
            "Para editar un reporte:\n\n"
            "1. Entra a 'Mis Reportes'.\n"
            "2. Busca el reporte que deseas modificar.\n"
            "3. Presiona 'Editar'.\n"
            "4. Cambia los datos necesarios.\n"
            "5. Guarda los cambios."
        )

    elif contiene("como elimino", "eliminar reporte", "borrar reporte"):
        respuesta = (
            "Para eliminar un reporte:\n\n"
            "1. Entra a 'Mis Reportes'.\n"
            "2. Presiona 'Eliminar'.\n"
            "3. Confirma la acción.\n\n"
            "Ten cuidado: una vez eliminado, el reporte ya no aparecerá en el sistema."
        )

    elif contiene("perfil", "foto", "cambiar foto", "contraseña", "cambiar nombre"):
        respuesta = (
            "En tu perfil puedes modificar tu información personal.\n\n"
            "Puedes cambiar:\n"
            "• Nombre.\n"
            "• Foto de perfil.\n"
            "• Contraseña.\n\n"
            "La foto se guarda en Cloudinary y Firestore conserva solo la URL, por eso permanece aunque cierres sesión."
        )

    elif contiene("mapa", "como uso el mapa", "ver mapa", "marcadores"):
        respuesta = (
            "El mapa muestra los reportes registrados por los usuarios.\n\n"
            "Los colores indican el nivel de riesgo:\n"
            "• Rojo: riesgo alto.\n"
            "• Amarillo: riesgo medio.\n"
            "• Verde: riesgo bajo.\n\n"
            "Puedes usarlo para revisar zonas antes de salir o antes de tomar una ruta."
        )

    # ======================
    # MIS REPORTES
    # ======================
    elif contiene("cuantos reportes tengo", "mis reportes", "total de mis reportes"):
        respuesta = (
            f"Tienes {total_mis_reportes} reportes registrados en tu cuenta.\n\n"
            f"• Riesgo alto: {mis_alto}\n"
            f"• Riesgo medio: {mis_medio}\n"
            f"• Riesgo bajo: {mis_bajo}"
        )

    elif contiene("mi ultimo reporte", "ultimo reporte", "reporte mas reciente"):
        if ultimo_reporte:
            respuesta = (
                "Tu reporte más reciente es:\n\n"
                f"Tipo: {ultimo_reporte.get('tipo', 'Sin tipo')}\n"
                f"Ubicación: {ultimo_reporte.get('ubicacion', 'Sin ubicación')}\n"
                f"Riesgo: {ultimo_reporte.get('gravedad', 'Sin gravedad')}\n"
                f"Fecha: {ultimo_reporte.get('fecha', 'Sin fecha')}\n"
                f"Descripción: {ultimo_reporte.get('descripcion', 'Sin descripción')}"
            )
        else:
            respuesta = "Todavía no tienes reportes registrados."

    elif contiene("mi primer reporte", "primer reporte"):
        if primer_reporte:
            respuesta = (
                "Tu primer reporte registrado fue:\n\n"
                f"Tipo: {primer_reporte.get('tipo', 'Sin tipo')}\n"
                f"Ubicación: {primer_reporte.get('ubicacion', 'Sin ubicación')}\n"
                f"Riesgo: {primer_reporte.get('gravedad', 'Sin gravedad')}\n"
                f"Fecha: {primer_reporte.get('fecha', 'Sin fecha')}\n"
                f"Descripción: {primer_reporte.get('descripcion', 'Sin descripción')}"
            )
        else:
            respuesta = "Todavía no tienes reportes registrados."

    elif contiene("mi zona mas reportada", "donde reporto mas", "zona que mas reporto", "en que zona reporto mas", "zona frecuente", "mi zona frecuente"):
        if mi_zona_mas_reportada:
            respuesta = f"La zona donde más has reportado es {mi_zona_mas_reportada}, con {total_mi_zona_mas_reportada} reportes."
        else:
            respuesta = "Aún no tienes suficientes reportes para identificar tu zona más reportada."

    elif contiene("que tipo reporto mas", "mi incidente mas comun", "que reporto mas", "tipo de incidente reporto mas", "incidente comun"):
        if mi_tipo_mas_comun:
            respuesta = f"El tipo de incidente que más has reportado es {mi_tipo_mas_comun}, con {total_mi_tipo_mas_comun} registros."
        else:
            respuesta = "Aún no tienes reportes suficientes para identificar tu tipo de incidente más común."

    elif contiene("resumen de mi actividad", "mi actividad", "resumen de mis reportes"):
        respuesta = (
            "Resumen de tu actividad en SafeRoute MX:\n\n"
            f"Total de reportes: {total_mis_reportes}\n"
            f"Riesgo alto: {mis_alto}\n"
            f"Riesgo medio: {mis_medio}\n"
            f"Riesgo bajo: {mis_bajo}"
        )
        if mi_zona_mas_reportada:
            respuesta += f"\nZona donde más reportas: {mi_zona_mas_reportada}"
        if mi_tipo_mas_comun:
            respuesta += f"\nIncidente que más reportas: {mi_tipo_mas_comun}"


    elif contiene("mi nivel de riesgo", "cual es mi nivel de riesgo", "riesgo de mis reportes"):
        if total_mis_reportes == 0:
            respuesta = "Aún no puedo calcular tu nivel de riesgo porque no tienes reportes registrados."
        elif mis_alto > 0:
            respuesta = (
                "Tu nivel de riesgo actual es ALTO.\n\n"
                f"Tienes {mis_alto} reportes de riesgo alto, {mis_medio} de riesgo medio y {mis_bajo} de riesgo bajo.\n\n"
                "Recomendación: revisa tus zonas frecuentes y evita pasar por lugares donde hayas reportado incidentes graves."
            )
        elif mis_medio > 0:
            respuesta = (
                "Tu nivel de riesgo actual es MEDIO.\n\n"
                f"Tienes {mis_medio} reportes de riesgo medio y {mis_bajo} de riesgo bajo.\n\n"
                "Recomendación: mantente atento y consulta el mapa antes de salir."
            )
        else:
            respuesta = (
                "Tu nivel de riesgo actual es BAJO.\n\n"
                f"Tienes {mis_bajo} reportes de riesgo bajo.\n\n"
                "Aun así, es recomendable seguir revisando el mapa y reportar cualquier incidente importante."
            )

    elif contiene("estado de mis reportes", "seguimiento de mis reportes", "mis reportes tienen seguimiento", "mi reporte lleva seguimiento", "mi reporte tiene seguimiento"):
        if total_mis_reportes == 0:
            respuesta = "Todavía no tienes reportes registrados para consultar seguimiento."
        else:
            respuesta = (
                "Estado de tus reportes:\n\n"
                f"• Pendientes: {mis_pendientes}\n"
                f"• Aprobados: {mis_aprobados}\n"
                f"• Rechazados: {mis_rechazados}\n"
                f"• En seguimiento: {mis_seguimiento}\n"
                f"• Resueltos: {mis_resueltos}\n\n"
                "Puedes revisar el detalle en 'Mis Reportes'. Ahí verás el comentario del administrador si ya fue actualizado."
            )

    elif contiene("mi reporte fue aprobado", "reporte aprobado", "aprobaron mi reporte", "mi publicacion fue aprobada"):
        if total_mis_reportes == 0:
            respuesta = "Aún no tienes reportes registrados."
        else:
            respuesta = (
                f"Tienes {mis_aprobados} reportes aprobados y visibles para la comunidad.\n"
                f"También tienes {mis_pendientes} pendientes y {mis_rechazados} rechazados."
            )

    elif contiene("mi reporte fue rechazado", "rechazaron mi reporte", "reporte rechazado"):
        if mis_rechazados > 0:
            respuesta = f"Tienes {mis_rechazados} reporte(s) rechazado(s). Revisa 'Mis Reportes' para ver si el administrador dejó un comentario."
        else:
            respuesta = "No tienes reportes rechazados actualmente."

    elif contiene("por que no aparece mi reporte", "no veo mi reporte en el mapa", "mi reporte no aparece"):
        respuesta = (
            "Tu reporte puede no aparecer en el mapa por estas razones:\n\n"
            "• Todavía está pendiente de revisión.\n"
            "• Fue rechazado por el administrador.\n"
            "• No tiene ubicación válida.\n\n"
            "Solo los reportes aprobados por el administrador aparecen en la comunidad y en el mapa."
        )

    elif contiene("como protege mis datos", "privacidad", "mis datos", "datos personales"):
        respuesta = (
            "SafeRoute MX protege tu información usando datos mínimos necesarios para el sistema.\n\n"
            "• Tu contraseña se guarda cifrada.\n"
            "• Las imágenes se guardan en Cloudinary y en Firestore solo se guarda la URL.\n"
            "• Los reportes se muestran a la comunidad solo cuando son aprobados.\n"
            "• El administrador puede revisar reportes para evitar publicaciones falsas o inapropiadas."
        )

    elif contiene("evitar robos", "como puedo evitar robos", "prevenir robos"):
        respuesta = (
            "Consejos para reducir el riesgo de robo:\n\n"
            "• Evita usar el celular en calles solas.\n"
            "• Revisa el mapa antes de salir.\n"
            "• Evita zonas con reportes recientes de robo o asalto.\n"
            "• Camina por lugares iluminados y transitados.\n"
            "• Comparte tu ubicación con alguien de confianza.\n"
            "• Si hay peligro inmediato, llama al 911."
        )

    elif contiene("caminar seguro", "recomendaciones para caminar", "caminar de noche"):
        respuesta = (
            "Para caminar con más seguridad:\n\n"
            "• Revisa el mapa antes de salir.\n"
            "• Evita calles oscuras o solas.\n"
            "• Mantente atento a tu entorno.\n"
            "• No uses audífonos a volumen alto.\n"
            "• Si notas una situación sospechosa, cambia de ruta.\n"
            "• En caso de emergencia, llama al 911."
        )


    # ======================
    # ANÁLISIS DE RIESGO
    # ======================
    elif contiene("zona mas peligrosa", "colonia mas peligrosa", "ubicacion mas peligrosa", "zona debo evitar", "zonas debo evitar"):
        if zona_mas_alta:
            respuesta = (
                f"La zona con más reportes de riesgo alto es {zona_mas_alta}.\n\n"
                f"Reportes de riesgo alto en esa zona: {total_zona_mas_alta}\n\n"
                "Recomendación: evita pasar por esa zona si no es necesario, especialmente de noche o en horarios de baja afluencia."
            )
        elif zona_mas_reportada:
            respuesta = (
                f"La zona con más reportes es {zona_mas_reportada}.\n\n"
                f"Total de reportes registrados ahí: {total_zona_mas_reportada}."
            )
        else:
            respuesta = "Aún no hay suficientes reportes para identificar una zona peligrosa."

    elif contiene("zona mas segura", "menos riesgo", "zona segura"):
        zonas_bajo = {}
        for r in reportes:
            if r.get("gravedad") == "Baja":
                ubicacion = r.get("ubicacion", "Sin ubicación") or "Sin ubicación"
                zonas_bajo[ubicacion] = zonas_bajo.get(ubicacion, 0) + 1
        zona_baja, total_baja = top_diccionario(zonas_bajo)
        if zona_baja:
            respuesta = f"La zona con más reportes de riesgo bajo es {zona_baja}, con {total_baja} reportes de bajo riesgo."
        else:
            respuesta = "Aún no hay suficientes datos para identificar una zona de menor riesgo."

    elif contiene("riesgo alto") and not contiene("cuantos", "hay"):
        respuesta = (
            "Riesgo alto significa que el incidente puede representar una amenaza importante.\n\n"
            "Ejemplos: asalto, robo con violencia, zona peligrosa, accidente grave o vandalismo severo.\n\n"
            "Recomendación: evita la zona, busca rutas alternas y avisa a las autoridades si el peligro sigue activo."
        )

    elif contiene("riesgo medio") and not contiene("cuantos", "hay"):
        respuesta = (
            "Riesgo medio indica que la zona requiere precaución.\n\n"
            "Puede tratarse de incidentes moderados, zonas con reportes recientes o situaciones que podrían escalar."
        )

    elif contiene("riesgo bajo") and not contiene("cuantos", "hay"):
        respuesta = (
            "Riesgo bajo indica que el incidente tiene menor gravedad o que la zona presenta menor nivel de peligro.\n\n"
            "Aun así, es recomendable mantenerse atento y revisar el mapa."
        )

    elif contiene("recomendacion", "recomendaciones", "consejos", "que me recomiendas", "viajar seguro", "caminar de noche", "seguridad"):
        respuesta = "Recomendaciones de seguridad:\n\n"
        if zona_mas_alta:
            respuesta += f"• Evita pasar por {zona_mas_alta} si no es necesario.\n"
        if tipo_mas_comun:
            respuesta += f"• Mantente atento a incidentes de tipo {tipo_mas_comun}, porque es el más reportado.\n"
        respuesta += (
            "• Revisa el mapa antes de salir.\n"
            "• Comparte tu ubicación con alguien de confianza.\n"
            "• Evita calles solas o con poca iluminación.\n"
            "• Reporta incidentes para ayudar a la comunidad.\n"
            "• En caso de emergencia, llama al 911."
        )

    elif contiene("911", "emergencia", "que hago si", "me asaltan", "accidente", "persona sospechosa"):
        respuesta = (
            "Si estás ante una emergencia real o inmediata, llama al 911.\n\n"
            "Consejos generales:\n"
            "• Mantén la calma.\n"
            "• Aléjate de la zona si es seguro hacerlo.\n"
            "• No te enfrentes a personas agresivas.\n"
            "• Busca un lugar iluminado o con más personas.\n"
            "• Después puedes registrar el incidente en SafeRoute MX para alertar a la comunidad."
        )

    # ======================
    # ESTADÍSTICAS GENERALES
    # ======================
    elif contiene("resumen del sistema", "resumen general", "dame un resumen", "estadisticas generales"):
        respuesta = (
            "Resumen general de SafeRoute MX:\n\n"
            f"Usuarios registrados: {total_usuarios}\n"
            f"Reportes totales: {total_reportes}\n"
            f"Riesgo alto: {reportes_alto} ({porcentaje_alto}%)\n"
            f"Riesgo medio: {reportes_medio} ({porcentaje_medio}%)\n"
            f"Riesgo bajo: {reportes_bajo} ({porcentaje_bajo}%)"
        )
        if zona_mas_reportada:
            respuesta += f"\nZona con más reportes: {zona_mas_reportada}"
        if tipo_mas_comun:
            respuesta += f"\nIncidente más común: {tipo_mas_comun}"

    elif contiene("incidente mas comun", "tipo mas comun", "reporte mas comun", "incidente principal"):
        if tipo_mas_comun:
            respuesta = f"El incidente más común es {tipo_mas_comun}, con {total_tipo_mas_comun} reportes registrados."
        else:
            respuesta = "Aún no hay reportes suficientes para identificar el incidente más común."

    elif contiene("dia con mas reportes", "fecha con mas reportes", "cuando hay mas reportes"):
        if fecha_mas_reportada:
            respuesta = f"La fecha con más reportes registrados es {fecha_mas_reportada}, con {total_fecha_mas_reportada} reportes."
        else:
            respuesta = "Aún no hay suficientes datos para identificar una fecha con más reportes."

    elif contiene("cuantos reportes hay", "total reportes", "reportes hay"):
        respuesta = f"Actualmente existen {total_reportes} reportes registrados en el sistema."

    elif contiene("cuantos usuarios", "usuarios hay", "total usuarios"):
        respuesta = f"Actualmente hay {total_usuarios} usuarios registrados."

    elif contiene("cuantos robos", "robos hay"):
        total = sum(1 for r in reportes if "robo" in (r.get("tipo", "").lower()))
        respuesta = f"Actualmente hay {total} reportes relacionados con robo."

    elif contiene("cuantos asaltos", "asaltos hay"):
        total = sum(1 for r in reportes if "asalto" in (r.get("tipo", "").lower()))
        respuesta = f"Actualmente hay {total} reportes relacionados con asalto."

    elif contiene("cuantos accidentes", "accidentes hay"):
        total = sum(1 for r in reportes if "accidente" in (r.get("tipo", "").lower()))
        respuesta = f"Actualmente hay {total} reportes relacionados con accidentes."

    # ======================
    # RESPUESTAS ADMIN
    # ======================
    if rol == "admin":

        if contiene("cuantos reportes de riesgo alto", "reportes de riesgo alto hay", "riesgo alto hay"):
            respuesta = f"Actualmente hay {reportes_alto} reportes de riesgo alto en el sistema."

        elif contiene("cuantos reportes de riesgo medio", "reportes de riesgo medio hay", "riesgo medio hay"):
            respuesta = f"Actualmente hay {reportes_medio} reportes de riesgo medio en el sistema."

        elif contiene("cuantos reportes de riesgo bajo", "reportes de riesgo bajo hay", "riesgo bajo hay"):
            respuesta = f"Actualmente hay {reportes_bajo} reportes de riesgo bajo en el sistema."

        elif contiene("reportes pendientes", "cuantos pendientes", "pendientes de aprobacion"):
            respuesta = (
                "Estado general de reportes:\n\n"
                f"• Pendientes: {reportes_pendientes}\n"
                f"• Aprobados: {reportes_aprobados}\n"
                f"• Rechazados: {reportes_rechazados}\n"
                f"• En seguimiento: {reportes_seguimiento}\n"
                f"• Resueltos: {reportes_resueltos}"
            )

        elif contiene("zona conflictiva", "zona mas conflictiva", "cual es la zona mas conflictiva"):
            if zona_mas_alta:
                respuesta = (
                    f"La zona más conflictiva es {zona_mas_alta}, porque concentra {total_zona_mas_alta} reportes de riesgo alto.\n\n"
                    "Recomendación administrativa: revisar esos reportes, validar si siguen activos y priorizar seguimiento."
                )
            elif zona_mas_reportada:
                respuesta = f"La zona con más reportes es {zona_mas_reportada}, con {total_zona_mas_reportada} registros."
            else:
                respuesta = "Aún no hay reportes suficientes para detectar una zona conflictiva."

        elif contiene("usuario con mas reportes", "quien reporta mas", "usuario mas activo"):
            if usuario_mas_activo:
                respuesta = (
                    "El usuario con más reportes es:\n\n"
                    f"Usuario: {usuario_mas_activo}\n"
                    f"Reportes registrados: {total_usuario_mas_activo}"
                )
            else:
                respuesta = "Aún no hay reportes suficientes para identificar al usuario más activo."

        elif contiene("que puedo hacer como admin", "panel admin", "administrador"):
            respuesta = (
                "Como administrador puedes:\n\n"
                "• Consultar todos los reportes.\n"
                "• Aprobar o rechazar reportes.\n"
                "• Dar seguimiento a reportes.\n"
                "• Agregar comentarios administrativos.\n"
                "• Enviar notificaciones al usuario cuando cambia el estado.\n"
                "• Eliminar reportes inapropiados.\n"
                "• Ver usuarios registrados.\n"
                "• Eliminar usuarios.\n"
                "• Revisar estadísticas.\n"
                "• Consultar el mapa general.\n"
                "• Usar SafeRoute IA para análisis del sistema."
            )

        elif contiene("estadisticas preocupantes", "que debo revisar", "alerta del sistema"):
            respuesta = "Puntos importantes para revisar:\n\n"
            if reportes_alto > reportes_medio and reportes_alto > reportes_bajo:
                respuesta += "• Predominan los reportes de riesgo alto.\n"
            if zona_mas_alta:
                respuesta += f"• La zona crítica principal es {zona_mas_alta}.\n"
            if tipo_mas_comun:
                respuesta += f"• El incidente más frecuente es {tipo_mas_comun}.\n"
            respuesta += "• Revisa el panel de reportes y el mapa general para tomar decisiones."

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

    return redirect("/admin/usuarios")
# ======================
# LOGOUT
# ======================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ======================
# RUN
# ======================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
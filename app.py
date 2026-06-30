from flask import Flask, render_template, request, redirect, session, jsonify
from flask_mail import Mail, Message
import random
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
from firebase_admin import credentials, firestore
import os
import uuid
import json
from werkzeug.utils import secure_filename
app = Flask(__name__)
app.secret_key = "saferoute_secret_key"
# ======================
# CONFIGURACIÓN CORREO
# ======================
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_USERNAME")
mail = Mail(app)
UPLOAD_FOLDER = "static/uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
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
# LOGIN USUARIO / ADMIN
# ======================
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "").strip()

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
                session["foto_perfil"] = usuario.get("foto_perfil", "")

                if rol_db == "admin":
                    return redirect("/admin")

                return redirect("/dashboard")

        return render_template(
            "login.html",
            error="Correo o contraseña incorrectos. Intenta nuevamente."
        )

    return render_template("login.html")
# ======================
# REGISTRO USUARIO
# ======================
@app.route("/registro", methods=["GET", "POST"])
def registro():

    if request.method == "POST":
        nombre = request.form.get("nombre")
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password")
        confirmar = request.form.get("confirmar_password")

        if password != confirmar:
            return render_template(
                "registro.html",
                error="Las contraseñas no coinciden."
            )

        usuarios = db.collection("usuarios").stream()

        for doc in usuarios:
            usuario_existente = doc.to_dict()

            if usuario_existente.get("correo", "").strip().lower() == correo:
                return render_template(
                    "registro.html",
                    error="Este correo ya está registrado."
                )

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
            return render_template(
                "verificar_codigo.html",
                codigo_demo=codigo
            )

        mensaje = Message(
            "Código de verificación - SafeRoute MX",
            recipients=[correo]
        )

        mensaje.body = f"""
Hola {nombre}.

Bienvenido a SafeRoute MX.

Tu código de verificación es:

{codigo}

Ingresa este código en la plataforma para activar tu cuenta.

Gracias por usar SafeRoute MX.
"""

        mail.send(mensaje)

        return redirect("/verificar")

    return render_template("registro.html")


@app.route("/verificar", methods=["GET", "POST"])
def verificar():

    correo = session.get("correo_verificacion")

    if not correo:
        return redirect("/registro")

    if request.method == "POST":

        codigo = request.form.get("codigo")

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

    # Traer todos los usuarios para poder mostrar nombre y foto
    usuarios_por_correo = {}
    usuarios_docs = db.collection("usuarios").stream()

    for user_doc in usuarios_docs:
        user = user_doc.to_dict()
        correo_user = user.get("correo", "").strip().lower()

        if correo_user:
            usuarios_por_correo[correo_user] = {
                "nombre": user.get("nombre", "Usuario SafeRoute"),
                "foto_perfil": user.get("foto_perfil", "")
            }

    # Traer todos los reportes del sistema
    reportes = []
    docs = db.collection("reportes").stream()

    for doc in docs:
        reporte = doc.to_dict()
        reporte["id"] = doc.id

        latitud = reporte.get("latitud")
        longitud = reporte.get("longitud")

        if latitud is not None and longitud is not None:
            try:
                reporte["latitud"] = float(latitud)
                reporte["longitud"] = float(longitud)

                correo_reporte = reporte.get("usuario", "").strip().lower()
                datos_usuario = usuarios_por_correo.get(correo_reporte, {})

                reporte["nombre_usuario"] = datos_usuario.get("nombre", "Usuario SafeRoute")
                reporte["foto_usuario"] = datos_usuario.get("foto_perfil", "")

                reportes.append(reporte)

            except:
                pass

    # Ordenar por fecha, los más recientes primero
    reportes.sort(key=lambda r: r.get("fecha", ""), reverse=True)

    return render_template("usuario/mapa.html", reportes=reportes)

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

        if not latitud or not longitud:
            return "Debes seleccionar una ubicación en el mapa"

        reporte = {
            "tipo": tipo,
            "descripcion": descripcion,
            "fecha": fecha,
            "ubicacion": ubicacion,
            "gravedad": gravedad,
            "latitud": float(latitud),
            "longitud": float(longitud),
            "usuario": session.get("usuario")
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

    return render_template("admin/reportes.html", reportes=reportes)


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

    db.collection("usuarios").document(id).delete()

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

    if request.method == "POST":

        nombre = request.form.get("nombre")
        foto = request.files.get("foto")

        password_actual = request.form.get("password_actual")
        password_nueva = request.form.get("password_nueva")
        password_confirmar = request.form.get("password_confirmar")

        datos_actualizados = {
            "nombre": nombre
        }

        session["nombre"] = nombre

        if foto and foto.filename != "":
            filename = secure_filename(foto.filename)
            filename = f"{uuid.uuid4()}_{filename}"

            ruta_guardado = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            foto.save(ruta_guardado)

            ruta_foto = "/" + ruta_guardado.replace("\\", "/")
            datos_actualizados["foto_perfil"] = ruta_foto
            session["foto_perfil"] = ruta_foto

        if password_actual or password_nueva or password_confirmar:

            if not check_password_hash(usuario.get("password", ""), password_actual):
                return render_template(
                    "usuario/perfil.html",
                    usuario=usuario,
                    total_reportes=0,
                    error="La contraseña actual no es correcta."
                )

            if password_nueva != password_confirmar:
                return render_template(
                    "usuario/perfil.html",
                    usuario=usuario,
                    total_reportes=0,
                    error="La nueva contraseña no coincide."
                )

            datos_actualizados["password"] = generate_password_hash(password_nueva)

        usuario_ref.update(datos_actualizados)

        usuario_actualizado = usuario_ref.get().to_dict()

        total_reportes = 0
        docs = db.collection("reportes").where("usuario", "==", session.get("usuario")).stream()

        for doc in docs:
            total_reportes += 1

        return render_template(
            "usuario/perfil.html",
            usuario=usuario_actualizado,
            total_reportes=total_reportes,
            exito="Perfil actualizado correctamente."
        )

    total_reportes = 0

    docs = db.collection("reportes").where("usuario", "==", session.get("usuario")).stream()

    for doc in docs:
        total_reportes += 1

    return render_template(
        "usuario/perfil.html",
        usuario=usuario,
        total_reportes=total_reportes
    )

@app.route("/chatbot")
def chatbot():

    if "usuario" not in session:
        return redirect("/login")

    return render_template("usuario/chatbot.html")


@app.route("/chatbot/preguntar", methods=["POST"])
def chatbot_preguntar():

    if "usuario" not in session:
        return redirect("/login")

    pregunta = request.form.get("pregunta", "").lower()
    pregunta = pregunta.replace("á", "a").replace("é", "e").replace("í", "i").replace("ó", "o").replace("ú", "u")

    rol = session.get("rol")
    usuario_actual = session.get("usuario")

    respuesta = "Puedo ayudarte con reportes, mapa, perfil, riesgos, estadísticas y recomendaciones de seguridad."

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
    # ANALISIS DE DATOS
    # ======================
    reportes_alto = 0
    reportes_medio = 0
    reportes_bajo = 0

    zonas = {}
    zonas_alto = {}
    tipos = {}
    usuarios_reportes = {}
    reportes_por_fecha = {}

    for r in reportes:
        gravedad = r.get("gravedad", "")
        ubicacion = r.get("ubicacion", "Sin ubicación")
        tipo = r.get("tipo", "Sin tipo")
        usuario = r.get("usuario", "Sin usuario")
        fecha = r.get("fecha", "Sin fecha")

        if gravedad == "Alta":
            reportes_alto += 1
            zonas_alto[ubicacion] = zonas_alto.get(ubicacion, 0) + 1
        elif gravedad == "Media":
            reportes_medio += 1
        elif gravedad == "Baja":
            reportes_bajo += 1

        zonas[ubicacion] = zonas.get(ubicacion, 0) + 1
        tipos[tipo] = tipos.get(tipo, 0) + 1
        usuarios_reportes[usuario] = usuarios_reportes.get(usuario, 0) + 1
        reportes_por_fecha[fecha] = reportes_por_fecha.get(fecha, 0) + 1

    zona_mas_reportada = max(zonas, key=zonas.get) if zonas else None
    tipo_mas_comun = max(tipos, key=tipos.get) if tipos else None
    usuario_mas_activo = max(usuarios_reportes, key=usuarios_reportes.get) if usuarios_reportes else None
    zona_mas_alta = max(zonas_alto, key=zonas_alto.get) if zonas_alto else None

    ultimo_reporte = mis_reportes[-1] if mis_reportes else None

    porcentaje_alto = 0
    porcentaje_medio = 0
    porcentaje_bajo = 0

    if total_reportes > 0:
        porcentaje_alto = round((reportes_alto / total_reportes) * 100, 1)
        porcentaje_medio = round((reportes_medio / total_reportes) * 100, 1)
        porcentaje_bajo = round((reportes_bajo / total_reportes) * 100, 1)

    # ======================
    # RESPUESTAS GENERALES
    # ======================
    if "hola" in pregunta or "buenas" in pregunta:
        respuesta = (
            "Hola 👋 Soy SafeRoute IA.\n\n"
            "Puedo ayudarte a consultar reportes, analizar zonas de riesgo, revisar estadísticas y darte recomendaciones de seguridad."
        )

    elif "cuantos reportes tengo" in pregunta or "mis reportes" in pregunta:
        respuesta = f"Tienes {total_mis_reportes} reportes registrados en tu cuenta."

    elif "ultimo reporte" in pregunta or "mi ultimo reporte" in pregunta:
        if ultimo_reporte:
            respuesta = (
                "Tu último reporte registrado fue:\n\n"
                f"🚨 Tipo: {ultimo_reporte.get('tipo', 'Sin tipo')}\n"
                f"📍 Ubicación: {ultimo_reporte.get('ubicacion', 'Sin ubicación')}\n"
                f"⚠️ Riesgo: {ultimo_reporte.get('gravedad', 'Sin gravedad')}\n"
                f"📅 Fecha: {ultimo_reporte.get('fecha', 'Sin fecha')}\n"
                f"📝 Descripción: {ultimo_reporte.get('descripcion', 'Sin descripción')}"
            )
        else:
            respuesta = "Todavía no tienes reportes registrados."

    elif "reportar" in pregunta or "incidente" in pregunta:
        respuesta = "Para reportar un incidente, entra a 'Reportar incidente', selecciona tipo, gravedad, ubicación en el mapa y guarda el reporte."

    elif "editar" in pregunta:
        respuesta = "Para editar un reporte, entra a 'Mis Reportes' y presiona el botón ✏️ Editar."

    elif "eliminar" in pregunta:
        respuesta = "Para eliminar un reporte, entra a 'Mis Reportes' y usa el botón 🗑️ Eliminar. El sistema te pedirá confirmación."

    elif "mapa" in pregunta:
        respuesta = "El mapa muestra reportes ubicados por gravedad: rojo para alto, amarillo para medio y verde para bajo."

    elif "perfil" in pregunta or "foto" in pregunta:
        respuesta = "En tu perfil puedes cambiar tu nombre, foto de perfil y contraseña."

    # ======================
    # ANALISIS INTELIGENTE
    # ======================
    elif "zona mas peligrosa" in pregunta or "colonia mas peligrosa" in pregunta or "ubicacion mas peligrosa" in pregunta:
        if zona_mas_alta:
            respuesta = (
                f"La zona con más reportes de riesgo alto es: {zona_mas_alta}.\n\n"
                f"🔴 Reportes de riesgo alto en esa zona: {zonas_alto[zona_mas_alta]}\n"
                "Recomendación: evita pasar por esa zona en horarios de baja afluencia y revisa el mapa antes de salir."
            )
        elif zona_mas_reportada:
            respuesta = (
                f"La zona con más reportes es: {zona_mas_reportada}.\n\n"
                f"📍 Total de reportes: {zonas[zona_mas_reportada]}"
            )
        else:
            respuesta = "Aún no hay suficientes reportes para identificar una zona peligrosa."

    elif "incidente mas comun" in pregunta or "tipo mas comun" in pregunta or "reporte mas comun" in pregunta:
        if tipo_mas_comun:
            respuesta = (
                f"El incidente más común es: {tipo_mas_comun}.\n\n"
                f"📊 Total registrado: {tipos[tipo_mas_comun]}"
            )
        else:
            respuesta = "Aún no hay reportes suficientes para identificar el incidente más común."

    elif "resumen" in pregunta or "resumen del sistema" in pregunta:
        respuesta = (
            "📊 Resumen general de SafeRoute MX:\n\n"
            f"👥 Usuarios registrados: {total_usuarios}\n"
            f"📋 Reportes totales: {total_reportes}\n"
            f"🔴 Riesgo alto: {reportes_alto} ({porcentaje_alto}%)\n"
            f"🟡 Riesgo medio: {reportes_medio} ({porcentaje_medio}%)\n"
            f"🟢 Riesgo bajo: {reportes_bajo} ({porcentaje_bajo}%)"
        )

        if zona_mas_reportada:
            respuesta += f"\n📍 Zona con más reportes: {zona_mas_reportada}"

        if tipo_mas_comun:
            respuesta += f"\n🚨 Incidente más común: {tipo_mas_comun}"

    elif "recomendacion" in pregunta or "recomendaciones" in pregunta or "que me recomiendas" in pregunta:
        respuesta = "Recomendaciones de SafeRoute IA:\n\n"

        if zona_mas_alta:
            respuesta += f"🔴 Evita pasar por {zona_mas_alta} si no es necesario, ya que concentra reportes de riesgo alto.\n"

        if tipo_mas_comun:
            respuesta += f"🚨 Mantente alerta ante incidentes de tipo {tipo_mas_comun}, porque es el más reportado.\n"

        if reportes_alto > reportes_medio and reportes_alto > reportes_bajo:
            respuesta += "⚠️ Actualmente predominan reportes de riesgo alto. Revisa el mapa antes de salir.\n"
        else:
            respuesta += "🛡️ Revisa el mapa y reporta cualquier incidente para mantener actualizada la información.\n"

    elif "riesgo alto" in pregunta and not ("cuantos" in pregunta or "hay" in pregunta):
        respuesta = "Riesgo alto significa que el incidente es grave o representa una zona peligrosa."

    elif "riesgo medio" in pregunta and not ("cuantos" in pregunta or "hay" in pregunta):
        respuesta = "Riesgo medio indica una zona donde debes tener precaución."

    elif "riesgo bajo" in pregunta and not ("cuantos" in pregunta or "hay" in pregunta):
        respuesta = "Riesgo bajo indica una zona con menor nivel de peligro."

    # ======================
    # RESPUESTAS ADMIN
    # ======================
    if rol == "admin":

        if "cuantos usuarios" in pregunta or "usuarios hay" in pregunta:
            respuesta = f"Actualmente hay {total_usuarios} usuarios registrados."

        elif "cuantos reportes" in pregunta or "reportes hay" in pregunta:
            respuesta = f"Actualmente existen {total_reportes} reportes registrados en el sistema."

        elif "riesgo alto" in pregunta and ("cuantos" in pregunta or "hay" in pregunta):
            respuesta = f"Actualmente hay {reportes_alto} reportes de riesgo alto."

        elif "riesgo medio" in pregunta and ("cuantos" in pregunta or "hay" in pregunta):
            respuesta = f"Actualmente hay {reportes_medio} reportes de riesgo medio."

        elif "riesgo bajo" in pregunta and ("cuantos" in pregunta or "hay" in pregunta):
            respuesta = f"Actualmente hay {reportes_bajo} reportes de riesgo bajo."

        elif "usuario con mas reportes" in pregunta or "quien reporta mas" in pregunta or "usuario mas activo" in pregunta:
            if usuario_mas_activo:
                respuesta = (
                    f"El usuario con más reportes es:\n\n"
                    f"👤 {usuario_mas_activo}\n"
                    f"📋 Reportes registrados: {usuarios_reportes[usuario_mas_activo]}"
                )
            else:
                respuesta = "Aún no hay reportes suficientes para identificar al usuario más activo."

        elif "admin" in pregunta or "panel" in pregunta:
            respuesta = "Como administrador puedes revisar reportes, usuarios, estadísticas, mapa general y el asistente IA."

    return jsonify({"respuesta": respuesta})
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
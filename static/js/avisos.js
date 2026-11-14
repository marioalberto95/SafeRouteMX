/* Avisos y validación de formularios de SafeRoute MX.
   - Reemplaza las burbujas del navegador ("Please include an '@'...") por mensajes en español con el diseño de la página.
   - Reemplaza alert() por una ventana de aviso con el mismo diseño. */
(function () {
    if (window.__srAvisos) return;
    window.__srAvisos = true;

    function esc(t) {
        var d = document.createElement("div");
        d.textContent = t == null ? "" : String(t);
        return d.innerHTML;
    }

    /* ---------- Ventana de aviso ---------- */
    var abierto = null;

    function srAviso(mensaje, opciones) {
        opciones = opciones || {};
        if (abierto) { abierto.remove(); abierto = null; }

        var exito = opciones.tipo === "exito";
        var fondo = document.createElement("div");
        fondo.className = "sr-aviso-fondo";
        fondo.innerHTML =
            '<div class="sr-aviso' + (exito ? " sr-aviso--exito" : "") + '" role="alertdialog" aria-modal="true">' +
                '<div class="sr-aviso__cabecera">' +
                    '<div class="sr-aviso__icono"><i class="fa-solid ' + (exito ? "fa-circle-check" : "fa-triangle-exclamation") + '"></i></div>' +
                    '<h5 class="sr-aviso__titulo">' + esc(opciones.titulo || (exito ? "Listo" : "Revisa la información")) + "</h5>" +
                "</div>" +
                '<div class="sr-aviso__texto">' + esc(mensaje) + "</div>" +
                '<div class="sr-aviso__pie"><button type="button" class="sr-aviso__boton">Entendido</button></div>' +
            "</div>";

        function cerrar() {
            document.removeEventListener("keydown", tecla, true);
            fondo.remove();
            abierto = null;
        }

        function tecla(e) {
            if (e.key === "Escape" || e.key === "Enter") { e.preventDefault(); cerrar(); }
        }

        fondo.addEventListener("click", function (e) { if (e.target === fondo) cerrar(); });
        fondo.querySelector("button").addEventListener("click", cerrar);
        document.addEventListener("keydown", tecla, true);
        document.body.appendChild(fondo);
        fondo.querySelector("button").focus();
        abierto = fondo;
    }

    window.srAviso = srAviso;
    window.alert = function (mensaje) { srAviso(mensaje); };

    /* ---------- Validación de campos ---------- */
    function etiquetaDe(el) {
        var caja = el.closest(".field-box, .section-box, .mb-3, .col-12, .form-group") || el.parentElement;
        var lab = caja ? caja.querySelector("label") : null;
        if (!lab) return "";
        return lab.textContent.replace(/\s+/g, " ").trim();
    }

    function mensajeDe(el) {
        if (el.dataset.msg) return el.dataset.msg;

        var nombre = (el.name || el.id || "").toLowerCase();
        var v = el.validity;

        if (el.hasAttribute("readonly") && /latitud|longitud/.test(nombre)) {
            return "Toca el mapa o busca una dirección para elegir la ubicación del incidente.";
        }

        if (v.valueMissing) {
            if (el.type === "email") return "Escribe tu correo electrónico.";
            if (el.type === "password") {
                return /confirm/.test(nombre) ? "Confirma tu contraseña." :
                       /nueva/.test(nombre) ? "Escribe tu nueva contraseña." : "Escribe tu contraseña.";
            }
            if (/codigo/.test(nombre)) return "Escribe el código de 6 dígitos que te enviamos al correo.";
            if (el.tagName === "SELECT") return "Selecciona una opción.";
            if (el.type === "file") return "Selecciona un archivo.";
            if (el.type === "date") return "Elige una fecha.";
            if (el.type === "checkbox") return "Debes aceptar para continuar.";
            var et = etiquetaDe(el);
            return et ? "Completa el campo «" + et + "»." : "Completa este campo.";
        }

        if (v.typeMismatch) {
            if (el.type === "email") return "Escribe un correo válido, por ejemplo: nombre@gmail.com.";
            if (el.type === "url") return "Escribe una dirección web válida.";
            return "El formato no es válido.";
        }

        if (v.patternMismatch) return el.title || "El formato no es válido.";
        if (v.tooShort) return "Escribe al menos " + el.minLength + " caracteres.";
        if (v.tooLong) return "Escribe máximo " + el.maxLength + " caracteres.";
        if (v.rangeUnderflow) return "El valor debe ser mayor o igual a " + el.min + ".";
        if (v.rangeOverflow) return "El valor debe ser menor o igual a " + el.max + ".";
        if (v.badInput) return "El valor escrito no es válido.";
        return "Revisa este campo.";
    }

    function envoltura(el) {
        return el.closest(".password-wrapper, .input-group") || el;
    }

    function limpiar(el) {
        el.classList.remove("sr-invalid");
        if (el._srError) { el._srError.remove(); el._srError = null; }
    }

    function mostrar(el, mensaje) {
        limpiar(el);
        el.classList.add("sr-invalid");

        var caja = document.createElement("div");
        caja.className = "sr-campo-error";
        caja.setAttribute("role", "alert");
        caja.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i><span></span>';
        caja.lastChild.textContent = mensaje;

        envoltura(el).insertAdjacentElement("afterend", caja);
        el._srError = caja;
    }

    function esInvalido(el) {
        if (el.disabled || el.type === "hidden" || el.type === "submit" || el.type === "button" || el.type === "reset") return false;
        if (!el.willValidate) {
            // Los campos readonly + required (latitud/longitud) no se validan solos
            return el.hasAttribute("readonly") && el.required && !String(el.value).trim();
        }
        return !el.checkValidity();
    }

    // Se desactiva la burbuja del navegador en todos los formularios
    function prepararFormularios() {
        document.querySelectorAll("form").forEach(function (f) { f.noValidate = true; });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", prepararFormularios);
    } else {
        prepararFormularios();
    }

    document.addEventListener("submit", function (e) {
        var f = e.target;
        if (!(f instanceof HTMLFormElement)) return;
        if (f.hasAttribute("data-sr-skip")) return;
        if (e.submitter && e.submitter.formNoValidate) return;

        var invalidos = [];

        Array.prototype.forEach.call(f.elements, function (el) {
            if (!el.tagName || !/^(INPUT|SELECT|TEXTAREA)$/.test(el.tagName)) return;
            limpiar(el);
            if (esInvalido(el)) invalidos.push(el);
        });

        if (!invalidos.length) return;

        e.preventDefault();
        e.stopImmediatePropagation();

        invalidos.forEach(function (el) { mostrar(el, mensajeDe(el)); });

        var primero = invalidos[0];
        primero.scrollIntoView({ behavior: "smooth", block: "center" });
        try { primero.focus({ preventScroll: true }); } catch (err) { /* nada */ }
    }, true);

    function alEscribir(e) {
        var el = e.target;
        if (!el || !el._srError) return;
        if (!esInvalido(el)) limpiar(el);
    }

    document.addEventListener("input", alEscribir, true);
    document.addEventListener("change", alEscribir, true);
})();

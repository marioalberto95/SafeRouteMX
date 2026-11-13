// Si el navegador recupera una página privada desde el historial (flecha "atrás"),
// la vuelve a solicitar al servidor para comprobar la sesión.
// Si la sesión ya se cerró, el servidor lo manda al login.
(function () {
    if (window.__srSeguridadSesion) return;   // evita registrarlo dos veces
    window.__srSeguridadSesion = true;

    window.addEventListener("pageshow", function (event) {
        const navegacion = performance.getEntriesByType("navigation")[0];

        const regresoDesdeHistorial =
            event.persisted ||
            (navegacion && navegacion.type === "back_forward");

        if (regresoDesdeHistorial) {
            window.location.reload();
        }
    });
})();

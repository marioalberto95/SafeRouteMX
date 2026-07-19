// Si el navegador recupera una página privada desde el historial,
// la vuelve a solicitar al servidor para comprobar la sesión.
window.addEventListener("pageshow", function (event) {
    const navegacion = performance.getEntriesByType("navigation")[0];

    const regresoDesdeHistorial =
        event.persisted ||
        (navegacion && navegacion.type === "back_forward");

    if (regresoDesdeHistorial) {
        window.location.reload();
    }
});
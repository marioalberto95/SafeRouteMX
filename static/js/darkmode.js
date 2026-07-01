document.addEventListener("DOMContentLoaded", function () {

    const boton = document.getElementById("modoOscuro");

    if(!boton) return;

    const icono = boton.querySelector("i");

    function actualizarTema(){

        if(localStorage.getItem("modo") === "dark"){

            document.body.classList.add("dark");

            icono.classList.remove("fa-moon");
            icono.classList.add("fa-sun");

        }else{

            document.body.classList.remove("dark");

            icono.classList.remove("fa-sun");
            icono.classList.add("fa-moon");

        }

    }

    actualizarTema();

    boton.onclick = function(){

        if(document.body.classList.contains("dark")){

            localStorage.setItem("modo","light");

        }else{

            localStorage.setItem("modo","dark");

        }

        actualizarTema();

    };

});
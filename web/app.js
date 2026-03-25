const contadorPaquetes = document.querySelector("#packet-count");
const estadoFlujo = document.querySelector("#stream-state");
const estadoVacio = document.querySelector("#empty-state");
const direccionCollector = document.querySelector("#collector-addr");
const direccionFrontend = document.querySelector("#frontend-addr");
const contadorDescartados = document.querySelector("#dropped-count");
const contadorAlertas = document.querySelector("#inbound-alert-count");
const cuerpoPerfiles = document.querySelector("#profiles-body");

const idsVistos = new Set();
let totalAlertas = 0;

iniciar();

async function iniciar() {
  await cargarConfiguracion();
  await cargarPaquetesIniciales();
  await cargarEstadisticas();
  await cargarPerfiles();
  abrirStream();

  window.setInterval(cargarEstadisticas, 2000);
  window.setInterval(cargarPerfiles, 2000);
}

async function cargarConfiguracion() {
  const respuesta = await fetch("/api/config");
  const configuracion = await respuesta.json();
  direccionCollector.textContent = configuracion.collectorAddr || "-";
  direccionFrontend.textContent = configuracion.frontendAddr || "-";
}

async function cargarPaquetesIniciales() {
  const respuesta = await fetch("/api/packets");
  const paquetes = await respuesta.json();
  paquetes.forEach(registrarPaquete);
}

async function cargarEstadisticas() {
  const respuesta = await fetch("/api/stats");
  const estadisticas = await respuesta.json();
  contadorDescartados.textContent = String(estadisticas.dropped || 0);
}

async function cargarPerfiles() {
  const respuesta = await fetch("/api/perfiles");
  const perfiles = await respuesta.json();
  estadoVacio.hidden = perfiles.length > 0;

  const filas = perfiles.map((perfil) => {
    const fila = document.createElement("tr");
    fila.innerHTML = [
      `<td>${escaparHtml(perfil.ip)}</td>`,
      `<td>${formatearNumero(perfil.promedio_mbps, 3)}</td>`,
      `<td>${formatearNumero(perfil.desvio_mbps, 3)}</td>`,
      `<td>${formatearNumero(perfil.promedio_pps, 2)}</td>`,
      `<td>${formatearNumero(perfil.desvio_pps, 2)}</td>`,
      `<td>${Number(perfil.muestras_pps || 0)}</td>`,
      `<td>${escaparHtml((perfil.protocolos_top || []).join(", ") || "-")}</td>`,
      `<td>${formatearFecha(perfil.ultima_muestra)}</td>`,
    ].join("");
    return fila;
  });

  cuerpoPerfiles.replaceChildren(...filas);
}

function abrirStream() {
  const eventos = new EventSource("/api/events");
  eventos.onopen = () => {
    estadoFlujo.textContent = "live";
  };
  eventos.onmessage = (evento) => {
    registrarPaquete(JSON.parse(evento.data));
  };
  eventos.onerror = () => {
    estadoFlujo.textContent = "reconnecting";
  };
}

function registrarPaquete(paquete) {
  if (idsVistos.has(paquete.id)) {
    return;
  }
  idsVistos.add(paquete.id);
  if (paquete.alert) {
    totalAlertas += 1;
  }

  contadorPaquetes.textContent = String(idsVistos.size);
  contadorAlertas.textContent = String(totalAlertas);
}

function formatearNumero(valor, decimales) {
  return Number(valor || 0).toFixed(decimales);
}

function formatearFecha(fechaISO) {
  if (!fechaISO) {
    return "-";
  }
  const fecha = new Date(fechaISO);
  if (Number.isNaN(fecha.getTime())) {
    return "-";
  }
  return fecha.toLocaleString();
}

function escaparHtml(valor) {
  return String(valor)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

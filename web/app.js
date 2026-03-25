const contadorPaquetes = document.querySelector("#packet-count");
const estadoFlujo = document.querySelector("#stream-state");
const estadoVacio = document.querySelector("#empty-state");
const direccionCollector = document.querySelector("#collector-addr");
const direccionFrontend = document.querySelector("#frontend-addr");
const nombreFiltro = document.querySelector("#filter-name");
const contadorBloqueados = document.querySelector("#blocked-count");
const contadorDescartados = document.querySelector("#dropped-count");
const contadorProtocolos = document.querySelector("#protocol-count");
const protocoloDominante = document.querySelector("#dominant-protocol");
const protocoloTop = document.querySelector("#top-protocol");
const porcentajeTop = document.querySelector("#top-protocol-share");
const graficoProtocolos = document.querySelector("#protocol-chart");
const leyendaProtocolos = document.querySelector("#protocol-legend");

const totalEventosInbound = document.querySelector("#inbound-events");
const totalAlertasInbound = document.querySelector("#inbound-alert-count");
const ppsActualInbound = document.querySelector("#inbound-current-pps");
const ppsBaseInbound = document.querySelector("#inbound-baseline-pps");
const ppsSpikeInbound = document.querySelector("#inbound-spike-pps");
const perfilActivoInbound = document.querySelector("#inbound-profile-active");
const perfilClaveInbound = document.querySelector("#inbound-profile-key");
const destinoLocalInbound = document.querySelector("#inbound-destination-local");
const banderaAlertaInbound = document.querySelector("#inbound-alert-flag");
const nombreAlertaInbound = document.querySelector("#inbound-alert-name");
const razonAlertaInbound = document.querySelector("#inbound-alert-reason");
const razonFiltroInbound = document.querySelector("#inbound-filter-reason");

const idsVistos = new Set();
const totalesProtocolo = new Map();
let totalBloqueados = 0;
let eventosInbound = 0;
let alertasInbound = 0;
let ultimoInbound = null;

const coloresGrafico = [
  "#7EE0C6",
  "#45B4FF",
  "#FFB36D",
  "#FF7A90",
  "#A78BFA",
  "#FFE066",
  "#4ADE80",
  "#FB7185",
  "#38BDF8",
  "#F472B6",
];

iniciar();

async function iniciar() {
  await cargarConfiguracion();
  await cargarPaquetesIniciales();
  await cargarEstadisticas();
  abrirStream();
  window.setInterval(cargarEstadisticas, 2000);
  renderizarGraficoProtocolos();
  renderizarDatosInbound();
}

async function cargarConfiguracion() {
  const respuesta = await fetch("/api/config");
  const configuracion = await respuesta.json();
  direccionCollector.textContent = configuracion.collectorAddr || "-";
  direccionFrontend.textContent = configuracion.frontendAddr || "-";
  nombreFiltro.textContent = configuracion.activeFilters || "-";
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

  const protocolo = paquete.protocol || paquete.transport || paquete.network || "Unknown";
  totalesProtocolo.set(protocolo, (totalesProtocolo.get(protocolo) || 0) + 1);

  if (paquete.filterAction === "blocked") {
    totalBloqueados += 1;
  }

  if (paquete.profileActive || paquete.filterName === "inbound-global-profile") {
    eventosInbound += 1;
    ultimoInbound = paquete;

    if (paquete.alert) {
      alertasInbound += 1;
    }
  }

  renderizarGraficoProtocolos();
  renderizarDatosInbound();
}

function renderizarGraficoProtocolos() {
  const entradas = [...totalesProtocolo.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const total = entradas.reduce((suma, [, conteo]) => suma + conteo, 0);

  contadorPaquetes.textContent = String(total);
  contadorProtocolos.textContent = String(entradas.length);
  contadorBloqueados.textContent = String(totalBloqueados);
  estadoVacio.hidden = total > 0;

  if (total === 0) {
    protocoloDominante.textContent = "-";
    protocoloTop.textContent = "-";
    porcentajeTop.textContent = "0%";
    leyendaProtocolos.replaceChildren();
    graficoProtocolos.style.background =
      "radial-gradient(circle at center, rgba(8, 17, 31, 0.98) 0 34%, transparent 35% 100%), conic-gradient(from -90deg, rgba(125, 169, 255, 0.18) 0 100%)";
    return;
  }

  const [ganadorNombre, ganadorConteo] = entradas[0];
  const ganadorPorcentaje = Math.round((ganadorConteo / total) * 1000) / 10;
  protocoloDominante.textContent = ganadorNombre;
  protocoloTop.textContent = ganadorNombre;
  porcentajeTop.textContent = `${ganadorPorcentaje}%`;

  const segmentos = [];
  let porcentajeActual = 0;

  entradas.forEach(([nombre, conteo], indice) => {
    const color = coloresGrafico[indice % coloresGrafico.length];
    const siguientePorcentaje = porcentajeActual + (conteo / total) * 100;
    segmentos.push(`${color} ${porcentajeActual}% ${siguientePorcentaje}%`);
    porcentajeActual = siguientePorcentaje;
  });

  graficoProtocolos.style.background =
    `radial-gradient(circle at center, rgba(8, 17, 31, 0.98) 0 34%, transparent 35% 100%), conic-gradient(from -90deg, ${segmentos.join(", ")})`;

  const filas = entradas.map(([nombre, conteo], indice) => {
    const porcentaje = Math.round((conteo / total) * 1000) / 10;
    const color = coloresGrafico[indice % coloresGrafico.length];

    const fila = document.createElement("div");
    fila.className = "legend-item";
    fila.innerHTML = [
      `<span class="legend-color" style="background:${color}"></span>`,
      `<span class="legend-name">${escaparHtml(nombre)}</span>`,
      `<span class="legend-count">${conteo}</span>`,
      `<span class="legend-share">${porcentaje}%</span>`,
    ].join("");
    return fila;
  });

  leyendaProtocolos.replaceChildren(...filas);
}

function renderizarDatosInbound() {
  totalEventosInbound.textContent = String(eventosInbound);
  totalAlertasInbound.textContent = String(alertasInbound);

  if (!ultimoInbound) {
    ppsActualInbound.textContent = "0.0";
    ppsBaseInbound.textContent = "0.0";
    ppsSpikeInbound.textContent = "0.0";
    perfilActivoInbound.textContent = "false";
    perfilClaveInbound.textContent = "-";
    destinoLocalInbound.textContent = "false";
    banderaAlertaInbound.textContent = "false";
    nombreAlertaInbound.textContent = "-";
    razonAlertaInbound.textContent = "-";
    razonFiltroInbound.textContent = "-";
    return;
  }

  ppsActualInbound.textContent = formatearTasa(ultimoInbound.currentPPS);
  ppsBaseInbound.textContent = formatearTasa(ultimoInbound.baselinePPS);
  ppsSpikeInbound.textContent = formatearTasa(ultimoInbound.spikePPS);
  perfilActivoInbound.textContent = String(Boolean(ultimoInbound.profileActive));
  perfilClaveInbound.textContent = ultimoInbound.profileKey || "-";
  destinoLocalInbound.textContent = String(Boolean(ultimoInbound.destinationIsLocal));
  banderaAlertaInbound.textContent = String(Boolean(ultimoInbound.alert));
  nombreAlertaInbound.textContent = ultimoInbound.alertName || "-";
  razonAlertaInbound.textContent = ultimoInbound.alertReason || "-";
  razonFiltroInbound.textContent = ultimoInbound.filterReason || "-";
}

function formatearTasa(valor) {
  return Number(valor || 0).toFixed(1);
}

function escaparHtml(valor) {
  return String(valor)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

const packetCount = document.querySelector("#packet-count");
const streamState = document.querySelector("#stream-state");
const emptyState = document.querySelector("#empty-state");
const protocolCount = document.querySelector("#protocol-count");
const dominantProtocol = document.querySelector("#dominant-protocol");
const topProtocol = document.querySelector("#top-protocol");
const topProtocolShare = document.querySelector("#top-protocol-share");
const protocolChart = document.querySelector("#protocol-chart");
const protocolLegend = document.querySelector("#protocol-legend");

const seenPacketIDs = new Set();
const protocolTotals = new Map();
const chartColors = [
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

boot();

async function boot() {
  await loadInitialPackets();
  openStream();
  renderProtocolChart();
}

async function loadInitialPackets() {
  const response = await fetch("/api/packets");
  const packets = await response.json();
  packets.forEach(registerPacket);
}

function openStream() {
  const events = new EventSource("/api/events");

  events.onopen = () => {
    streamState.textContent = "live";
  };

  events.onmessage = (event) => {
    registerPacket(JSON.parse(event.data));
  };

  events.onerror = () => {
    streamState.textContent = "reconnecting";
  };
}

function registerPacket(packet) {
  if (seenPacketIDs.has(packet.id)) {
    return;
  }

  seenPacketIDs.add(packet.id);

  const protocol = packet.protocol || packet.transport || packet.network || "Unknown";
  protocolTotals.set(protocol, (protocolTotals.get(protocol) || 0) + 1);

  renderProtocolChart();
}

function renderProtocolChart() {
  const entries = [...protocolTotals.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const total = entries.reduce((sum, [, count]) => sum + count, 0);

  packetCount.textContent = String(total);
  protocolCount.textContent = String(entries.length);
  emptyState.hidden = total > 0;

  if (total === 0) {
    dominantProtocol.textContent = "-";
    topProtocol.textContent = "-";
    topProtocolShare.textContent = "0%";
    protocolLegend.replaceChildren();
    protocolChart.style.background =
      "radial-gradient(circle at center, rgba(8, 17, 31, 0.98) 0 34%, transparent 35% 100%), conic-gradient(from -90deg, rgba(125, 169, 255, 0.18) 0 100%)";
    return;
  }

  const [winnerName, winnerCount] = entries[0];
  const winnerShare = Math.round((winnerCount / total) * 1000) / 10;
  dominantProtocol.textContent = winnerName;
  topProtocol.textContent = winnerName;
  topProtocolShare.textContent = `${winnerShare}%`;

  const segments = [];
  let current = 0;

  entries.forEach(([name, count], index) => {
    const color = chartColors[index % chartColors.length];
    const next = current + (count / total) * 100;
    segments.push(`${color} ${current}% ${next}%`);
    current = next;
  });

  protocolChart.style.background =
    `radial-gradient(circle at center, rgba(8, 17, 31, 0.98) 0 34%, transparent 35% 100%), conic-gradient(from -90deg, ${segments.join(", ")})`;

  const items = entries.map(([name, count], index) => {
    const share = Math.round((count / total) * 1000) / 10;
    const color = chartColors[index % chartColors.length];

    const row = document.createElement("div");
    row.className = "legend-item";
    row.innerHTML = [
      `<span class="legend-color" style="background:${color}"></span>`,
      `<span class="legend-name">${escapeHtml(name)}</span>`,
      `<span class="legend-count">${count}</span>`,
      `<span class="legend-share">${share}%</span>`,
    ].join("");
    return row;
  });

  protocolLegend.replaceChildren(...items);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

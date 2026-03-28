// State Management
const state = {
    currentView: 'overview',
    config: {},
    globalStats: { mbps: 0, pps: 0, targets: 0, alerts: 0 },
    profiles: [],
    alerts: [],
    activeIP: null,
    inspectorFilter: { src: '', dst: '', port: '', proto: '', keyword: '' },
    inspectorPaused: false,
    ipFlagsChart: null,
    ipPortsChart: null,
    ipSourcesChart: null,
    ipSrcPortsChart: null,
    ipL4ProtoChart: null,
    ipTtlChart: null,
    ipPpsLineChart: null,
    activeIPHistory: { labels: [], pps: [] }
};

// DOM Elements
const elements = {
    views: document.querySelectorAll('.view'),
    navItems: document.querySelectorAll('.nav-item'),
    streamState: document.getElementById('stream-state'),
    collectorAddr: document.getElementById('collector-addr'),
    globalMbps: document.getElementById('global-mbps'),
    globalPps: document.getElementById('global-pps'),
    activeTargets: document.getElementById('active-targets'),
    alertCount: document.getElementById('alert-count'),
    topTargetsList: document.getElementById('top-targets-list'),
    profilesBody: document.getElementById('profiles-body'),
    inspectorBody: document.getElementById('inspector-body'),
    alertsHistory: document.getElementById('alerts-history'),
    inspectSrc: document.getElementById('inspect-src'),
    inspectDst: document.getElementById('inspect-dst'),
    inspectPort: document.getElementById('inspect-port'),
    inspectProto: document.getElementById('inspect-proto'),
    inspectKeyword: document.getElementById('inspect-keyword'),
    inspectClearBtn: document.getElementById('inspect-clear-btn'),
    inspectorToggleBtn: document.getElementById('inspector-toggle-btn'),
    globalSearch: document.getElementById('global-search')
};

// Charts
let globalPpsChart = null;
const ppsChartData = {
    labels: [],
    datasets: []
};

// Formatting Helpers
function formatShortTime(iso) {
    if (!iso) return '-';
    const d = new Date(iso);
    const ss = String(d.getSeconds()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    const hh = String(d.getHours()).padStart(2, '0');
    return `${hh}:${mm}:${ss}`;
}

function formatDate(iso) {
    if (!iso) return '-';
    const d = new Date(iso);
    const day = String(d.getDate()).padStart(2, '0');
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const year = d.getFullYear();
    return `${day}/${month}/${year}`;
}

function formatFullDateTime(iso) {
    if (!iso) return '-';
    return `${formatShortTime(iso)} ${formatDate(iso)}`;
}

function formatDuration(start) {
    if (!start) return '-';
    const diff = Math.floor((new Date() - new Date(start)) / 1000);
    if (diff < 60) return `${diff}s`;
    const m = Math.floor(diff / 60);
    const s = diff % 60;
    if (m < 60) return `${m}m ${s}s`;
    const h = Math.floor(m / 60);
    const rm = m % 60;
    return `${h}h ${rm}m`;
}

function getProtocolName(port) {
    const p = parseInt(port);
    const common = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 123: 'NTP', 143: 'IMAP',
        161: 'SNMP', 179: 'BGP', 443: 'HTTPS', 500: 'IKE-VPN', 1194: 'OpenVPN',
        1900: 'SSDP', 3306: 'MySQL', 3389: 'RDP', 5353: 'mDNS', 5432: 'PostgreSQL',
        6379: 'Redis', 8080: 'Proxy', 25565: 'Minecraft', 51820: 'WireGuard'
    };
    if (p >= 27015 && p <= 27030) return 'Games';
    return common[p] || `Port ${p}`;
}

// Initialization
async function init() {
    setupNavigation();
    setupSearch();
    setupInspector();
    initCharts();
    await loadConfig();
    refreshAll();
    startEventStream();
    
    // Periodic tasks
    setInterval(refreshStats, 3000);
    setInterval(() => {
        refreshCurrentView();
    }, 5000);
}

// Navigation Logic
function setupNavigation() {
    elements.navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const view = item.getAttribute('data-view');
            switchView(view);
        });
    });
    window.addEventListener('hashchange', () => {
        const hash = window.location.hash.replace('#', '') || 'overview';
        switchView(hash);
    });
}

function switchView(viewId) {
    state.currentView = viewId;
    elements.navItems.forEach(item => {
        item.classList.toggle('active', item.getAttribute('data-view') === viewId);
    });
    elements.views.forEach(view => {
        view.style.display = view.id === `view-${viewId}` ? 'block' : 'none';
    });

    refreshCurrentView();
}

function setupSearch() {
    if (!elements.globalSearch) return;
    elements.globalSearch.addEventListener('input', (e) => {
        const term = e.target.value.toLowerCase();
        filterCurrentView(term);
    });
}

function filterCurrentView(term) {
    const rows = document.querySelectorAll(`#view-${state.currentView} tbody tr`);
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(term) ? '' : 'none';
    });
}

function setupInspector() {
    if (!elements.inspectorToggleBtn) return;

    elements.inspectorToggleBtn.addEventListener('click', () => {
        state.inspectorPaused = !state.inspectorPaused;
        const btn = elements.inspectorToggleBtn;
        const icon = btn.querySelector('i');
        const span = btn.querySelector('span');

        if (state.inspectorPaused) {
            btn.style.backgroundColor = 'var(--accent-green)';
            icon.setAttribute('data-lucide', 'play');
            span.textContent = 'Start Stream';
        } else {
            btn.style.backgroundColor = 'var(--accent-red)';
            icon.setAttribute('data-lucide', 'pause');
            span.textContent = 'Stop Stream';
        }
        lucide.createIcons();
    });

    elements.inspectClearBtn.addEventListener('click', () => {
        if (elements.inspectorBody) elements.inspectorBody.innerHTML = '';
    });

    // Reactive filters
    ['inspectSrc', 'inspectDst', 'inspectPort', 'inspectProto', 'inspectKeyword'].forEach(key => {
        if (elements[key]) {
            elements[key].addEventListener('input', (e) => {
                state.inspectorFilter[key.replace('inspect', '').toLowerCase()] = e.target.value.toLowerCase();
            });
        }
    });
}

function refreshCurrentView() {
    switch (state.currentView) {
        case 'overview':
            refreshProfiles(); 
            break;
        case 'protected-ips':
            refreshProfiles();
            break;
        case 'connections':
            loadConnections();
            break;
        case 'intelligence':
            loadAlerts();
            loadGlobalReputations();
            break;
        case 'inspector':
            if (elements.inspectorBody && elements.inspectorBody.children.length === 0) {
                loadInitialPackets();
            }
            break;
        case 'blocklist':
            loadBlocklistFiles();
            loadWhitelist();
            break;
        case 'mitigation':
            loadMitigationStatus();
            break;
        case 'ip-detail':
            updateActiveIPDetail();
            break;
    }
}

// Chart Logic
function initCharts() {
    const ctx = document.getElementById('globalPpsChart').getContext('2d');
    if (!ctx) return;
    globalPpsChart = new Chart(ctx, {
        type: 'line',
        data: ppsChartData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            scales: {
                x: { grid: { display: false }, ticks: { color: '#8b949e' } },
                y: { 
                    beginAtZero: true, 
                    grid: { color: '#30363d' }, 
                    ticks: { 
                        color: '#8b949e',
                        stepSize: 1,
                        callback: function(value) {
                            if (value % 1 !== 0) return null;
                            return value.toLocaleString();
                        }
                    } 
                }
            },
            plugins: { legend: { display: false } },
            elements: { line: { tension: 0.4, borderWidth: 2 }, point: { radius: 0 } },
            animation: { duration: 0 }
        }
    });
}

function updateGlobalChart(profiles) {
    if (!globalPpsChart) return;
    const now = formatShortTime(new Date());
    if (ppsChartData.labels.length > 30) {
        ppsChartData.labels.shift();
        ppsChartData.datasets.forEach(ds => ds.data.shift());
    }
    ppsChartData.labels.push(now);
    profiles.forEach(p => {
        let dataset = ppsChartData.datasets.find(ds => ds.label === p.ip);
        if (!dataset) {
            const color = getRandomColor();
            dataset = {
                label: p.ip,
                data: new Array(ppsChartData.labels.length - 1).fill(0),
                borderColor: color,
                backgroundColor: color + '22',
                fill: true
            };
            ppsChartData.datasets.push(dataset);
        }
        dataset.data.push(Math.round(p.current_pps));
    });
    globalPpsChart.update();
}

// Data Fetching
async function loadConfig() {
    try {
        const res = await fetch('/api/config');
        state.config = await res.json();
        elements.collectorAddr.textContent = state.config.collectorAddr;
    } catch (err) {}
}

async function refreshStats() {
    try {
        const [summaryRes, alertsRes] = await Promise.all([
            fetch('/api/global-summary'),
            fetch('/api/alerts')
        ]);
        const summary = await summaryRes.json();
        const alerts = await alertsRes.json();
        
        elements.globalMbps.textContent = summary.total_current_mbps.toFixed(2);
        elements.globalPps.textContent = Math.round(summary.total_current_pps).toLocaleString();
        elements.activeTargets.textContent = summary.active_targets;
        elements.alertCount.textContent = alerts.length;
        
        // Visual indicator for active alerts
        const alertCard = elements.alertCount.closest('.stat-card');
        if (alertCard) {
            if (alerts.length > 0) {
                alertCard.classList.add('glow-red');
            } else {
                alertCard.classList.remove('glow-red');
            }
        }
    } catch (err) {}
}

async function refreshProfiles() {
    try {
        const res = await fetch('/api/profiles');
        state.profiles = await res.json();
        renderProfilesTable();
        renderTopTargets();
        updateGlobalChart(state.profiles);
    } catch (err) {}
}

async function loadInitialPackets() {
    try {
        const res = await fetch('/api/packets');
        const pkts = await res.json();
        renderInspectorTable(pkts);
    } catch (err) {}
}

async function loadAlerts() {
    try {
        const res = await fetch('/api/alerts');
        state.alerts = await res.json();
        renderAlertsList();
        elements.alertCount.textContent = state.alerts.length;
    } catch (err) {}
}

async function loadGlobalReputations() {
    try {
        const res = await fetch('/api/reputation/all');
        const reputations = await res.json();
        renderIntelligenceTable(reputations);
    } catch (err) {}
}

async function loadConnections() {
    try {
        const res = await fetch('/api/connections');
        const conns = await res.json();
        renderConnectionsTable(conns);
    } catch (err) {}
}

// Rendering
function renderProfilesTable() {
    if (!elements.profilesBody) return;
    elements.profilesBody.innerHTML = state.profiles.map(p => {
        const statusClass = p.puntaje_amenaza > 80 ? 'badge-red' : (p.puntaje_amenaza > 40 ? 'badge-purple' : 'badge-green');
        const statusText = p.puntaje_amenaza > 80 ? 'Under Attack' : (p.puntaje_amenaza > 40 ? 'Anomalous' : 'Clean');
        const protoNames = (p.protocolos_top || []).map(port => getProtocolName(port));
        return `
            <tr>
                <td><strong style="color: var(--accent-blue)">${p.ip}</strong></td>
                <td>${p.current_mbps.toFixed(2)} <small>Mbps</small></td>
                <td>${Math.round(p.current_pps).toLocaleString()} <small>PPS</small></td>
                <td><span class="badge ${statusClass}">${statusText}</span></td>
                <td><small>${protoNames.join(', ')}</small></td>
                <td>${formatShortTime(p.ultima_muestra)}</td>
                <td><button class="primary-btn" onclick="showIPDetail('${p.ip}')">Inspect</button></td>
            </tr>
        `;
    }).join('');
}

function renderTopTargets() {
    const sorted = [...state.profiles].sort((a, b) => b.current_pps - a.current_pps).slice(0, 5);
    if (sorted.length === 0) {
        elements.topTargetsList.innerHTML = '<div class="empty-state">No active traffic.</div>';
        return;
    }
    elements.topTargetsList.innerHTML = sorted.map(p => `
        <div class="mini-item">
            <span class="ip">${p.ip}</span>
            <span class="val">${Math.round(p.current_pps).toLocaleString()} <small>PPS</small></span>
        </div>
    `).join('');
}

function renderInspectorTable(packets) {
    if (!elements.inspectorBody) return;
    elements.inspectorBody.innerHTML = '';
    packets.forEach(p => appendPacketToInspector(p, true));
}

function renderConnectionsTable(conns) {
    const tbody = document.getElementById('connections-body-view');
    if (!tbody) return;
    
    if (!conns || conns.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No active TCP connections.</td></tr>';
        return;
    }

    tbody.innerHTML = conns.sort((a,b) => new Date(b.last_seen) - new Date(a.last_seen)).map(c => `
        <tr>
            <td><code>${c.src_ip}:${c.src_port}</code></td>
            <td><code>${c.dst_ip}:${c.dst_port}</code></td>
            <td><span class="badge badge-blue">${c.protocol}</span></td>
            <td><strong>${formatDuration(c.start_time)}</strong></td>
            <td><span style="color: var(--text-secondary)">${formatShortTime(c.last_seen)}</span></td>
        </tr>
    `).join('');
}

function renderAlertsList() {
    if (!elements.alertsHistory) return;
    const sorted = [...state.alerts].sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp));
    elements.alertsHistory.innerHTML = sorted.map(a => `
        <div class="alert-item">
            <div class="icon"><i data-lucide="alert-octagon"></i></div>
            <div class="alert-content">
                <div class="time">${formatFullDateTime(a.timestamp)}</div>
                <div class="msg">${a.alert_name} on ${a.dst_ip || '-'}</div>
                <div class="reason">${a.alert_reason}</div>
            </div>
        </div>
    `).join('');
    lucide.createIcons();
}

function renderIntelligenceTable(reputations) {
    const tbody = document.getElementById('top-reputations-body');
    if (!tbody) return;
    const sorted = Object.values(reputations).sort((a,b) => b.trust_score - a.trust_score);
    tbody.innerHTML = sorted.slice(0, 20).map(r => {
        const logId = `log-intel-${r.ip.replace(/\./g, '-')}`;
        return `
            <tr onclick="toggleLog('${logId}')" style="cursor: pointer;">
                <td><code style="color: var(--accent-purple)">${r.ip}</code></td>
                <td><span class="badge ${r.trust_score >= 70 ? 'badge-green' : (r.trust_score >= 40 ? 'badge-purple' : 'badge-red')}">${r.trust_score}%</span></td>
                <td><div style="display:flex; gap:5px; align-items:center;">
                    ${r.handshake_completed ? '<span class="badge badge-blue">TCP-OK</span>' : ''}
                    <button class="primary-btn" style="padding: 4px 8px; font-size: 11px;" onclick="event.stopPropagation(); trustIPManual('${r.ip}')">Trust</button>
                </div></td>
            </tr>
            <tr id="${logId}" style="display: none; background: rgba(0,0,0,0.2);">
                <td colspan="3" style="padding: 10px 24px;">
                    <div style="font-size: 12px; color: var(--text-secondary);">
                        <strong>Score History:</strong>
                        ${renderScoreLog(r.history)}
                    </div>
                </td>
            </tr>

        `;
    }).join('');
}

function renderScoreLog(log) {
    if (!log || log.length === 0) return ' No events recorded.';
    return `<ul style="list-style: none; padding: 5px 0; margin: 0;">
        ${log.map(e => `
            <li style="margin-bottom: 4px;">
                <span style="color: ${e.delta >= 0 ? 'var(--accent-green)' : 'var(--accent-red)'}">
                    ${e.delta >= 0 ? '+' : ''}${e.delta}
                </span>
                <span style="margin-left: 8px;">${e.reason}</span>
                <small style="float: right; color: var(--text-secondary);">${formatShortTime(e.timestamp)}</small>
            </li>
        `).join('')}
    </ul>`;
}

window.toggleLog = (id) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.display = el.style.display === 'none' ? 'table-row' : 'none';
};

// Blocklist View Logic
async function loadBlocklistFiles() {
    try {
        const res = await fetch('/api/blocklist/files');
        const files = await res.json();
        const list = document.getElementById('blocklist-files-list');
        list.innerHTML = files.map(f => `
            <div class="mini-item">
                <span class="ip"><i data-lucide="file-text" style="width:14px; vertical-align:middle; margin-right:8px;"></i>${f}</span>
                <span class="badge badge-blue">ACTIVE</span>
            </div>
        `).join('') || '<div class="empty-state">No blocklist files found.</div>';
        lucide.createIcons();
    } catch (err) {}
}

window.submitManualBlock = async () => {
    const entry = document.getElementById('new-block-entry').value.trim();
    if (!entry) return alert('Entry cannot be empty.');
    try {
        const res = await fetch('/api/blocklist/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ entry })
        });
        if (res.ok) {
            alert('Added to manual.list');
            document.getElementById('new-block-entry').value = '';
            loadBlocklistFiles();
        }
    } catch (err) { alert('Error adding block.'); }
};

// Whitelist Logic
async function loadWhitelist() {
    try {
        const res = await fetch('/api/reputation/all');
        const reputations = await res.json();
        const whitelist = Object.values(reputations).filter(r => r.is_manual_trust);
        const tbody = document.getElementById('whitelist-body');
        if (!tbody) return;
        tbody.innerHTML = whitelist.map(r => `
            <tr>
                <td><code>${r.ip}</code></td>
                <td><span class="badge badge-green">TRUSTED</span></td>
                <td>${formatDate(r.last_seen)}</td>
                <td><button class="primary-btn" style="background-color: var(--accent-red); padding: 4px 8px; font-size: 11px;" onclick="untrustIP('${r.ip}')">Revoke</button></td>
            </tr>
        `).join('') || '<tr><td colspan="4" class="empty-state">No whitelist rules.</td></tr>';
    } catch (err) {}
}

// IP Detail View
window.showIPDetail = async (ip) => {
    state.activeIP = ip;
    state.activeIPHistory = { labels: [], pps: [] }; // Reset history for new IP
    const container = document.getElementById('ip-detail-container');
    const reputationContainer = document.getElementById('ip-detail-reputation-container');
    switchView('ip-detail');
    
    try {
        const res = await fetch(`/api/profile-detail?ip=${ip}`);
        const data = await res.json();
        
        container.innerHTML = `
            <div class="view-header">
                <div style="display: flex; align-items: center; gap: 20px;">
                    <button class="icon-btn" onclick="switchView('protected-ips')"><i data-lucide="arrow-left"></i></button>
                    <div><h1>IP Insight: ${ip}</h1><p>Persistent baseline and threat analysis.</p></div>
                </div>
            </div>
            <div class="stats-grid">
                <div class="glass-card stat-card glow-blue"><div class="card-content"><span class="label">Max Peak PPS</span><strong>${Math.round(data.stats_historicas.max_pps).toLocaleString()}</strong></div></div>
                <div class="glass-card stat-card glow-purple"><div class="card-content"><span class="label">Max Peak Mbps</span><strong>${data.stats_historicas.max_mbps.toFixed(2)}</strong></div></div>
                <div class="glass-card stat-card"><div class="card-content"><span class="label">Lifetime Packets</span><strong>${data.stats_historicas.total_packets_processed.toLocaleString()}</strong></div></div>
                <div class="glass-card stat-card"><div class="card-content"><span class="label">Total Data</span><strong>${(data.stats_historicas.total_bytes_processed / 1024 / 1024).toFixed(2)} MB</strong></div></div>
            </div>
            <div class="content-grid" style="grid-template-columns: 1fr 1fr 1fr; margin-bottom: 24px;">
                <div class="glass-card stat-card"><div class="card-content"><span class="label">Dominant TTL</span><strong>${data.perfil_trafico.ttl_dominante || 'N/A'}</strong></div></div>
                <div class="glass-card stat-card"><div class="card-content"><span class="label">Avg MTU</span><strong>${data.perfil_trafico.mtu_promedio || 'N/A'}</strong></div></div>
                <div class="glass-card stat-card glow-green"><div class="card-content"><span class="label">Active Sources</span><strong>${Object.keys(data.reputacion_origenes || {}).length}</strong></div></div>
            </div>
        `;

        // Initialize Line Chart
        initIPLineChart();

        reputationContainer.innerHTML = `
            <div class="glass-card">
                <div class="card-header"><h3>External Source Reputation</h3></div>
                <div class="table-container">
                    <table>
                        <thead><tr><th>Source IP</th><th>Trust</th><th>Handshake</th><th>Manual</th><th>Last Seen</th></tr></thead>
                        <tbody>${Object.values(data.reputacion_origenes || {}).sort((a,b) => b.trust_score - a.trust_score).slice(0, 50).map(r => {
                            const logId = `log-detail-${r.ip.replace(/\./g, '-')}`;
                            return `
                            <tr onclick="toggleLog('${logId}')" style="cursor: pointer;">
                                <td><code>${r.ip}</code></td>
                                <td><span class="badge ${r.trust_score > 70 ? 'badge-green' : 'badge-red'}">${r.trust_score}%</span></td>
                                <td>${r.handshake_completed ? '<span class="badge badge-blue">DONE</span>' : '<span class="badge" style="background:var(--border-color)">PENDING</span>'}</td>
                                <td>${r.is_manual_trust ? '✅' : '❌'}</td>
                                <td><small>${formatFullDateTime(r.last_seen)}</small></td>
                            </tr>
                            <tr id="${logId}" style="display: none; background: rgba(0,0,0,0.2);">
                                <td colspan="5" style="padding: 10px 24px;">
                                    <div style="font-size: 12px; color: var(--text-secondary);">
                                        <strong>Score History:</strong>
                                        ${renderScoreLog(r.history)}
                                    </div>
                                </td>
                            </tr>
                        `;}).join('') || '<tr><td colspan="5" class="empty-state">No sources tracked yet.</td></tr>'}</tbody>
                    </table>
                </div>
            </div>
        `;

        // Render Charts
        renderIPCharts(data);
        lucide.createIcons();
    } catch (err) {
        console.error("Error loading IP detail:", err);
    }
};

function initIPLineChart() {
    const ctx = document.getElementById('ipPpsLineChart');
    if (!ctx) return;
    if (state.ipPpsLineChart) state.ipPpsLineChart.destroy();
    state.ipPpsLineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: state.activeIPHistory.labels,
            datasets: [{
                label: 'PPS',
                data: state.activeIPHistory.pps,
                borderColor: '#58a6ff',
                backgroundColor: 'rgba(88, 166, 255, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            maintainAspectRatio: false,
            responsive: true,
            scales: {
                x: { display: false },
                y: { beginAtZero: true, grid: { color: '#30363d' }, ticks: { color: '#8b949e' } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function renderIPCharts(data) {
    const flagCtx = document.getElementById('ipFlagsChart');
    const portCtx = document.getElementById('ipPortsChart');
    const srcCtx = document.getElementById('ipSourcesChart');
    const srcPortCtx = document.getElementById('ipSrcPortsChart');
    const l4Ctx = document.getElementById('ipL4ProtoChart');
    const ttlCtx = document.getElementById('ipTtlChart');
    
    if (!flagCtx || !portCtx || !srcCtx || !srcPortCtx || !l4Ctx || !ttlCtx) return;

    const colors = ['#58a6ff', '#bc8cff', '#3fb950', '#f85149', '#d29922', '#1f6feb', '#8957e5', '#238636'];

    const chartOptions = {
        maintainAspectRatio: false,
        plugins: {
            legend: { position: 'right', labels: { color: '#8b949e', font: { size: 10 }, boxWidth: 10 } }
        }
    };

    // 1. L4 Protocols
    const l4Entries = Object.entries(data.protocolos_frecuentes || {}).sort((a,b)=>b[1]-a[1]);
    if (state.ipL4ProtoChart) state.ipL4ProtoChart.destroy();
    state.ipL4ProtoChart = new Chart(l4Ctx, {
        type: 'pie',
        data: { labels: l4Entries.map(e => e[0]), datasets: [{ data: l4Entries.map(e => e[1]), backgroundColor: colors }] },
        options: chartOptions
    });

    // 2. TCP Flags
    const flagEntries = Object.entries(data.distribucion_flags_total || {}).sort((a,b)=>b[1]-a[1]).slice(0, 8);
    if (state.ipFlagsChart) state.ipFlagsChart.destroy();
    state.ipFlagsChart = new Chart(flagCtx, {
        type: 'pie',
        data: { labels: flagEntries.map(e => e[0]), datasets: [{ data: flagEntries.map(e => e[1]), backgroundColor: colors }] },
        options: chartOptions
    });

    // 3. TTL
    const ttlEntries = Object.entries(data.distribucion_ttl || {}).sort((a,b)=>b[1]-a[1]).slice(0, 8);
    if (state.ipTtlChart) state.ipTtlChart.destroy();
    state.ipTtlChart = new Chart(ttlCtx, {
        type: 'pie',
        data: { labels: ttlEntries.map(e => `TTL ${e[0]}`), datasets: [{ data: ttlEntries.map(e => e[1]), backgroundColor: colors }] },
        options: chartOptions
    });

    // 4. Target Services (Port names)
    const portEntries = Object.entries(data.puertos_frecuentes || {}).sort((a,b) => b[1] - a[1]).slice(0, 8);
    if (state.ipPortsChart) state.ipPortsChart.destroy();
    state.ipPortsChart = new Chart(portCtx, {
        type: 'pie',
        data: { 
            labels: portEntries.map(e => getProtocolName(e[0])), 
            datasets: [{ data: portEntries.map(e => e[1]), backgroundColor: colors }] 
        },
        options: chartOptions
    });

    // 5. Source IPs
    const srcEntries = Object.values(data.reputacion_origenes || {})
        .sort((a,b) => (b.syn_count + b.ack_count) - (a.syn_count + a.ack_count))
        .slice(0, 8);
    if (state.ipSourcesChart) state.ipSourcesChart.destroy();
    state.ipSourcesChart = new Chart(srcCtx, {
        type: 'pie',
        data: { labels: srcEntries.map(e => e.ip), datasets: [{ data: srcEntries.map(e => (e.syn_count + e.ack_count) || 1), backgroundColor: colors }] },
        options: chartOptions
    });

    // 6. Source Ports
    const srcPortEntries = Object.entries(data.source_ports_frecuentes || {}).sort((a,b) => b[1] - a[1]).slice(0, 8);
    if (state.ipSrcPortsChart) state.ipSrcPortsChart.destroy();
    state.ipSrcPortsChart = new Chart(srcPortCtx, {
        type: 'pie',
        data: { labels: srcPortEntries.map(e => `Port ${e[0]}`), datasets: [{ data: srcPortEntries.map(e => e[1]), backgroundColor: colors }] },
        options: chartOptions
    });
}

// Mitigation View Logic
async function loadMitigationStatus() {
    try {
        const res = await fetch('/api/mitigation/status');
        const data = await res.json();
        document.getElementById('bgp-status').textContent = data.bgp_enabled ? 'Active (GoBGP)' : 'Simulation Mode';
        document.getElementById('blocklist-count').textContent = data.blocklist_entries.toLocaleString();
        const tbody = document.getElementById('bgp-announcements-body');
        tbody.innerHTML = (data.announcements || []).map(a => `
            <tr><td><code>${a.prefix}</code></td><td><span class="badge badge-red">${a.type}</span></td><td><small>${a.community || '-'}</small></td><td><small>${formatShortTime(a.time)}</small></td></tr>
        `).join('') || '<tr><td colspan="4" class="empty-state">No active BGP announcements.</td></tr>';
    } catch (err) {}
}

window.reloadBlocklists = async () => {
    try {
        const res = await fetch('/api/mitigation/reload', { method: 'POST' });
        if (res.ok) { alert('Blocklists reloaded.'); loadMitigationStatus(); }
    } catch (err) {}
};

// Actions
async function updateReputation(srcIP, dstIP, trust) {
    try {
        await fetch('/api/reputation/trust', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dst_ip: dstIP, src_ip: srcIP, trust })
        });
    } catch (err) {}
}

window.trustIPManual = async (srcIP) => {
    const dstIP = prompt(`Trust ${srcIP} for destination:`);
    if (dstIP) { await updateReputation(srcIP, dstIP, true); if (state.currentView === 'intelligence') loadGlobalReputations(); }
};

window.untrustIP = async (srcIP) => {
    const dstIP = prompt(`Revoke trust for ${srcIP} from protected IP:`);
    if (dstIP) { await updateReputation(srcIP, dstIP, false); loadWhitelist(); }
};

// SSE
function startEventStream() {
    const sse = new EventSource('/api/events');
    sse.onopen = () => { elements.streamState.textContent = 'Live Connected'; elements.streamState.parentElement.querySelector('.status-dot').className = 'status-dot online'; };
    sse.onmessage = (e) => {
        const pkt = JSON.parse(e.data);
        if (state.currentView === 'inspector') appendPacketToInspector(pkt);
        if (pkt.alert) {
            loadAlerts();
            refreshStats(); // Update alert count immediately
        }
    };
    sse.onerror = () => { elements.streamState.textContent = 'Reconnecting...'; elements.streamState.parentElement.querySelector('.status-dot').className = 'status-dot'; };
}

function appendPacketToInspector(p, force = false) {
    if (!elements.inspectorBody) return;
    if (state.inspectorPaused && !force) return;

    // Apply live filters
    const f = state.inspectorFilter;
    if (f.src && !p.src_ip?.toLowerCase().includes(f.src)) return;
    if (f.dst && !p.dst_ip?.toLowerCase().includes(f.dst)) return;
    if (f.port && !(String(p.src_port).includes(f.port) || String(p.dst_port).includes(f.port))) return;
    
    // Fuzzy matching for protocol
    if (f.proto) {
        const proto = (p.protocol || p.transport || '').toLowerCase();
        if (!proto.includes(f.proto)) return;
    }
    
    if (f.keyword && !p.summary?.toLowerCase().includes(f.keyword)) return;

    const tr = document.createElement('tr');
    if (p.alert) tr.className = 'row-alert';
    
    // Use most specific protocol for display
    const displayProto = p.protocol || p.transport || '-';
    
    tr.innerHTML = `<td><small>${formatShortTime(p.timestamp)}</small></td><td>${p.src_ip || '-'}</td><td>${p.dst_ip || '-'}</td><td><span class="badge badge-blue">${displayProto}</span></td><td>${p.ip_total_len || 0}</td><td>${p.ttl || 0}</td><td><small>${p.tcp_flags || '-'}</small></td><td><small>${p.summary || '-'}</small></td>`;
    
    if (force) {
        elements.inspectorBody.appendChild(tr);
    } else {
        elements.inspectorBody.prepend(tr);
    }

    if (elements.inspectorBody.children.length > 100) {
        if (force) elements.inspectorBody.firstElementChild.remove();
        else elements.inspectorBody.lastElementChild.remove();
    }
}

function getRandomColor() {
    const colors = ['#58a6ff', '#bc8cff', '#3fb950', '#f85149', '#d29922', '#1f6feb'];
    return colors[Math.floor(Math.random() * colors.length)];
}

// Función para actualizar los datos de la IP que se está inspeccionando sin recargar la vista entera
async function updateActiveIPDetail() {
    if (!state.activeIP) return;
    try {
        const res = await fetch(`/api/profile-detail?ip=${state.activeIP}`);
        if (!res.ok) return;
        const data = await res.json();
        
        // Actualizar solo los valores numéricos del stats-grid para no parpadear
        const labels = {
            'Max Peak PPS': Math.round(data.stats_historicas.max_pps).toLocaleString(),
            'Max Peak Mbps': data.stats_historicas.max_mbps.toFixed(2),
            'Lifetime Packets': data.stats_historicas.total_packets_processed.toLocaleString(),
            'Total Data': (data.stats_historicas.total_bytes_processed / 1024 / 1024).toFixed(2) + " MB"
        };

        // Buscar y actualizar los strong tags en el stats-grid
        const statCards = document.querySelectorAll('#view-ip-detail .stats-grid .stat-card');
        statCards.forEach(card => {
            const label = card.querySelector('.label')?.textContent;
            const strong = card.querySelector('strong');
            if (label && labels[label] && strong) {
                strong.textContent = labels[label];
            }
        });

        // Actualizar tabla de reputación si el contenedor existe
        const repBody = reputationContainer.querySelector('tbody');
        if (repBody) {
            repBody.innerHTML = Object.values(data.reputacion_origenes || {}).sort((a,b) => b.trust_score - a.trust_score).slice(0, 50).map(r => {
                const logId = `log-detail-${r.ip.replace(/\./g, '-')}`;
                return `
                <tr onclick="toggleLog('${logId}')" style="cursor: pointer;">
                    <td><code>${r.ip}</code></td>
                    <td><span class="badge ${r.trust_score > 70 ? 'badge-green' : 'badge-red'}">${r.trust_score}%</span></td>
                    <td>${r.handshake_completed ? '<span class="badge badge-blue">DONE</span>' : '<span class="badge" style="background:var(--border-color)">PENDING</span>'}</td>
                    <td>${r.is_manual_trust ? '✅' : '❌'}</td>
                    <td><small>${formatFullDateTime(r.last_seen)}</small></td>
                </tr>
                <tr id="${logId}" style="display: none; background: rgba(0,0,0,0.2);">
                    <td colspan="5" style="padding: 10px 24px;">
                        <div style="font-size: 12px; color: var(--text-secondary);">
                            <strong>Score History:</strong>
                            ${renderScoreLog(r.history)}
                        </div>
                    </td>
                </tr>
            `;}).join('') || '<tr><td colspan="5" class="empty-state">No sources tracked yet.</td></tr>';
        }

        // Actualizar gráficos
        renderIPCharts(data);

        // Actualizar Gráfica de Línea PPS
        const now = new Date().toLocaleTimeString();
        // Encontrar el perfil actual en state.profiles para obtener el PPS exacto en tiempo real
        const currentProfile = state.profiles.find(p => p.ip === state.activeIP);
        const currentPps = currentProfile ? Math.round(currentProfile.current_pps) : 0;

        state.activeIPHistory.labels.push(now);
        state.activeIPHistory.pps.push(currentPps);

        if (state.activeIPHistory.labels.length > 20) {
            state.activeIPHistory.labels.shift();
            state.activeIPHistory.pps.shift();
        }

        if (state.ipPpsLineChart) {
            state.ipPpsLineChart.update('none'); // Update without animation for smoother look
        }
    } catch (err) {
        console.error("Auto-refresh error for IP detail:", err);
    }
}

function refreshAll() {
    refreshStats();
    refreshCurrentView();
}

init();

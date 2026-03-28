package analyzer

import (
	"dolly-sensor/config"
	"dolly-sensor/mitigation"
	"dolly-sensor/packet"
	"dolly-sensor/stateful"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	CooldownDiscord  = 10 * time.Minute
	MaxProtocolosTop = 5
)

type PerfilGlobalIP struct {
	IP               string    `json:"ip"`
	CurrentMbps      float64   `json:"current_mbps"`
	PromedioMbps     float64   `json:"promedio_mbps"`
	DesvioMbps       float64   `json:"desvio_mbps"`
	CurrentPPS       float64   `json:"current_pps"`
	PromedioPPS      float64   `json:"promedio_pps"`
	DesvioPPS        float64   `json:"desvio_pps"`
	PuntajeAmenaza   int       `json:"puntaje_amenaza"`
	Muestras         int       `json:"muestras"`
	UltimaMuestra    time.Time `json:"ultima_muestra"`
	ProtocolosTop    []string  `json:"protocolos_top"`
}

type thresholds struct {
	SueloPPS       float64
	ZScoreExtremo  float64
	Persistencia   int
	UmbralThreat   float64
}

type ResultadoEvaluacionInbound struct {
	CoincideDestinoPropio bool
	Alerta                bool
	NombreAlerta          string
	RazonAlerta           string
	PPSActual             float64
	PPSBase               float64
	PPSThreshold          float64
	SourcePPS             float64
}

type InboundProfileProvider interface {
	GetProfile(ip string) *packet.PersistentProfile
}

type GlobalSummary struct {
	TotalCurrentPPS  float64 `json:"total_current_pps"`
	TotalCurrentMbps float64 `json:"total_current_mbps"`
	TotalSamples     int     `json:"total_samples"`
	ActiveTargets    int     `json:"active_targets"`
}

type analyzerShard struct {
	mu            sync.Mutex
	realtimePPS    map[string]*PerfilZScore
	realtimeMbps   map[string]*PerfilZScore
	sourcePPS      map[string]*PerfilZScore
	sourceDestPPS  map[string]*PerfilZScore
	puntajes       map[string]float64
	contadores     map[string]int
}

type PerfilInboundGlobal struct {
	ownedNets      []*net.IPNet
	mu             sync.Mutex // Solo para alertCooldowns
	alertCooldowns map[string]time.Time
	
	shards         []*analyzerShard
	numShards      int

	blocklist      *mitigation.BlocklistEngine
	bgp            *mitigation.BGPManager
	cfg            config.Config
	profiler       InboundProfileProvider
	HasConn        func(srcIP string, srcPort uint16, dstIP string, dstPort uint16) bool
	ValidateTCP    func(pkt *packet.Event) stateful.SecurityCheck
	ValidateTCPFlood func(pkt *packet.Event, syn, ack int) stateful.SecurityCheck
}

func NuevoPerfilInboundGlobal(ownedNets []*net.IPNet, bl *mitigation.BlocklistEngine, bgp *mitigation.BGPManager, cfg config.Config, prof InboundProfileProvider) *PerfilInboundGlobal {
	numShards := cfg.Performance.Shards
	p := &PerfilInboundGlobal{
		ownedNets:      ownedNets,
		alertCooldowns: make(map[string]time.Time),
		blocklist:      bl,
		bgp:            bgp,
		cfg:            cfg,
		profiler:       prof,
		numShards:      numShards,
		shards:         make([]*analyzerShard, numShards),
	}
	for i := 0; i < numShards; i++ {
		p.shards[i] = &analyzerShard{
			realtimePPS:   make(map[string]*PerfilZScore),
			realtimeMbps:  make(map[string]*PerfilZScore),
			sourcePPS:     make(map[string]*PerfilZScore),
			sourceDestPPS: make(map[string]*PerfilZScore),
			puntajes:      make(map[string]float64),
			contadores:    make(map[string]int),
		}
	}
	return p
}

func (p *PerfilInboundGlobal) getShard(ip string) *analyzerShard {
	h := uint32(2166136261)
	for i := 0; i < len(ip); i++ {
		h *= 16777619
		h ^= uint32(ip[i])
	}
	return p.shards[h%uint32(p.numShards)]
}

func (p *PerfilInboundGlobal) Evaluar(pkt *packet.Event, cfg config.Config) ResultadoEvaluacionInbound {
	srcIP := pkt.SrcIP
	dstIP := pkt.DstIP
	protocolo := pkt.BestProtocol()
	bytes := pkt.FrameLength
	
	sr := pkt.SamplingRate
	if sr == 0 { sr = 1 }

	if !p.esDestinoPropio(dstIP) {
		return ResultadoEvaluacionInbound{}
	}

	// 1. Baseline & Z-Score Analysis (SHARDED por IP de destino)
	shard := p.getShard(dstIP)
	
	thr := getDetectionThresholds(cfg.Detection.NetworkType, cfg.Detection.Sensitivity)
	ahora := pkt.Timestamp
	if ahora.IsZero() { ahora = time.Now() }

	shard.mu.Lock()
	pps, ok := shard.realtimePPS[dstIP]
	if !ok { pps = NuevoPerfilZScore(); shard.realtimePPS[dstIP] = pps }
	mbps, ok := shard.realtimeMbps[dstIP]
	if !ok { mbps = NuevoPerfilZScore(); shard.realtimeMbps[dstIP] = mbps }
	
	var sdPPS *PerfilZScore
	if srcIP != "" {
		keySD := srcIP + "-" + dstIP
		sdPPS, ok = shard.sourceDestPPS[keySD]
		if !ok { sdPPS = NuevoPerfilZScore(); shard.sourceDestPPS[keySD] = sdPPS }
	}
	
	resPPS := pps.ObservarConPeso(ahora, float64(sr))
	realBytes := float64(bytes) * float64(sr)
	resMbps := mbps.ObservarConPeso(ahora, (realBytes*8)/1_000_000)

	var resSourceDestPPS ResultadoZScore
	if sdPPS != nil {
		resSourceDestPPS = sdPPS.ObservarConPeso(ahora, float64(sr))
	}

	pkt.CurrentPPS = resPPS.Actual
	pkt.SourcePPS = resSourceDestPPS.Actual
	shard.mu.Unlock()

	// 2. Ejecutar el Pipeline de Filtros
	if alert, name, reason := p.ExecutePipeline(pkt, cfg); alert {
		return ResultadoEvaluacionInbound{
			CoincideDestinoPropio: true,
			Alerta:                true,
			NombreAlerta:          name,
			RazonAlerta:           reason,
			PPSActual:             resPPS.Actual,
			SourcePPS:             resSourceDestPPS.Actual,
		}
	}

	puntos := 0.0
	if resPPS.Actual > thr.SueloPPS { puntos += (resPPS.Actual - thr.SueloPPS) / 400.0 }
	if resPPS.Desvio > 5.0 {
		z := (resPPS.Actual - resPPS.Media) / resPPS.Desvio
		if z > thr.ZScoreExtremo { puntos += 40.0 }
	}
	tamanioPromedio := realBytes / float64(sr)
	proto := strings.ToUpper(protocolo)
	if resPPS.Actual > thr.SueloPPS && (proto == "SYN" || proto == "UDP") && tamanioPromedio < 128 { puntos += 30.0 }

	shard.mu.Lock()
	shard.puntajes[dstIP] = (0.2 * puntos) + (0.8 * shard.puntajes[dstIP])
	if shard.puntajes[dstIP] >= thr.UmbralThreat { shard.contadores[dstIP]++ } else { if shard.contadores[dstIP] > 0 { shard.contadores[dstIP]-- } }

	resultado := ResultadoEvaluacionInbound{
		CoincideDestinoPropio: true,
		PPSActual:             resPPS.Actual,
		PPSBase:               resPPS.Media,
		PPSThreshold:          resPPS.Media + (thr.ZScoreExtremo * resPPS.Desvio),
		SourcePPS:             resSourceDestPPS.Actual,
	}

	if shard.contadores[dstIP] >= thr.Persistencia {
		p.mu.Lock()
		lastAlert, onCooldown := p.alertCooldowns[dstIP]
		if !onCooldown || ahora.Sub(lastAlert) > CooldownDiscord {
			p.alertCooldowns[dstIP] = ahora
			p.mu.Unlock()
			resultado.Alerta = true
			resultado.NombreAlerta = "🔥 DDOS-ATTACK-CONFIRMED"
			resultado.RazonAlerta = fmt.Sprintf("ATAQUE DETECTADO (%s/%s): PPS=%.0f Mbps=%.1f Proto=%s", cfg.Detection.NetworkType, cfg.Detection.Sensitivity, resPPS.Actual, resMbps.Actual, proto)
			shard.contadores[dstIP] = 0
		} else { p.mu.Unlock() }
	}
	shard.mu.Unlock()

	return resultado
}

func getDetectionThresholds(netType, sensitivity string) thresholds {
	t := thresholds{ SueloPPS: 8000.0, ZScoreExtremo: 12.0, Persistencia: 15, UmbralThreat: 100.0 }
	switch strings.ToLower(netType) {
	case "home": t.SueloPPS = 5000.0
	case "office": t.SueloPPS = 25000.0
	case "datacenter": t.SueloPPS = 100000.0
	}
	switch strings.ToLower(sensitivity) {
	case "relaxed": t.ZScoreExtremo = 25.0; t.Persistencia = 15; t.UmbralThreat = 150.0
	case "balanced": t.ZScoreExtremo = 12.0; t.Persistencia = 8; t.UmbralThreat = 100.0
	case "aggressive": t.ZScoreExtremo = 6.0; t.Persistencia = 5; t.UmbralThreat = 60.0
	case "ultra": t.ZScoreExtremo = 4.0; t.Persistencia = 3; t.UmbralThreat = 40.0
	case "instant": t.ZScoreExtremo = 2.5; t.Persistencia = 1; t.UmbralThreat = 20.0
	}
	return t
}

func (p *PerfilInboundGlobal) GetGlobalSummary() GlobalSummary {
	var summary GlobalSummary
	for i := 0; i < p.numShards; i++ {
		shard := p.shards[i]
		shard.mu.Lock()
		summary.ActiveTargets += len(shard.realtimePPS)
		for ip, pps := range shard.realtimePPS {
			resPPS := pps.Resumen()
			resMbps := shard.realtimeMbps[ip].Resumen()
			summary.TotalCurrentPPS += resPPS.Actual
			summary.TotalCurrentMbps += resMbps.Actual
			summary.TotalSamples += resPPS.Muestras
		}
		shard.mu.Unlock()
	}
	return summary
}

func (p *PerfilInboundGlobal) SnapshotPerfiles() []PerfilGlobalIP {
	var allIPs []string
	for i := 0; i < p.numShards; i++ {
		shard := p.shards[i]
		shard.mu.Lock()
		for ip := range shard.realtimePPS {
			allIPs = append(allIPs, ip)
		}
		shard.mu.Unlock()
	}
	sort.Strings(allIPs)

	resultados := make([]PerfilGlobalIP, 0, len(allIPs))
	for _, ip := range allIPs {
		shard := p.getShard(ip)
		shard.mu.Lock()
		resPPS := shard.realtimePPS[ip].Resumen()
		resMbps := shard.realtimeMbps[ip].Resumen()
		puntaje := int(shard.puntajes[ip])
		shard.mu.Unlock()

		var topProtos []string
		if p.profiler != nil {
			if pers := p.profiler.GetProfile(ip); pers != nil {
				pers.RLock()
				topProtos = p.getTopProtosInternal(pers.PuertosFrecuentes)
				pers.RUnlock()
			}
		}
		resultados = append(resultados, PerfilGlobalIP{
			IP: ip, CurrentMbps: resMbps.Actual, PromedioMbps: resMbps.Media, DesvioMbps: resMbps.Desvio,
			CurrentPPS: resPPS.Actual, PromedioPPS: resPPS.Media, DesvioPPS: resPPS.Desvio,
			PuntajeAmenaza: puntaje, Muestras: resPPS.Muestras, UltimaMuestra: time.Now(), ProtocolosTop: topProtos,
		})
	}
	return resultados
}

func (p *PerfilInboundGlobal) getTopProtosInternal(puertos map[uint16]uint64) []string {
	if len(puertos) == 0 { return nil }
	type item struct { p uint16; c uint64 }
	items := make([]item, 0, len(puertos))
	for port, count := range puertos { items = append(items, item{p: port, c: count}) }
	sort.Slice(items, func(i, j int) bool { return items[i].c > items[j].c })
	if len(items) > MaxProtocolosTop { items = items[:MaxProtocolosTop] }
	res := make([]string, 0, len(items))
	for _, it := range items { res = append(res, fmt.Sprintf("%d", it.p)) }
	return res
}

func (p *PerfilInboundGlobal) esDestinoPropio(dstIP string) bool {
	ip := net.ParseIP(dstIP)
	if ip == nil { return false }
	for _, network := range p.ownedNets {
		if network.Contains(ip) { return true }
	}
	return false
}

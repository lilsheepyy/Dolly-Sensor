package sflow

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	minMuestrasGlobal   = 20
	umbralZGlobal       = 3.0
	minPPSGlobal        = 25.0
	minMbpsGlobal       = 1.0
	maxProtocolosTop    = 5
	nombreAlertaInbound = "inbound-ddos-suspected"
)

type PerfilGlobalIP struct {
	IP               string    `json:"ip"`
	PromedioMbps     float64   `json:"promedio_mbps"`
	DesvioMbps       float64   `json:"desvio_mbps"`
	PromedioPPS      float64   `json:"promedio_pps"`
	DesvioPPS        float64   `json:"desvio_pps"`
	MuestrasMbps     int       `json:"muestras_mbps"`
	MuestrasPPS      int       `json:"muestras_pps"`
	UltimaMuestra    time.Time `json:"ultima_muestra"`
	ProtocolosTop    []string  `json:"protocolos_top"`
	UltimaAlertaPPS  bool      `json:"ultima_alerta_pps"`
	UltimaAlertaMbps bool      `json:"ultima_alerta_mbps"`
}

type ResultadoEvaluacionInbound struct {
	CoincideDestinoPropio bool
	Alerta                bool
	NombreAlerta          string
	RazonAlerta           string
	PPSActual             float64
	PPSBase               float64
	PPSThreshold          float64
}

type PerfilInboundGlobal struct {
	ownedNets []*net.IPNet
	mu        sync.Mutex
	perfiles  map[string]*perfilDestino
}

type perfilDestino struct {
	mu         sync.Mutex
	pps        *PerfilZScore
	mbps       *PerfilZScore
	protocolos map[string]int
}

func NuevoPerfilInboundGlobal(ownedNets []*net.IPNet) *PerfilInboundGlobal {
	return &PerfilInboundGlobal{ownedNets: ownedNets, perfiles: make(map[string]*perfilDestino)}
}

func (p *PerfilInboundGlobal) Evaluar(dstIP, protocolo string, bytes uint32) ResultadoEvaluacionInbound {
	if !p.esDestinoPropio(dstIP) {
		return ResultadoEvaluacionInbound{}
	}

	perfil := p.perfilPorIP(dstIP)
	ahora := time.Now()
	resPPS := perfil.pps.Observar(ahora)
	mbits := (float64(bytes) * 8) / 1_000_000
	resMbps := perfil.mbps.ObservarConPeso(ahora, mbits)
	perfil.registrarProtocolo(protocolo)

	resultado := ResultadoEvaluacionInbound{
		CoincideDestinoPropio: true,
		Alerta:                resPPS.Alerta || resMbps.Alerta,
		PPSActual:             resPPS.PPSActual,
		PPSBase:               resPPS.MediaPPS,
		PPSThreshold:          resPPS.UmbralPPS,
	}
	if resultado.Alerta {
		resultado.NombreAlerta = nombreAlertaInbound
		resultado.RazonAlerta = fmt.Sprintf(
			"inbound anomaly on %s pps=%.1f/%.1f mbps=%.2f/%.2f protocolos=%s",
			dstIP, resPPS.PPSActual, resPPS.UmbralPPS, resMbps.PPSActual, resMbps.UmbralPPS,
			strings.Join(perfil.topProtocolos(maxProtocolosTop), ","),
		)
	}

	return resultado
}

func (p *PerfilInboundGlobal) SnapshotPerfiles() []PerfilGlobalIP {
	p.mu.Lock()
	ips := make([]string, 0, len(p.perfiles))
	for ip := range p.perfiles {
		ips = append(ips, ip)
	}
	p.mu.Unlock()

	sort.Strings(ips)
	resultados := make([]PerfilGlobalIP, 0, len(ips))
	for _, ip := range ips {
		perfil := p.perfilPorIP(ip)
		resPPS := perfil.pps.Resumen()
		resMbps := perfil.mbps.Resumen()
		ultima := resPPS.UltimaMuestra
		if resMbps.UltimaMuestra.After(ultima) {
			ultima = resMbps.UltimaMuestra
		}

		resultados = append(resultados, PerfilGlobalIP{
			IP:               ip,
			PromedioMbps:     resMbps.MediaPPS,
			DesvioMbps:       resMbps.DesvioPPS,
			PromedioPPS:      resPPS.MediaPPS,
			DesvioPPS:        resPPS.DesvioPPS,
			MuestrasMbps:     resMbps.Muestras,
			MuestrasPPS:      resPPS.Muestras,
			UltimaMuestra:    ultima,
			ProtocolosTop:    perfil.topProtocolos(maxProtocolosTop),
			UltimaAlertaPPS:  resPPS.Alerta,
			UltimaAlertaMbps: resMbps.Alerta,
		})
	}

	sort.Slice(resultados, func(i, j int) bool {
		if resultados[i].UltimaMuestra.Equal(resultados[j].UltimaMuestra) {
			return resultados[i].IP < resultados[j].IP
		}
		return resultados[i].UltimaMuestra.After(resultados[j].UltimaMuestra)
	})
	return resultados
}

func (p *PerfilInboundGlobal) esDestinoPropio(dstIP string) bool {
	ip := net.ParseIP(dstIP)
	if ip == nil {
		return false
	}
	for _, network := range p.ownedNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *PerfilInboundGlobal) perfilPorIP(dstIP string) *perfilDestino {
	p.mu.Lock()
	defer p.mu.Unlock()
	if perfil, ok := p.perfiles[dstIP]; ok {
		return perfil
	}

	perfil := &perfilDestino{
		pps:        NuevoPerfilZScore(minMuestrasGlobal, umbralZGlobal, minPPSGlobal),
		mbps:       NuevoPerfilZScore(minMuestrasGlobal, umbralZGlobal, minMbpsGlobal),
		protocolos: make(map[string]int),
	}
	p.perfiles[dstIP] = perfil
	return perfil
}

func (p *perfilDestino) registrarProtocolo(protocolo string) {
	clave := strings.TrimSpace(strings.ToUpper(protocolo))
	if clave == "" {
		clave = "UNKNOWN"
	}
	p.mu.Lock()
	p.protocolos[clave]++
	p.mu.Unlock()
}

func (p *perfilDestino) topProtocolos(limite int) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	type item struct {
		nombre string
		conteo int
	}
	items := make([]item, 0, len(p.protocolos))
	for nombre, conteo := range p.protocolos {
		items = append(items, item{nombre: nombre, conteo: conteo})
	}
	if len(items) == 0 {
		return nil
	}
	sort.Slice(items, func(i, j int) bool { return items[i].conteo > items[j].conteo })
	if len(items) > limite {
		items = items[:limite]
	}
	resultado := make([]string, 0, len(items))
	for _, it := range items {
		resultado = append(resultado, it.nombre)
	}
	return resultado
}

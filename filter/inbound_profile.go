package filter

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const inboundMinSamples = 20
const inboundZThreshold = 3.0
const inboundMinPPS = 25.0
const inboundMinMbps = 1.0

type ResultadoPerfilInbound struct {
	PPS        ResultadoZScore
	Mbps       ResultadoZScore
	AlertaPPS  bool
	AlertaMbps bool
	Protocolos []string
}

type PerfilInbound struct {
	mu         sync.Mutex
	perfilPPS  *PerfilZScore
	perfilMbps *PerfilZScore
	protocolos map[string]int
}

func NuevoPerfilInbound() *PerfilInbound {
	return &PerfilInbound{
		perfilPPS:  NuevoPerfilZScore(inboundMinSamples, inboundZThreshold, inboundMinPPS),
		perfilMbps: NuevoPerfilZScore(inboundMinSamples, inboundZThreshold, inboundMinMbps),
		protocolos: make(map[string]int),
	}
}

func (p *PerfilInbound) Observar(ahora time.Time, bytes uint32, protocolo string) ResultadoPerfilInbound {
	resPPS := p.perfilPPS.Observar(ahora)
	mbits := (float64(bytes) * 8) / 1_000_000
	resMbps := p.perfilMbps.ObservarConPeso(ahora, mbits)

	p.mu.Lock()
	if protocolo == "" {
		protocolo = "unknown"
	}
	p.protocolos[strings.ToUpper(protocolo)]++
	protocolos := p.topProtocolos(5)
	p.mu.Unlock()

	return ResultadoPerfilInbound{
		PPS:        resPPS,
		Mbps:       resMbps,
		AlertaPPS:  resPPS.Alerta,
		AlertaMbps: resMbps.Alerta,
		Protocolos: protocolos,
	}
}

func (p *PerfilInbound) Resumen() ResultadoPerfilInbound {
	return ResultadoPerfilInbound{
		PPS:        p.perfilPPS.Resumen(),
		Mbps:       p.perfilMbps.Resumen(),
		Protocolos: p.topProtocolosBloqueante(5),
	}
}

func (p *PerfilInbound) ExportarProtocolos() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	copia := make(map[string]int, len(p.protocolos))
	for k, v := range p.protocolos {
		copia[k] = v
	}
	return copia
}

func (p *PerfilInbound) ImportarProtocolos(protocolos map[string]int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.protocolos = make(map[string]int, len(protocolos))
	for k, v := range protocolos {
		p.protocolos[k] = v
	}
}

func (p *PerfilInbound) topProtocolosBloqueante(limite int) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.topProtocolos(limite)
}

func (p *PerfilInbound) topProtocolos(limite int) []string {
	type item struct {
		nombre string
		conteo int
	}
	items := make([]item, 0, len(p.protocolos))
	for nombre, conteo := range p.protocolos {
		items = append(items, item{nombre: nombre, conteo: conteo})
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

package perfilglobal

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type ResumenIP struct {
	IP            string    `json:"ip"`
	PromedioMbps  float64   `json:"promedio_mbps"`
	DesvioMbps    float64   `json:"desvio_mbps"`
	PromedioPPS   float64   `json:"promedio_pps"`
	DesvioPPS     float64   `json:"desvio_pps"`
	MuestrasMbps  int       `json:"muestras_mbps"`
	MuestrasPPS   int       `json:"muestras_pps"`
	ProtocolosTop []string  `json:"protocolos_top"`
	UltimaMuestra time.Time `json:"ultima_muestra"`
	AlertaActiva  bool      `json:"alerta_activa"`
	RazonAlerta   string    `json:"razon_alerta"`
}

type PerfilIP struct {
	mu             sync.Mutex
	perfilPPS      *PerfilZ
	perfilMbps     *PerfilZ
	protocolos     map[string]int
	ultimaAlerta   bool
	razonUltAlerta string
}

func NuevoPerfilIP() *PerfilIP {
	return &PerfilIP{
		perfilPPS:  NuevoPerfilZ(),
		perfilMbps: NuevoPerfilZ(),
		protocolos: make(map[string]int),
	}
}

func (p *PerfilIP) Observar(ahora time.Time, bytes uint32, protocolo string) (ResultadoZ, ResultadoZ) {
	resPPS := p.perfilPPS.Observar(ahora, 1)
	mbits := (float64(bytes) * 8) / 1_000_000
	resMbps := p.perfilMbps.Observar(ahora, mbits)

	p.mu.Lock()
	if protocolo == "" {
		protocolo = "unknown"
	}
	p.protocolos[strings.ToUpper(protocolo)]++
	p.mu.Unlock()

	return resPPS, resMbps
}

func (p *PerfilIP) MarcarAlerta(activa bool, razon string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ultimaAlerta = activa
	p.razonUltAlerta = razon
}

func (p *PerfilIP) Resumen(ip string) ResumenIP {
	resPPS := p.perfilPPS.Resumen()
	resMbps := p.perfilMbps.Resumen()
	ultima := resPPS.UltimaMuestra
	if resMbps.UltimaMuestra.After(ultima) {
		ultima = resMbps.UltimaMuestra
	}

	p.mu.Lock()
	protocolos := p.topProtocolos(5)
	activa := p.ultimaAlerta
	razon := p.razonUltAlerta
	p.mu.Unlock()

	return ResumenIP{
		IP:            ip,
		PromedioMbps:  resMbps.Promedio,
		DesvioMbps:    resMbps.Desvio,
		PromedioPPS:   resPPS.Promedio,
		DesvioPPS:     resPPS.Desvio,
		MuestrasMbps:  resMbps.Muestras,
		MuestrasPPS:   resPPS.Muestras,
		ProtocolosTop: protocolos,
		UltimaMuestra: ultima,
		AlertaActiva:  activa,
		RazonAlerta:   razon,
	}
}

func (p *PerfilIP) topProtocolos(limite int) []string {
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
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.nombre)
	}
	return out
}

package filter

import (
	"sort"
	"time"
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

func (f *InboundFilter) SnapshotPerfiles() []PerfilGlobalIP {
	f.profilesMu.Lock()
	destinos := make([]struct {
		ip     string
		perfil *PerfilInbound
	}, 0, len(f.profilesByIP))
	for ip, perfil := range f.profilesByIP {
		destinos = append(destinos, struct {
			ip     string
			perfil *PerfilInbound
		}{ip: ip, perfil: perfil.perfil})
	}
	f.profilesMu.Unlock()

	resultados := make([]PerfilGlobalIP, 0, len(destinos))
	for _, destino := range destinos {
		resumen := destino.perfil.Resumen()
		ultima := resumen.PPS.UltimaMuestra
		if resumen.Mbps.UltimaMuestra.After(ultima) {
			ultima = resumen.Mbps.UltimaMuestra
		}
		resultados = append(resultados, PerfilGlobalIP{
			IP:               destino.ip,
			PromedioMbps:     resumen.Mbps.MediaPPS,
			DesvioMbps:       resumen.Mbps.DesvioPPS,
			PromedioPPS:      resumen.PPS.MediaPPS,
			DesvioPPS:        resumen.PPS.DesvioPPS,
			MuestrasMbps:     resumen.Mbps.Muestras,
			MuestrasPPS:      resumen.PPS.Muestras,
			UltimaMuestra:    ultima,
			ProtocolosTop:    resumen.Protocolos,
			UltimaAlertaPPS:  resumen.AlertaPPS,
			UltimaAlertaMbps: resumen.AlertaMbps,
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

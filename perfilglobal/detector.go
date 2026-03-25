package perfilglobal

import (
	"dolly-sensor/packet"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	minMuestrasAlerta = 20
	umbralZAlerta     = 3.0
	minPPSAlerta      = 25.0
	minMbpsAlerta     = 1.0
)

type Detector struct {
	mu           sync.Mutex
	redesPropias []*net.IPNet
	perfiles     map[string]*PerfilIP
}

func NuevoDetector(redes []*net.IPNet) *Detector {
	return &Detector{redesPropias: redes, perfiles: make(map[string]*PerfilIP)}
}

func (d *Detector) Analizar(pkt *packet.Event) bool {
	if !d.esDestinoPropio(pkt.DstIP) {
		return false
	}

	perfil := d.perfilParaIP(pkt.DstIP)
	ahora := time.Now()
	resPPS, resMbps := perfil.Observar(ahora, pkt.FrameLength, pkt.BestProtocol())

	alertaPPS := d.evaluarAlerta(resPPS, minPPSAlerta)
	alertaMbps := d.evaluarAlerta(resMbps, minMbpsAlerta)
	alerta := alertaPPS || alertaMbps

	razon := ""
	if alerta {
		razon = fmt.Sprintf("anomaly dst=%s pps=%.2f avg=%.2f dev=%.2f mbps=%.3f avg=%.3f dev=%.3f", pkt.DstIP, resPPS.Actual, resPPS.Promedio, resPPS.Desvio, resMbps.Actual, resMbps.Promedio, resMbps.Desvio)
	}
	perfil.MarcarAlerta(alerta, razon)

	pkt.ProfileActive = true
	pkt.ProfileKey = pkt.DstIP
	pkt.DestinationIsLocal = true
	pkt.CurrentPPS = resPPS.Actual
	pkt.BaselinePPS = resPPS.Promedio
	pkt.CurrentMbps = resMbps.Actual
	pkt.BaselineMbps = resMbps.Promedio
	pkt.DeviationPPS = resPPS.Desvio
	pkt.DeviationMbps = resMbps.Desvio
	pkt.Alert = alerta
	pkt.AlertName = "inbound-ddos-suspected"
	pkt.AlertReason = razon

	return true
}

func (d *Detector) Perfiles() []ResumenIP {
	d.mu.Lock()
	ips := make([]string, 0, len(d.perfiles))
	for ip := range d.perfiles {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	perfiles := make([]*PerfilIP, 0, len(ips))
	for _, ip := range ips {
		perfiles = append(perfiles, d.perfiles[ip])
	}
	d.mu.Unlock()

	out := make([]ResumenIP, 0, len(perfiles))
	for i, perfil := range perfiles {
		out = append(out, perfil.Resumen(ips[i]))
	}
	return out
}

func (d *Detector) perfilParaIP(ip string) *PerfilIP {
	d.mu.Lock()
	defer d.mu.Unlock()
	if perfil, ok := d.perfiles[ip]; ok {
		return perfil
	}
	perfil := NuevoPerfilIP()
	d.perfiles[ip] = perfil
	return perfil
}

func (d *Detector) esDestinoPropio(dst string) bool {
	ip := net.ParseIP(dst)
	if ip == nil {
		return false
	}
	for _, red := range d.redesPropias {
		if red.Contains(ip) {
			return true
		}
	}
	return false
}

func (d *Detector) evaluarAlerta(res ResultadoZ, minimo float64) bool {
	if res.Muestras < minMuestrasAlerta || res.Actual < minimo {
		return false
	}
	if res.Desvio == 0 {
		return res.Actual > res.Promedio && res.Promedio > 0
	}
	z := (res.Actual - res.Promedio) / res.Desvio
	return z >= umbralZAlerta
}

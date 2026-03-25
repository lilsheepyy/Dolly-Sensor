package filter

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const InboundGlobalName = "inbound-global-profile"
const inboundProfileTTL = 30 * 24 * time.Hour
const inboundCleanupInterval = 5 * time.Minute
const inboundProfilesFilename = "data/inbound_profiles.json"

type InboundFilter struct {
	ownedNets    []*net.IPNet
	profilesMu   sync.Mutex
	profilesByIP map[string]*perfilDestinoInbound
	almacen      *almacenPerfilesInbound
	baseDir      string
}

func NewInboundGlobalFilter(ownedNets []*net.IPNet) *InboundFilter {
	filter := &InboundFilter{
		ownedNets:    ownedNets,
		profilesByIP: make(map[string]*perfilDestinoInbound),
		baseDir:      ".",
	}
	filter.almacen = nuevoAlmacenPerfilesInbound(filepath.Join(filter.baseDir, inboundProfilesFilename))
	filter.cargarPerfilesPersistidos()
	go filter.cleanupLoop()
	return filter
}

func (f *InboundFilter) Evaluate(pkt Packet) Decision {
	decision := Decision{
		Name:    InboundGlobalName,
		Action:  "allowed",
		Allowed: true,
		Reason:  "inbound global profile not triggered",
	}

	if !f.esDestinoPropio(pkt.DstIP) {
		return decision
	}

	protocolo := pkt.Protocolo
	if protocolo == "" {
		protocolo = pkt.Transport
	}
	resultado := f.perfilParaDestino(pkt.DstIP).Observar(time.Now(), pkt.Bytes, protocolo)

	decision.ProfileActive = true
	decision.ProfileKey = pkt.DstIP
	decision.DestinationIsLocal = true
	decision.CurrentPPS = resultado.PPS.PPSActual
	decision.BaselinePPS = resultado.PPS.MediaPPS
	decision.SpikePPS = resultado.PPS.UmbralPPS
	decision.Reason = "inbound profile evaluated"

	if resultado.AlertaPPS || resultado.AlertaMbps {
		decision.Alert = true
		decision.AlertName = "inbound-ddos-suspected"
		decision.AlertReason = fmt.Sprintf(
			"inbound anomaly on %s pps=%.1f/%.1f mbps=%.2f/%.2f protocolos=%s",
			pkt.DstIP,
			resultado.PPS.PPSActual,
			resultado.PPS.UmbralPPS,
			resultado.Mbps.PPSActual,
			resultado.Mbps.UmbralPPS,
			strings.Join(resultado.Protocolos, ","),
		)
	}

	return decision
}

func (f *InboundFilter) esDestinoPropio(dstIP string) bool {
	ip := net.ParseIP(dstIP)
	if ip == nil {
		return false
	}
	for _, network := range f.ownedNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (f *InboundFilter) perfilParaDestino(dstIP string) *PerfilInbound {
	f.profilesMu.Lock()
	defer f.profilesMu.Unlock()

	now := time.Now()
	if perfil, ok := f.profilesByIP[dstIP]; ok {
		perfil.lastSeen = now
		return perfil.perfil
	}

	perfil := &perfilDestinoInbound{perfil: NuevoPerfilInbound(), lastSeen: now}
	f.profilesByIP[dstIP] = perfil
	return perfil.perfil
}

func (f *InboundFilter) cleanupLoop() {
	ticker := time.NewTicker(inboundCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-inboundProfileTTL)
		f.cleanupProfiles(cutoff)
		f.guardarPerfilesPersistidos()
	}
}

func (f *InboundFilter) cleanupProfiles(cutoff time.Time) {
	f.profilesMu.Lock()
	defer f.profilesMu.Unlock()

	for key, profile := range f.profilesByIP {
		if profile.lastSeen.Before(cutoff) {
			delete(f.profilesByIP, key)
		}
	}
}

func (f *InboundFilter) cargarPerfilesPersistidos() {
	archivo, err := f.almacen.cargar()
	if err != nil || archivo == nil {
		return
	}

	f.profilesMu.Lock()
	defer f.profilesMu.Unlock()

	for _, registro := range archivo.PerfilesPorIPDestino {
		perfil := NuevoPerfilInbound()
		perfil.perfilPPS.Importar(registro.PPS)
		perfil.perfilMbps.Importar(registro.Mbps)
		perfil.ImportarProtocolos(registro.Protocolos)
		f.profilesByIP[registro.IP] = &perfilDestinoInbound{
			perfil:   perfil,
			lastSeen: time.Unix(registro.UltimaVez, 0),
		}
	}
}

func (f *InboundFilter) guardarPerfilesPersistidos() {
	f.profilesMu.Lock()
	registros := make([]registroPerfilInbound, 0, len(f.profilesByIP))
	for ip, perfil := range f.profilesByIP {
		registros = append(registros, registroPerfilInbound{
			IP:         ip,
			UltimaVez:  perfil.lastSeen.Unix(),
			PPS:        perfil.perfil.perfilPPS.Exportar(),
			Mbps:       perfil.perfil.perfilMbps.Exportar(),
			Protocolos: perfil.perfil.ExportarProtocolos(),
		})
	}
	f.profilesMu.Unlock()

	_ = f.almacen.guardar(archivoPerfilesInbound{PerfilesPorIPDestino: registros})
}

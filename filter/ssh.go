package filter

import (
	"dolly-sensor/flowspec"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"time"
)

const SSHPort22InboundName = "ssh-port-22-inbound"
const sshProfileTTL = 30 * 24 * time.Hour
const sshCleanupInterval = 5 * time.Minute
const sshMinSamples = 20
const sshZThreshold = 3.0
const sshMinPPS = 25.0
const sshProfilesFilename = "data/ssh_profiles.json"

type SSHFilter struct {
	ownedNets    []*net.IPNet
	profilesMu   sync.Mutex
	profilesByIP map[string]*perfilDestinoSSH
	almacen      *almacenPerfilesSSH
	baseDir      string
}

func NewSSHPort22Inbound(_ flowspec.Blocker, ownedNets []*net.IPNet) *SSHFilter {
	filter := &SSHFilter{
		ownedNets:    ownedNets,
		profilesByIP: make(map[string]*perfilDestinoSSH),
		baseDir:      ".",
	}
	filter.almacen = nuevoAlmacenPerfilesSSH(filepath.Join(filter.baseDir, sshProfilesFilename))
	filter.cargarPerfilesPersistidos()
	go filter.cleanupLoop()
	return filter
}

func (f *SSHFilter) Evaluate(pkt Packet) Decision {
	decision := Decision{
		Name:    SSHPort22InboundName,
		Action:  "allowed",
		Allowed: true,
		Reason:  "destination port 22 policy not triggered",
	}

	if pkt.DstPort != 22 {
		return decision
	}

	decision.Reason = "SSH policy evaluated for destination port 22"
	if !f.isOwnedDestination(pkt.DstIP) {
		decision.Reason = "destination is not owned, profile skipped"
		return decision
	}

	resultadoIP := f.perfilParaDestino(pkt.DstIP).Observar(time.Now())
	decision.ProfileActive = true
	decision.ProfileKey = pkt.DstIP
	decision.DestinationIsLocal = true
	decision.CurrentPPS = resultadoIP.PPSActual
	decision.BaselinePPS = resultadoIP.MediaPPS
	decision.SpikePPS = resultadoIP.UmbralPPS

	if resultadoIP.Alerta {
		decision.Alert = true
		decision.AlertName = "ssh-zscore-anomaly"
		decision.AlertReason = fmt.Sprintf(
			"ssh anomaly detected on %s current=%.1fpps mean=%.1fpps std=%.1f z=%.2f threshold=%.1fpps",
			pkt.DstIP,
			resultadoIP.PPSActual,
			resultadoIP.MediaPPS,
			resultadoIP.DesvioPPS,
			resultadoIP.PuntajeZ,
			resultadoIP.UmbralPPS,
		)
	}

	return decision
}

func (f *SSHFilter) isOwnedDestination(dstIP string) bool {
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

func (f *SSHFilter) perfilParaDestino(dstIP string) *PerfilZScore {
	f.profilesMu.Lock()
	defer f.profilesMu.Unlock()

	now := time.Now()
	if perfil, ok := f.profilesByIP[dstIP]; ok {
		perfil.lastSeen = now
		return perfil.perfil
	}

	perfil := &perfilDestinoSSH{
		perfil:   NuevoPerfilZScore(sshMinSamples, sshZThreshold, sshMinPPS),
		lastSeen: now,
	}
	f.profilesByIP[dstIP] = perfil
	return perfil.perfil
}

func (f *SSHFilter) cleanupLoop() {
	ticker := time.NewTicker(sshCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-sshProfileTTL)
		f.cleanupProfiles(cutoff)
		f.guardarPerfilesPersistidos()
	}
}

func (f *SSHFilter) cleanupProfiles(cutoff time.Time) {
	f.profilesMu.Lock()
	defer f.profilesMu.Unlock()

	for key, profile := range f.profilesByIP {
		if profile.lastSeen.Before(cutoff) {
			delete(f.profilesByIP, key)
		}
	}
}

func (f *SSHFilter) cargarPerfilesPersistidos() {
	archivo, err := f.almacen.cargar()
	if err != nil || archivo == nil {
		return
	}

	f.profilesMu.Lock()
	defer f.profilesMu.Unlock()

	for _, registro := range archivo.PerfilesPorIPDestino {
		perfil := NuevoPerfilZScore(sshMinSamples, sshZThreshold, sshMinPPS)
		perfil.Importar(registro.SnapshotEstadistico)
		f.profilesByIP[registro.IP] = &perfilDestinoSSH{
			perfil:   perfil,
			lastSeen: time.Unix(registro.UltimaVez, 0),
		}
	}
}

func (f *SSHFilter) guardarPerfilesPersistidos() {
	f.profilesMu.Lock()
	registros := make([]registroPerfilSSH, 0, len(f.profilesByIP))
	for ip, perfil := range f.profilesByIP {
		resumen := perfil.perfil.Resumen()
		registros = append(registros, registroPerfilSSH{
			IP:                  ip,
			UltimaVez:           perfil.lastSeen.Unix(),
			Muestras:            resumen.Muestras,
			MediaPPS:            resumen.MediaPPS,
			DesvioEstandarPPS:   resumen.DesvioPPS,
			SnapshotEstadistico: perfil.perfil.Exportar(),
		})
	}
	f.profilesMu.Unlock()

	archivo := archivoPerfilesSSH{PerfilesPorIPDestino: registros}
	_ = f.almacen.guardar(archivo)
}

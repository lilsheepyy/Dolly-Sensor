package analyzer

import (
	"dolly-sensor/basefilters"
	"dolly-sensor/config"
	"dolly-sensor/packet"
	"fmt"
	"log"
	"time"
)

// ExecutePipeline orquesta la cadena de filtros en el orden solicitado
func (p *PerfilInboundGlobal) ExecutePipeline(pkt *packet.Event, cfg config.Config) (alert bool, name, reason string) {
	srcIP := pkt.SrcIP
	dstIP := pkt.DstIP

	// 0. Obtener Trust Score para uso en filtros
	if p.profiler != nil && srcIP != "" {
		if pers := p.profiler.GetProfile(dstIP); pers != nil {
			pers.RLock()
			if trust, ok := pers.ReputacionOrigenes[srcIP]; ok {
				pkt.SourceTrustScore = trust.TrustScore
			}
			pers.RUnlock()
		}
	}

	// 1. Blocklist Global (Bloqueo explícito rápido)
	if p.blocklist != nil && srcIP != "" {
		if p.blocklist.IsBlocked(srcIP) {
			return true, "🚫 BLOCKLIST-HIT", fmt.Sprintf("Source IP %s matches global blocklist", srcIP)
		}
	}

	// 2. TRUSTSCORE / REPUTACIÓN (Detección por comportamiento histórico, e.g. SYN Flood)
	// Se ejecuta ANTES que stateful para proteger el motor de estado de flooders conocidos
	if p.ValidateTCPFlood != nil && srcIP != "" && p.profiler != nil {
		if pers := p.profiler.GetProfile(dstIP); pers != nil {
			pers.RLock()
			trust, hasTrust := pers.ReputacionOrigenes[srcIP]
			var alertFound bool
			var m packet.Mitigation
			
			if hasTrust {
				res := p.ValidateTCPFlood(pkt, trust.SYNCount, trust.ACKCount)
				if res.Alert {
					alertFound = true
					m = packet.Mitigation{
						Alert:    true,
						Block:    true,
						Drop:     true,
						SourceIP: srcIP,
						Name:     res.Name,
						Reason:   res.Reason,
					}
				}
			}
			pers.RUnlock()

			if alertFound {
				p.ExecuteMitigation(m)
				return true, m.Name, m.Reason
			}
		}
	}

	// 3. STATEFUL TCP VALIDATION (Protocol correctness, e.g. Out-of-state)
	if p.ValidateTCP != nil {
		check := p.ValidateTCP(pkt)
		if check.Alert {
			// Evitar que el sensor se bloquee a sí mismo si detecta paquetes out-of-state saliendo de nuestra red
			if check.Name == "🛡️ INVALID-TCP-STATE" && p.esDestinoPropio(pkt.SrcIP) {
				return false, "", ""
			}

			m := packet.Mitigation{
				Alert:    true,
				Block:    true,
				SourceIP: srcIP,
				Name:     check.Name,
				Reason:   check.Reason,
			}
			p.ExecuteMitigation(m)
			return true, check.Name, check.Reason
		}
	}

	// 4. PROTOCOL BASE FILTERS (Aplicación: FTP, SSH, etc.)
	if m := basefilters.Evaluate(pkt, cfg); m.Alert {
		if m.Block {
			p.ExecuteMitigation(m)
		}
		return true, m.Name, m.Reason
	}

	return false, "", ""
}

// ExecuteMitigation es el encargado de disparar la acción técnica real (BGP Flowspec)
func (p *PerfilInboundGlobal) ExecuteMitigation(m packet.Mitigation) {
	if !m.Block || m.SourceIP == "" {
		return
	}

	triggerID := m.Name + "-" + m.SourceIP
	// Evitar duplicidad de mitigaciones en corto tiempo
	if !p.blocklist.MarkTriggered(triggerID) {
		return
	}

	log.Printf("[PIPELINE] Mitigating: %s for Source %s. Reason: %s", m.Name, m.SourceIP, m.Reason)

	if p.bgp != nil {
		go func() {
			// Ahora enviamos la receta completa 'm' para un bloqueo granular
			err := p.bgp.AnnounceFlowspec(m)
			if err != nil {
				log.Printf("[BGP] Error in flowspec announcement: %v", err)
			}
			
			// Si tiene duración, después de que pase, limpiamos el triggered para que pueda re-activarse si el ataque sigue
			if m.Duration > 0 {
				time.Sleep(time.Duration(m.Duration) * time.Second)
				p.blocklist.ClearTriggered(triggerID)
			}
		}()
	}
}

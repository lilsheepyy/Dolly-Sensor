package basefilters

import (
	"dolly-sensor/config"
	"dolly-sensor/packet"
	"fmt"
)

// FTPFilter maneja específicamente el canal de CONTROL (Puerto 21)
type FTPFilter struct{}

func init() {
	Register(&FTPFilter{})
}

func (f *FTPFilter) Name() string { return "FTP-CONTROL-BASE" }
func (f *FTPFilter) Protocol() string { return "*" }

func (f *FTPFilter) Process(pkt *packet.Event, cfg config.Config) packet.Mitigation {
	// Solo puerto 21
	if pkt.DstPort != 21 && pkt.SrcPort != 21 {
		return packet.Mitigation{}
	}

	// 0. Excepción por Trust Score
	if pkt.SourceTrustScore >= cfg.Trust.MinScoreForExemption {
		return packet.Mitigation{}
	}

	// 1. Mismatch de Protocolo
	if pkt.Transport != "TCP" {
		return packet.Mitigation{
			Alert:    true,
			Block:    true,
			Drop:     true,
			SourceIP: pkt.SrcIP,
			DestIP:   pkt.DstIP,
			Protocol: pkt.Transport,
			DestPort: 21,
			Duration: cfg.Protocols.FTP.BlockDuration,
			Name:     "🛡️ FTP-CTRL-NON-TCP",
			Reason:   fmt.Sprintf("Non-TCP traffic (%s) to FTP control port from %s", pkt.Transport, pkt.SrcIP),
		}
	}

	// 2. Puertos Privilegiados
	if pkt.SrcPort < 1024 {
		return packet.Mitigation{
			Alert:    true,
			Block:    true,
			Drop:     true,
			SourceIP: pkt.SrcIP,
			DestIP:   pkt.DstIP,
			Duration: cfg.Protocols.FTP.BlockDuration,
			Name:     "🛡️ FTP-CTRL-PRIVILEGED-PORT",
			Reason:   fmt.Sprintf("Source IP %s using privileged port %d for FTP Control", pkt.SrcIP, pkt.SrcPort),
		}
	}

	// 3. Ratelimit
	if pkt.SourcePPS > cfg.Protocols.FTP.MaxPPS {
		return packet.Mitigation{
			Alert:     true,
			Block:     true,
			SourceIP:  pkt.SrcIP,
			DestIP:    pkt.DstIP,
			Protocol:  "TCP",
			DestPort:  21,
			RateLimit: cfg.Protocols.FTP.RateLimitPPS,
			Duration:  cfg.Protocols.FTP.BlockDuration,
			Name:      "🛡️ FTP-CTRL-RATELIMIT",
			Reason:    fmt.Sprintf("FTP Control Flood: %.0f pps from %s", pkt.SourcePPS, pkt.SrcIP),
		}
	}

	// 4. Comandos Malformados (Solo en puerto 21)
	if pkt.PayloadHex != "" && pkt.InEstablishedSession {
		if len(pkt.PayloadHex) > 1024 { 
			return packet.Mitigation{
				Alert:         true,
				Block:         true,
				SourceIP:      pkt.SrcIP,
				DestPort:      21,
				PacketLenMin:  512,
				Name:          "🛡️ FTP-CTRL-MALFORMED",
				Reason:        "FTP command exceeds maximum length",
			}
		}
	}
	
	return packet.Mitigation{}
}

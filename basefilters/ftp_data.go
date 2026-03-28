package basefilters

import (
	"dolly-sensor/config"
	"dolly-sensor/packet"
	"fmt"
)

// FTPDataFilter maneja específicamente el canal de DATOS (Puerto 20)
type FTPDataFilter struct{}

func init() {
	Register(&FTPDataFilter{})
}

func (f *FTPDataFilter) Name() string { return "FTP-DATA-BASE" }
func (f *FTPDataFilter) Protocol() string { return "*" }

func (f *FTPDataFilter) Process(pkt *packet.Event, cfg config.Config) packet.Mitigation {
	// Solo puerto 20
	if pkt.DstPort != 20 && pkt.SrcPort != 20 {
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
			DestPort: 20,
			Duration: cfg.Protocols.FTPData.BlockDuration,
			Name:     "🛡️ FTP-DATA-NON-TCP",
			Reason:   fmt.Sprintf("Non-TCP traffic (%s) to FTP data port from %s", pkt.Transport, pkt.SrcIP),
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
			Duration: cfg.Protocols.FTPData.BlockDuration,
			Name:     "🛡️ FTP-DATA-PRIVILEGED-PORT",
			Reason:   fmt.Sprintf("Source IP %s using privileged port %d for FTP Data", pkt.SrcIP, pkt.SrcPort),
		}
	}

	// 3. Ratelimit (Usando umbrales de FTP-Data, que suelen ser más altos)
	if pkt.SourcePPS > cfg.Protocols.FTPData.MaxPPS {
		return packet.Mitigation{
			Alert:     true,
			Block:     true,
			SourceIP:  pkt.SrcIP,
			DestIP:    pkt.DstIP,
			Protocol:  "TCP",
			DestPort:  20,
			RateLimit: cfg.Protocols.FTPData.RateLimitPPS,
			Duration:  cfg.Protocols.FTPData.BlockDuration,
			Name:      "🛡️ FTP-DATA-RATELIMIT",
			Reason:    fmt.Sprintf("FTP Data Flood: %.0f pps from %s (Limit: %.0f)", pkt.SourcePPS, pkt.SrcIP, cfg.Protocols.FTPData.MaxPPS),
		}
	}

	return packet.Mitigation{}
}

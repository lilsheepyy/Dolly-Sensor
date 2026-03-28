package trustscore

import (
	"fmt"
	"strings"
	"time"
)

// UpdateTrustScore actualiza el registro de confianza de una IP basándose en su comportamiento
func UpdateTrustScore(trust *SourceTrust, ev TrustEvent, isManual bool) {
	if trust.SeenDays == nil { trust.SeenDays = make(map[string]bool) }
	if trust.Fingerprints == nil { trust.Fingerprints = make(map[string]int) }
	if trust.Protocols == nil { trust.Protocols = make(map[string]uint64) }
	if trust.TCPFlags == nil { trust.TCPFlags = make(map[string]uint64) }

	trust.LastSeen = time.Now()
	if trust.FirstSeen.IsZero() { 
		trust.FirstSeen = trust.LastSeen
		trust.AddScoreEvent(2, "Initial detection")
	}
	trust.IsManualTrust = isManual || trust.IsManualTrust
	
	day := trust.LastSeen.Format("2006-01-02")
	if !trust.SeenDays[day] {
		trust.SeenDays[day] = true
		trust.AddScoreEvent(2, fmt.Sprintf("Activity day %d", len(trust.SeenDays)))
	}

	trust.Protocols[ev.BestProtocol]++
	finger := fmt.Sprintf("%s/%d", ev.Protocol, ev.SrcPort)
	trust.Fingerprints[finger]++

	flags := strings.ToUpper(ev.TCPFlags)
	if flags != "" {
		trust.TCPFlags[flags]++
	}

	// Seguimiento de flags para análisis de flood
	if strings.Contains(flags, "SYN") && !strings.Contains(flags, "ACK") {
		trust.SYNCount++
	}

	// Premiar el comportamiento legítimo (Handshake completo)
	if ev.HandshakeComplete {
		trust.HandshakeCompleted = true
		if time.Since(trust.LastHandshakeAward) > 1*time.Hour {
			trust.AddScoreEvent(10, "Successful TCP Handshake")
			trust.LastHandshakeAward = time.Now()
		}
	}

	if ev.InEstablishedSession || trust.HandshakeCompleted {
		if strings.Contains(flags, "ACK") { 
			trust.ACKCount++ 
			if trust.ACKCount == 100 { trust.AddScoreEvent(5, "100+ ACK packets verified") }
		}
		if strings.Contains(flags, "PSH") { 
			trust.PSHCount++ 
			if trust.PSHCount == 100 { trust.AddScoreEvent(5, "100+ PSH packets verified") }
		}
	}

	trust.UpdateScore()
}

// ApplyDecay reduce la confianza de IPs inactivas
func ApplyDecay(trusts map[string]*SourceTrust) {
	now := time.Now()
	for ip, trust := range trusts {
		if trust.IsManualTrust { continue }

		daysInactive := now.Sub(trust.LastSeen).Hours() / 24
		if daysInactive >= 1.0 {
			trust.AddScoreEvent(-10, "Inactivity penalty")
			
			if trust.TrustScore == 0 && daysInactive > 30 {
				delete(trusts, ip)
			}
		}
	}
}

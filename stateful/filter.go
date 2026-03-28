package stateful

import (
	"dolly-sensor/packet"
	"fmt"
	"strings"
)

type SecurityCheck struct {
	Alert  bool
	Name   string
	Reason string
}

// Validate realiza chequeos de seguridad basados puramente en el estado TCP
func (t *TCPTracker) Validate(pkt *packet.Event) SecurityCheck {
	if pkt.Transport != "TCP" {
		return SecurityCheck{}
	}

	flags := strings.ToUpper(pkt.TCPFlags)
	
	// Detección de Out-of-State (ACK/PSH/RST sin conexión activa)
	if !strings.Contains(flags, "SYN") {
		t.muConns.RLock()
		key := fmt.Sprintf("%s:%d->%s:%d", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)
		_, exists := t.activeConns[key]
		t.muConns.RUnlock()

		if !exists {
			if pkt.CurrentPPS > 100 { 
				return SecurityCheck{
					Alert:  true,
					Name:   "🛡️ INVALID-TCP-STATE",
					Reason: fmt.Sprintf("TCP %s detected without active session from %s", flags, pkt.SrcIP),
				}
			}
		}
	}

	return SecurityCheck{}
}

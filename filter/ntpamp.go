package filter

import (
	"context"
	"dolly-sensor/flowspec"
	"fmt"
)

const NTPAmplificationName = "ntp-amplification-guard"

var trustedNTPServers = map[string]struct{}{
	"129.6.15.25":   {},
	"129.6.15.26":   {},
	"129.6.15.27":   {},
	"129.6.15.28":   {},
	"129.6.15.29":   {},
	"129.6.15.30":   {},
	"129.6.15.32":   {},
	"132.163.96.1":  {},
	"132.163.96.2":  {},
	"132.163.96.3":  {},
	"132.163.96.4":  {},
	"132.163.96.5":  {},
	"132.163.96.6":  {},
	"132.163.97.1":  {},
	"132.163.97.2":  {},
	"132.163.97.3":  {},
	"132.163.97.4":  {},
	"132.163.97.5":  {},
	"132.163.97.6":  {},
	"132.163.97.7":  {},
	"216.239.35.0":  {},
	"216.239.35.4":  {},
	"216.239.35.8":  {},
	"216.239.35.12": {},
}

type NTPAmplificationFilter struct {
	blocker flowspec.Blocker
}

func NewNTPAmplificationFilter(blocker flowspec.Blocker) *NTPAmplificationFilter {
	return &NTPAmplificationFilter{
		blocker: blocker,
	}
}

func (f *NTPAmplificationFilter) Evaluate(pkt Packet) Decision {
	decision := Decision{
		Name:    NTPAmplificationName,
		Action:  "allowed",
		Allowed: true,
		Reason:  "source port 123 traffic matched trusted NTP server list",
	}

	if pkt.SrcPort != 123 {
		decision.Reason = fmt.Sprintf("source port %d is outside NTP amplification policy", pkt.SrcPort)
		return decision
	}

	if _, ok := trustedNTPServers[pkt.SourceIP]; ok {
		return decision
	}

	decision.Action = "blocked"
	decision.Allowed = false
	decision.Reason = fmt.Sprintf("untrusted source port 123 sender %s", fallback(pkt.SourceIP, "unknown"))

	if pkt.SourceIP == "" {
		decision.Reason += " (missing source IP for FlowSpec block)"
		return decision
	}

	if f.blocker != nil {
		if err := f.blocker.Block(context.Background(), flowspec.Match{
			SourceIP:          pkt.SourceIP,
			SourcePort:        pkt.SrcPort,
			IncludeSourcePort: true,
		}); err != nil {
			decision.Reason += fmt.Sprintf(" (flowspec error: %v)", err)
		} else {
			decision.Reason += fmt.Sprintf(" (flowspec block requested for %s:%d)", pkt.SourceIP, pkt.SrcPort)
		}
	}

	return decision
}

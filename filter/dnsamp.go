package filter

import (
	"context"
	"dolly-sensor/flowspec"
	"fmt"
)

const DNSAmplificationName = "dns-amplification-guard"

var trustedDNSResolvers = map[string]struct{}{
	"1.1.1.1":         {},
	"1.0.0.1":         {},
	"8.8.8.8":         {},
	"8.8.4.4":         {},
	"9.9.9.9":         {},
	"149.112.112.112": {},
	"208.67.222.222":  {},
	"208.67.220.220":  {},
	"94.140.14.14":    {},
	"94.140.15.15":    {},
}

type DNSAmplificationFilter struct {
	blocker flowspec.Blocker
}

func NewDNSAmplificationFilter(blocker flowspec.Blocker) *DNSAmplificationFilter {
	return &DNSAmplificationFilter{
		blocker: blocker,
	}
}

func (f *DNSAmplificationFilter) Evaluate(pkt Packet) Decision {
	decision := Decision{
		Name:    DNSAmplificationName,
		Action:  "allowed",
		Allowed: true,
		Reason:  "source port 53 traffic matched trusted resolver list",
	}

	if pkt.SrcPort != 53 {
		decision.Reason = fmt.Sprintf("source port %d is outside DNS amplification policy", pkt.SrcPort)
		return decision
	}

	if _, ok := trustedDNSResolvers[pkt.SourceIP]; ok {
		return decision
	}

	decision.Action = "blocked"
	decision.Allowed = false
	decision.Reason = fmt.Sprintf("untrusted source port 53 sender %s", fallback(pkt.SourceIP, "unknown"))

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

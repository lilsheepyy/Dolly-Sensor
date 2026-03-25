package filter

import (
	"context"
	"dolly-sensor/flowspec"
	"fmt"
)

const FTPPort21InboundName = "ftp-port-21-inbound"

type FTPFilter struct {
	blocker flowspec.Blocker
}

func NewFTPPort21Inbound(blocker flowspec.Blocker) *FTPFilter {
	return &FTPFilter{blocker: blocker}
}

func (f *FTPFilter) Evaluate(pkt Packet) Decision {
	decision := Decision{
		Name:    FTPPort21InboundName,
		Action:  "allowed",
		Allowed: true,
		Reason:  "destination port 21 policy not triggered",
	}

	if pkt.DstPort != 21 {
		return decision
	}

	if pkt.Transport != "TCP" {
		return f.blockBySourceIP(pkt, fmt.Sprintf("requires TCP on destination port 21, got %s/%d", fallback(pkt.Transport, "unknown"), pkt.DstPort))
	}

	if pkt.SrcPort <= 1024 {
		return f.blockBySourceIP(pkt, fmt.Sprintf("source port %d is not allowed for destination port 21", pkt.SrcPort))
	}

	decision.Reason = "TCP destination port 21 policy not violated"
	return decision
}

func (f *FTPFilter) blockBySourceIP(pkt Packet, reason string) Decision {
	decision := Decision{
		Name:    FTPPort21InboundName,
		Action:  "blocked",
		Allowed: false,
		Reason:  reason,
	}

	if pkt.SourceIP == "" {
		decision.Reason += " (missing source IP for FlowSpec block)"
		return decision
	}

	if f.blocker != nil {
		if err := f.blocker.Block(context.Background(), flowspec.Match{SourceIP: pkt.SourceIP}); err != nil {
			decision.Reason += fmt.Sprintf(" (flowspec error: %v)", err)
		} else {
			decision.Reason += fmt.Sprintf(" (flowspec block requested for %s)", pkt.SourceIP)
		}
	}

	return decision
}

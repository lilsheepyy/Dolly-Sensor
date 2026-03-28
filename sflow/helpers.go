package sflow

import (
	"dolly-sensor/packet"
	"fmt"
	"strings"
)

func isHTTPPayload(payload []byte) bool {
	line := firstLine(payload)
	if line == "" {
		return false
	}

	methods := []string{
		"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ",
		"PATCH ", "CONNECT ", "TRACE ", "HTTP/1.", "HTTP/2",
	}
	for _, prefix := range methods {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func firstLine(payload []byte) string {
	line := string(payload)
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	line = strings.TrimRight(line, "\r")
	line = strings.TrimSpace(line)
	if len(line) > 120 {
		line = line[:120]
	}
	return line
}

func bytesHasPrefixFold(payload []byte, prefix string) bool {
	if len(payload) < len(prefix) {
		return false
	}
	return strings.EqualFold(string(payload[:len(prefix)]), prefix)
}

func icmpTypeName(typ, code byte) string {
	switch typ {
	case 0:
		return "echo_reply"
	case 3:
		return fmt.Sprintf("destination_unreachable/%d", code)
	case 5:
		return "redirect"
	case 8:
		return "echo_request"
	case 11:
		return fmt.Sprintf("time_exceeded/%d", code)
	default:
		return fmt.Sprintf("icmp_%d", typ)
	}
}

func icmpv6TypeName(typ, code byte) string {
	switch typ {
	case 128:
		return "echo_request"
	case 129:
		return "echo_reply"
	case 133:
		return "router_solicitation"
	case 134:
		return "router_advertisement"
	case 135:
		return "neighbor_solicitation"
	case 136:
		return "neighbor_advertisement"
	default:
		return fmt.Sprintf("icmpv6_%d/%d", typ, code)
	}
}

func applySummary(pkt *packet.Event) {
	pkt.Summary = pkt.SummaryString()
}

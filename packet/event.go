package packet

import (
	"fmt"
	"time"
)

type Event struct {
	ID                 int64     `json:"id"`
	Timestamp          time.Time `json:"timestamp"`
	AgentIP            string    `json:"agentIP"`
	RemoteAddr         string    `json:"remoteAddr"`
	DatagramSequence   uint32    `json:"datagramSequence"`
	SampleSequence     uint32    `json:"sampleSequence"`
	SampleType         string    `json:"sampleType"`
	SourceID           string    `json:"sourceID"`
	Input              string    `json:"input"`
	Output             string    `json:"output"`
	SamplingRate       uint32    `json:"samplingRate"`
	SamplePool         uint32    `json:"samplePool"`
	Drops              uint32    `json:"drops"`
	RecordIndex        uint32    `json:"recordIndex"`
	HeaderProtocol     uint32    `json:"headerProtocol"`
	FrameLength        uint32    `json:"frameLength"`
	Stripped           uint32    `json:"stripped"`
	HeaderLength       uint32    `json:"headerLength"`
	DstMAC             string    `json:"dstMAC,omitempty"`
	SrcMAC             string    `json:"srcMAC,omitempty"`
	EtherType          string    `json:"etherType,omitempty"`
	Network            string    `json:"network,omitempty"`
	Protocol           string    `json:"protocol,omitempty"`
	Details            string    `json:"details,omitempty"`
	SrcIP              string    `json:"srcIP,omitempty"`
	DstIP              string    `json:"dstIP,omitempty"`
	TTL                uint8     `json:"ttl,omitempty"`
	IPProtocol         string    `json:"ipProtocol,omitempty"`
	Transport          string    `json:"transport,omitempty"`
	SrcPort            uint16    `json:"srcPort,omitempty"`
	DstPort            uint16    `json:"dstPort,omitempty"`
	TCPFlags           string    `json:"tcpFlags,omitempty"`
	ARPSourceIP        string    `json:"arpSourceIP,omitempty"`
	ARPTargetIP        string    `json:"arpTargetIP,omitempty"`
	ICMPType           string    `json:"icmpType,omitempty"`
	DNSQuery           string    `json:"dnsQuery,omitempty"`
	HTTPStartLine      string    `json:"httpStartLine,omitempty"`
	SSHBanner          string    `json:"sshBanner,omitempty"`
	FilterName         string    `json:"filterName,omitempty"`
	FilterAction       string    `json:"filterAction,omitempty"`
	FilterReason       string    `json:"filterReason,omitempty"`
	Allowed            bool      `json:"allowed"`
	Alert              bool      `json:"alert"`
	AlertName          string    `json:"alertName,omitempty"`
	AlertReason        string    `json:"alertReason,omitempty"`
	CurrentPPS         float64   `json:"currentPPS,omitempty"`
	BaselinePPS        float64   `json:"baselinePPS,omitempty"`
	SpikePPS           float64   `json:"spikePPS,omitempty"`
	ProfileActive      bool      `json:"profileActive"`
	ProfileKey         string    `json:"profileKey,omitempty"`
	DestinationIsLocal bool      `json:"destinationIsLocal"`
	PayloadHex         string    `json:"payloadHex"`
	Summary            string    `json:"summary"`
}

func (e Event) BestProtocol() string {
	if e.Protocol != "" {
		return e.Protocol
	}
	if e.Transport != "" {
		return e.Transport
	}
	if e.IPProtocol != "" {
		return e.IPProtocol
	}
	if e.Network != "" {
		return e.Network
	}
	return "-"
}

func (e Event) SummaryString() string {
	base := fmt.Sprintf("%s sample=%d record=%d", e.SampleType, e.SampleSequence, e.RecordIndex)
	proto := e.BestProtocol()

	if e.SrcIP != "" || e.DstIP != "" {
		addr := fmt.Sprintf("%s:%d -> %s:%d", zeroIfEmpty(e.SrcIP), e.SrcPort, zeroIfEmpty(e.DstIP), e.DstPort)
		if e.Details != "" {
			return fmt.Sprintf("%s %s %s %s [%s]", base, proto, addr, e.Details, e.FilterAction)
		}
		return fmt.Sprintf("%s %s %s [%s]", base, proto, addr, e.FilterAction)
	}

	if e.Protocol == "ARP" {
		if e.Details != "" {
			return fmt.Sprintf("%s %s %s [%s]", base, e.Protocol, e.Details, e.FilterAction)
		}
		return fmt.Sprintf("%s %s [%s]", base, e.Protocol, e.FilterAction)
	}

	return fmt.Sprintf("%s proto=%s frameLen=%d [%s]", base, zeroIfEmpty(proto), e.FrameLength, e.FilterAction)
}

func zeroIfEmpty(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

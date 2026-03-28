package packet

import (
	"fmt"
	"time"
)

type Event struct {
	ID                 int64     `json:"id"`
	Timestamp          time.Time `json:"timestamp"`
	AgentIP            string    `json:"agent_ip"`
	RemoteAddr         string    `json:"remote_addr"`
	DatagramSequence   uint32    `json:"datagram_sequence"`
	SampleSequence     uint32    `json:"sample_sequence"`
	SampleType         string    `json:"sample_type"`
	SourceID           string    `json:"source_id"`
	Input              string    `json:"input"`
	Output             string    `json:"output"`
	SamplingRate       uint32    `json:"sampling_rate"`
	SamplePool         uint32    `json:"sample_pool"`
	Drops              uint32    `json:"drops"`
	RecordIndex        uint32    `json:"record_index"`
	HeaderProtocol     uint32    `json:"header_protocol"`
	FrameLength        uint32    `json:"frame_length"`
	Stripped           uint32    `json:"stripped"`
	HeaderLength       uint32    `json:"header_length"`
	DstMAC             string    `json:"dst_mac"`
	SrcMAC             string    `json:"src_mac"`
	EtherType          string    `json:"ether_type"`
	Network            string    `json:"network"`
	Protocol           string    `json:"protocol"`
	Details            string    `json:"details"`
	SrcIP              string    `json:"src_ip"`
	DstIP              string    `json:"dst_ip"`
	TTL                uint8     `json:"ttl"`
	IPFlags            string    `json:"ip_flags"`
	FragOffset         uint16    `json:"frag_offset"`
	IPTotalLen         uint16    `json:"ip_total_len"`
	MaxMTU             uint16    `json:"max_mtu"`
	IPProtocol         string    `json:"ip_protocol"`
	Transport          string    `json:"transport"`
	SrcPort            uint16    `json:"src_port"`
	DstPort            uint16    `json:"dst_port"`
	TCPSeq             uint32    `json:"tcp_seq"`
	TCPAck             uint32    `json:"tcp_ack"`
	TCPFlags           string    `json:"tcp_flags"`
	HandshakeComplete  bool      `json:"handshake_complete"`
	HandshakeStep      int       `json:"handshake_step"`
	InEstablishedSession bool    `json:"in_established_session"`
	ARPSourceIP        string    `json:"arp_source_ip"`
	ARPTargetIP        string    `json:"arp_target_ip"`
	ICMPType           string    `json:"icmp_type"`
	DNSQuery           string    `json:"dns_query"`
	HTTPStartLine      string    `json:"http_start_line"`
	SSHBanner          string    `json:"ssh_banner"`
	FilterName         string    `json:"filter_name"`
	FilterAction       string    `json:"filter_action"`
	FilterReason       string    `json:"filter_reason"`
	Allowed            bool      `json:"allowed"`
	Alert              bool      `json:"alert"`
	AlertName          string    `json:"alert_name"`
	AlertReason        string    `json:"alert_reason"`
	CurrentPPS         float64   `json:"current_pps"`
	SourcePPS          float64   `json:"source_pps"`
	SourceTrustScore   int       `json:"source_trust_score"`
	BaselinePPS        float64   `json:"baseline_pps"`
	SpikePPS           float64   `json:"spike_pps"`
	ProfileActive      bool      `json:"profile_active"`
	ProfileKey         string    `json:"profile_key"`
	DestinationIsLocal bool      `json:"destination_is_local"`
	PayloadHex         string    `json:"payload_hex"`
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

package sflow

import (
	"dolly-sensor/packet"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

func decodePacketLayers(header []byte, pkt *packet.Event) {
	if len(header) >= 14 {
		pkt.DstMAC = net.HardwareAddr(header[0:6]).String()
		pkt.SrcMAC = net.HardwareAddr(header[6:12]).String()
		etherType := binary.BigEndian.Uint16(header[12:14])
		pkt.EtherType = fmt.Sprintf("0x%04x", etherType)

		switch etherType {
		case 0x0800:
			pkt.Network = "IPv4"
			decodeIPv4(header[14:], pkt)
			return
		case 0x0806:
			pkt.Network = "ARP"
			pkt.Protocol = "ARP"
			decodeARP(header[14:], pkt)
			return
		case 0x86dd:
			pkt.Network = "IPv6"
			decodeIPv6(header[14:], pkt)
			return
		case 0x8100:
			if len(header) >= 18 {
				innerEtherType := binary.BigEndian.Uint16(header[16:18])
				pkt.EtherType = fmt.Sprintf("0x8100 -> 0x%04x", innerEtherType)
				switch innerEtherType {
				case 0x0800:
					pkt.Network = "IPv4"
					decodeIPv4(header[18:], pkt)
					return
				case 0x0806:
					pkt.Network = "ARP"
					pkt.Protocol = "ARP"
					decodeARP(header[18:], pkt)
					return
				case 0x86dd:
					pkt.Network = "IPv6"
					decodeIPv6(header[18:], pkt)
					return
				}
			}
		}
	}

	pkt.Network = protocolName(pkt.HeaderProtocol)
	if pkt.Protocol == "" {
		pkt.Protocol = pkt.Network
	}
}

func decodeIPv4(payload []byte, pkt *packet.Event) {
	if len(payload) < 20 {
		return
	}

	ihl := int(payload[0]&0x0F) * 4
	if ihl < 20 || len(payload) < ihl {
		return
	}

	pkt.TTL = payload[8]
	pkt.IPTotalLen = binary.BigEndian.Uint16(payload[2:4])
	pkt.MaxMTU = 1500 // Por defecto, hasta que procesemos contadores sFlow de interfaz.

	flagsAndOffset := binary.BigEndian.Uint16(payload[6:8])
	pkt.IPFlags = formatIPFlags(byte(flagsAndOffset >> 13))
	pkt.FragOffset = flagsAndOffset & 0x1FFF

	proto := payload[9]
	pkt.IPProtocol = transportName(proto)
	pkt.SrcIP = net.IP(payload[12:16]).String()
	pkt.DstIP = net.IP(payload[16:20]).String()

	decodeTransport(proto, payload[ihl:], pkt)
}

func formatIPFlags(f byte) string {
	var flags []string
	if f&0x02 != 0 {
		flags = append(flags, "DF")
	}
	if f&0x01 != 0 {
		flags = append(flags, "MF")
	}
	if len(flags) == 0 {
		return "none"
	}
	return strings.Join(flags, ",")
}

func decodeIPv6(payload []byte, pkt *packet.Event) {
	if len(payload) < 40 {
		return
	}

	nextHeader := payload[6]
	pkt.TTL = payload[7]
	pkt.IPTotalLen = binary.BigEndian.Uint16(payload[4:6]) + 40
	pkt.MaxMTU = 1500
	pkt.IPProtocol = transportName(nextHeader)
	pkt.SrcIP = net.IP(payload[8:24]).String()
	pkt.DstIP = net.IP(payload[24:40]).String()

	decodeTransport(nextHeader, payload[40:], pkt)
}

func decodeTransport(proto byte, payload []byte, pkt *packet.Event) {
	switch proto {
	case 6:
		pkt.Transport = "TCP"
		pkt.Protocol = "TCP"
		if len(payload) < 20 {
			return
		}
		pkt.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		pkt.DstPort = binary.BigEndian.Uint16(payload[2:4])
		pkt.TCPSeq = binary.BigEndian.Uint32(payload[4:8])
		pkt.TCPAck = binary.BigEndian.Uint32(payload[8:12])
		pkt.TCPFlags = formatTCPFlags(payload[13])
		dataOffset := int(payload[12]>>4) * 4
		if dataOffset < 20 || len(payload) < dataOffset {
			return
		}
		decodeTCPApplication(payload[dataOffset:], pkt)
	case 17:
		pkt.Transport = "UDP"
		pkt.Protocol = "UDP"
		if len(payload) < 8 {
			return
		}
		pkt.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		pkt.DstPort = binary.BigEndian.Uint16(payload[2:4])
		decodeUDPApplication(payload[8:], pkt)
	case 1:
		pkt.Transport = "ICMP"
		pkt.Protocol = "ICMP"
		decodeICMP(payload, pkt, false)
	case 58:
		pkt.Transport = "ICMPv6"
		pkt.Protocol = "ICMPv6"
		decodeICMP(payload, pkt, true)
	default:
		pkt.Transport = transportName(proto)
		pkt.Protocol = pkt.Transport
	}
}

func formatTCPFlags(f byte) string {
	var flags []string
	if f&0x01 != 0 {
		flags = append(flags, "FIN")
	}
	if f&0x02 != 0 {
		flags = append(flags, "SYN")
	}
	if f&0x04 != 0 {
		flags = append(flags, "RST")
	}
	if f&0x08 != 0 {
		flags = append(flags, "PSH")
	}
	if f&0x10 != 0 {
		flags = append(flags, "ACK")
	}
	if f&0x20 != 0 {
		flags = append(flags, "URG")
	}
	if f&0x40 != 0 {
		flags = append(flags, "ECE")
	}
	if f&0x80 != 0 {
		flags = append(flags, "CWR")
	}

	if len(flags) == 0 {
		return fmt.Sprintf("0x%02x", f)
	}
	return strings.Join(flags, "/")
}

func decodeARP(payload []byte, pkt *packet.Event) {
	if len(payload) < 28 {
		return
	}

	opcode := binary.BigEndian.Uint16(payload[6:8])
	senderMAC := net.HardwareAddr(payload[8:14]).String()
	senderIP := net.IP(payload[14:18]).String()
	targetMAC := net.HardwareAddr(payload[18:24]).String()
	targetIP := net.IP(payload[24:28]).String()

	pkt.ARPSourceIP = senderIP
	pkt.ARPTargetIP = targetIP
	pkt.SrcMAC = senderMAC
	pkt.DstMAC = targetMAC

	switch opcode {
	case 1:
		pkt.Details = fmt.Sprintf("request %s asks for %s", senderIP, targetIP)
	case 2:
		pkt.Details = fmt.Sprintf("reply %s is-at %s for %s", senderIP, senderMAC, targetIP)
	default:
		pkt.Details = fmt.Sprintf("opcode=%d %s -> %s", opcode, senderIP, targetIP)
	}
}

func decodeICMP(payload []byte, pkt *packet.Event, ipv6 bool) {
	if len(payload) < 2 {
		return
	}

	typ := payload[0]
	code := payload[1]
	if ipv6 {
		pkt.ICMPType = icmpv6TypeName(typ, code)
	} else {
		pkt.ICMPType = icmpTypeName(typ, code)
	}
	pkt.Details = fmt.Sprintf("type=%d code=%d %s", typ, code, pkt.ICMPType)
}

func decodeUDPApplication(payload []byte, pkt *packet.Event) {
	if name := packet.GlobalProtocols.GetName("UDP", pkt.SrcPort); name != "" {
		pkt.Protocol = name
	} else if name := packet.GlobalProtocols.GetName("UDP", pkt.DstPort); name != "" {
		pkt.Protocol = name
	}

	if pkt.Protocol == "DNS" || pkt.SrcPort == 53 || pkt.DstPort == 53 {
		decodeDNS(payload, pkt, false)
	}
}

func decodeTCPApplication(payload []byte, pkt *packet.Event) {
	// 1. Fallback por puerto (mapeo dinámico)
	if name := packet.GlobalProtocols.GetName("TCP", pkt.SrcPort); name != "" {
		pkt.Protocol = name
	} else if name := packet.GlobalProtocols.GetName("TCP", pkt.DstPort); name != "" {
		pkt.Protocol = name
	}

	if len(payload) == 0 {
		if pkt.Protocol == "" && (pkt.SrcPort == 22 || pkt.DstPort == 22) {
			pkt.Protocol = "SSH"
			pkt.Details = "port 22"
		}
		return
	}

	// 2. Disectores específicos (pueden sobreescribir el nombre si detectan contenido)
	if pkt.Protocol == "DNS" || pkt.SrcPort == 53 || pkt.DstPort == 53 {
		if decodeDNS(payload, pkt, true) {
			return
		}
	}

	if isHTTPPayload(payload) {
		pkt.Protocol = "HTTP"
		pkt.HTTPStartLine = firstLine(payload)
		pkt.Details = pkt.HTTPStartLine
		return
	}

	if bytesHasPrefixFold(payload, "SSH-") {
		pkt.Protocol = "SSH"
		pkt.SSHBanner = firstLine(payload)
		pkt.Details = pkt.SSHBanner
		return
	}
}

func decodeDNS(payload []byte, pkt *packet.Event, tcp bool) bool {
	if tcp {
		if len(payload) < 2 {
			return false
		}
		msgLen := int(binary.BigEndian.Uint16(payload[0:2]))
		if msgLen == 0 || len(payload) < 2+msgLen {
			return false
		}
		payload = payload[2 : 2+msgLen]
	}

	if len(payload) < 12 {
		return false
	}

	flags := binary.BigEndian.Uint16(payload[2:4])
	qr := (flags & 0x8000) != 0
	qdCount := binary.BigEndian.Uint16(payload[4:6])

	pkt.Protocol = "DNS"
	if qr {
		pkt.Details = "response"
	} else {
		pkt.Details = "query"
	}

	if qdCount == 0 {
		return true
	}

	name, ok := parseDNSName(payload, 12, 0)
	if !ok {
		return true
	}
	pkt.DNSQuery = name
	return true
}

func parseDNSName(msg []byte, off int, depth int) (string, bool) {
	if depth > 8 || off >= len(msg) {
		return "", false
	}

	labels := make([]string, 0, 4)
	for off < len(msg) {
		l := int(msg[off])
		off++
		if l == 0 {
			return strings.Join(labels, "."), true
		}
		if l&0xC0 == 0xC0 {
			if off >= len(msg) {
				return "", false
			}
			ptr := ((l & 0x3F) << 8) | int(msg[off])
			name, ok := parseDNSName(msg, ptr, depth+1)
			if !ok {
				return "", false
			}
			labels = append(labels, name)
			return strings.Join(labels, "."), true
		}
		if off+l > len(msg) {
			return "", false
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}

	return "", false
}

func protocolName(v uint32) string {
	switch v {
	case 1:
		return "Ethernet"
	case 11:
		return "IPv4"
	case 12:
		return "IPv6"
	default:
		return fmt.Sprintf("header_protocol_%d", v)
	}
}

func transportName(v byte) string {
	switch v {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("IP-%d", v)
	}
}

func formatHexDump(b []byte) string {
	lines := make([]string, 0, (len(b)+15)/16)
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		chunk := b[i:end]
		lines = append(lines, fmt.Sprintf("%04x  %-47s", i, spacedHex(chunk)))
	}
	return strings.Join(lines, "\n")
}

func spacedHex(b []byte) string {
	raw := strings.ToUpper(hex.EncodeToString(b))
	if len(raw) == 0 {
		return ""
	}

	var sb strings.Builder
	for i := 0; i < len(raw); i += 2 {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(raw[i : i+2])
	}
	return sb.String()
}

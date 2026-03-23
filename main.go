package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	listenAddr       = "127.0.0.1:6343"
	httpAddr         = "127.0.0.1:8080"
	maxDatagramSize  = 65535
	maxRecentPackets = 200
)

type decoder struct {
	buf []byte
	off int
}

type packetStore struct {
	mu      sync.RWMutex
	packets []packetEvent
	nextID  int64
	clients map[chan packetEvent]struct{}
}

type packetEvent struct {
	ID               int64     `json:"id"`
	Timestamp        time.Time `json:"timestamp"`
	AgentIP          string    `json:"agentIP"`
	RemoteAddr       string    `json:"remoteAddr"`
	DatagramSequence uint32    `json:"datagramSequence"`
	SampleSequence   uint32    `json:"sampleSequence"`
	SampleType       string    `json:"sampleType"`
	SourceID         string    `json:"sourceID"`
	Input            string    `json:"input"`
	Output           string    `json:"output"`
	SamplingRate     uint32    `json:"samplingRate"`
	SamplePool       uint32    `json:"samplePool"`
	Drops            uint32    `json:"drops"`
	RecordIndex      uint32    `json:"recordIndex"`
	HeaderProtocol   uint32    `json:"headerProtocol"`
	FrameLength      uint32    `json:"frameLength"`
	Stripped         uint32    `json:"stripped"`
	HeaderLength     uint32    `json:"headerLength"`
	DstMAC           string    `json:"dstMAC,omitempty"`
	SrcMAC           string    `json:"srcMAC,omitempty"`
	EtherType        string    `json:"etherType,omitempty"`
	Network          string    `json:"network,omitempty"`
	Protocol         string    `json:"protocol,omitempty"`
	Details          string    `json:"details,omitempty"`
	SrcIP            string    `json:"srcIP,omitempty"`
	DstIP            string    `json:"dstIP,omitempty"`
	TTL              uint8     `json:"ttl,omitempty"`
	IPProtocol       string    `json:"ipProtocol,omitempty"`
	Transport        string    `json:"transport,omitempty"`
	SrcPort          uint16    `json:"srcPort,omitempty"`
	DstPort          uint16    `json:"dstPort,omitempty"`
	TCPFlags         string    `json:"tcpFlags,omitempty"`
	ARPSourceIP      string    `json:"arpSourceIP,omitempty"`
	ARPTargetIP      string    `json:"arpTargetIP,omitempty"`
	ICMPType         string    `json:"icmpType,omitempty"`
	DNSQuery         string    `json:"dnsQuery,omitempty"`
	HTTPStartLine    string    `json:"httpStartLine,omitempty"`
	SSHBanner        string    `json:"sshBanner,omitempty"`
	PayloadHex       string    `json:"payloadHex"`
	Summary          string    `json:"summary"`
}

type flowSampleInfo struct {
	SampleSequence uint32
	SampleType     string
	SourceID       string
	Input          string
	Output         string
	SamplingRate   uint32
	SamplePool     uint32
	Drops          uint32
}

var packets = newPacketStore(maxRecentPackets)

func newPacketStore(capacity int) *packetStore {
	return &packetStore{
		packets: make([]packetEvent, 0, capacity),
		clients: make(map[chan packetEvent]struct{}),
	}
}

func (d *decoder) remaining() int {
	return len(d.buf) - d.off
}

func (d *decoder) u32() (uint32, error) {
	if d.remaining() < 4 {
		return 0, fmt.Errorf("need 4 bytes, have %d", d.remaining())
	}
	v := binary.BigEndian.Uint32(d.buf[d.off : d.off+4])
	d.off += 4
	return v, nil
}

func (d *decoder) bytes(n int) ([]byte, error) {
	if n < 0 || d.remaining() < n {
		return nil, fmt.Errorf("need %d bytes, have %d", n, d.remaining())
	}
	v := d.buf[d.off : d.off+n]
	d.off += n
	return v, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	go runHTTPServer()
	runSFlowListener()
}

func runSFlowListener() {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatalf("resolve %s: %v", listenAddr, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", listenAddr, err)
	}
	defer conn.Close()

	log.Printf("listening for sFlow on %s", listenAddr)

	buf := make([]byte, maxDatagramSize)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read error: %v", err)
			continue
		}

		parseDatagram(remote, append([]byte(nil), buf[:n]...))
	}
}

func runHTTPServer() {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("web")))
	mux.HandleFunc("/api/packets", handlePackets)
	mux.HandleFunc("/api/events", handleEvents)

	log.Printf("web UI available at http://%s", httpAddr)
	if err := http.ListenAndServe(httpAddr, mux); err != nil {
		log.Fatalf("http server: %v", err)
	}
}

func handlePackets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(packets.snapshot()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := packets.subscribe()
	defer packets.unsubscribe(ch)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-ch:
			if err := writeSSE(w, pkt); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, pkt packetEvent) error {
	data, err := json.Marshal(pkt)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "data: %s\n\n", data)
	return err
}

func (s *packetStore) snapshot() []packetEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]packetEvent, len(s.packets))
	copy(out, s.packets)
	return out
}

func (s *packetStore) subscribe() chan packetEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := make(chan packetEvent, 32)
	s.clients[ch] = struct{}{}
	return ch
}

func (s *packetStore) unsubscribe(ch chan packetEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.clients, ch)
}

func (s *packetStore) add(pkt packetEvent) {
	s.mu.Lock()
	s.nextID++
	pkt.ID = s.nextID
	if len(s.packets) == cap(s.packets) {
		copy(s.packets, s.packets[1:])
		s.packets[len(s.packets)-1] = pkt
	} else {
		s.packets = append(s.packets, pkt)
	}

	clients := make([]chan packetEvent, 0, len(s.clients))
	for ch := range s.clients {
		clients = append(clients, ch)
	}
	s.mu.Unlock()

	for _, ch := range clients {
		select {
		case ch <- pkt:
		default:
		}
	}
}

func parseDatagram(remote *net.UDPAddr, pkt []byte) {
	d := decoder{buf: pkt}

	version, err := d.u32()
	if err != nil {
		log.Printf("short packet from %s: %v", remote, err)
		return
	}
	if version != 5 {
		log.Printf("packet from %s has unsupported sFlow version %d", remote, version)
		return
	}

	ipVersion, err := d.u32()
	if err != nil {
		log.Printf("invalid datagram from %s: missing agent address type: %v", remote, err)
		return
	}

	agentIP, err := readAgentAddress(&d, ipVersion)
	if err != nil {
		log.Printf("invalid datagram from %s: %v", remote, err)
		return
	}

	subAgentID, err := d.u32()
	if err != nil {
		log.Printf("invalid datagram from %s: missing sub-agent id: %v", remote, err)
		return
	}
	sequenceNumber, err := d.u32()
	if err != nil {
		log.Printf("invalid datagram from %s: missing sequence number: %v", remote, err)
		return
	}
	uptimeMS, err := d.u32()
	if err != nil {
		log.Printf("invalid datagram from %s: missing uptime: %v", remote, err)
		return
	}
	sampleCount, err := d.u32()
	if err != nil {
		log.Printf("invalid datagram from %s: missing sample count: %v", remote, err)
		return
	}

	log.Printf(
		"sFlow datagram remote=%s agent=%s seq=%d uptime=%s subAgent=%d samples=%d size=%dB",
		remote,
		agentIP,
		sequenceNumber,
		time.Duration(uptimeMS)*time.Millisecond,
		subAgentID,
		sampleCount,
		len(pkt),
	)

	for i := uint32(0); i < sampleCount; i++ {
		if err := parseSample(&d, i, remote.String(), agentIP, sequenceNumber); err != nil {
			log.Printf("sample %d parse error: %v", i+1, err)
			return
		}
	}

	if d.remaining() > 0 {
		log.Printf("datagram seq=%d has %d trailing bytes", sequenceNumber, d.remaining())
	}
}

func readAgentAddress(d *decoder, ipVersion uint32) (string, error) {
	switch ipVersion {
	case 1:
		b, err := d.bytes(4)
		if err != nil {
			return "", fmt.Errorf("missing IPv4 agent address: %w", err)
		}
		return net.IP(b).String(), nil
	case 2:
		b, err := d.bytes(16)
		if err != nil {
			return "", fmt.Errorf("missing IPv6 agent address: %w", err)
		}
		return net.IP(b).String(), nil
	default:
		return "", fmt.Errorf("unknown agent address type %d", ipVersion)
	}
}

func parseSample(d *decoder, index uint32, remoteAddr, agentIP string, datagramSequence uint32) error {
	format, err := d.u32()
	if err != nil {
		return fmt.Errorf("missing sample format: %w", err)
	}
	length, err := d.u32()
	if err != nil {
		return fmt.Errorf("missing sample length: %w", err)
	}
	body, err := d.bytes(int(length))
	if err != nil {
		return fmt.Errorf("sample body truncated: %w", err)
	}

	enterprise := format >> 12
	sampleType := format & 0x0FFF

	if enterprise != 0 {
		log.Printf("sample[%d] enterprise=%d type=%d length=%d skipped", index+1, enterprise, sampleType, length)
		return nil
	}

	switch sampleType {
	case 1:
		return parseFlowSample(body, false, remoteAddr, agentIP, datagramSequence)
	case 3:
		return parseFlowSample(body, true, remoteAddr, agentIP, datagramSequence)
	default:
		log.Printf("sample[%d] type=%d length=%d skipped", index+1, sampleType, length)
		return nil
	}
}

func parseFlowSample(body []byte, expanded bool, remoteAddr, agentIP string, datagramSequence uint32) error {
	d := decoder{buf: body}

	seq, err := d.u32()
	if err != nil {
		return fmt.Errorf("missing sample sequence: %w", err)
	}

	info := flowSampleInfo{
		SampleSequence: seq,
		SampleType:     "flow_sample",
	}

	if expanded {
		info.SampleType = "expanded_flow_sample"

		dsClass, err := d.u32()
		if err != nil {
			return fmt.Errorf("missing source class: %w", err)
		}
		dsIndex, err := d.u32()
		if err != nil {
			return fmt.Errorf("missing source index: %w", err)
		}
		info.SourceID = fmt.Sprintf("%d/%d", dsClass, dsIndex)

		info.SamplingRate, err = d.u32()
		if err != nil {
			return fmt.Errorf("missing sampling rate: %w", err)
		}
		info.SamplePool, err = d.u32()
		if err != nil {
			return fmt.Errorf("missing sample pool: %w", err)
		}
		info.Drops, err = d.u32()
		if err != nil {
			return fmt.Errorf("missing drops: %w", err)
		}

		inFormat, err := d.u32()
		if err != nil {
			return fmt.Errorf("missing input format: %w", err)
		}
		inValue, err := d.u32()
		if err != nil {
			return fmt.Errorf("missing input value: %w", err)
		}
		outFormat, err := d.u32()
		if err != nil {
			return fmt.Errorf("missing output format: %w", err)
		}
		outValue, err := d.u32()
		if err != nil {
			return fmt.Errorf("missing output value: %w", err)
		}
		info.Input = fmt.Sprintf("%d/%d", inFormat, inValue)
		info.Output = fmt.Sprintf("%d/%d", outFormat, outValue)
	} else {
		sourceID, err := d.u32()
		if err != nil {
			return fmt.Errorf("missing source id: %w", err)
		}
		info.SourceID = formatSourceID(sourceID)

		info.SamplingRate, err = d.u32()
		if err != nil {
			return fmt.Errorf("missing sampling rate: %w", err)
		}
		info.SamplePool, err = d.u32()
		if err != nil {
			return fmt.Errorf("missing sample pool: %w", err)
		}
		info.Drops, err = d.u32()
		if err != nil {
			return fmt.Errorf("missing drops: %w", err)
		}

		input, err := d.u32()
		if err != nil {
			return fmt.Errorf("missing input: %w", err)
		}
		output, err := d.u32()
		if err != nil {
			return fmt.Errorf("missing output: %w", err)
		}
		info.Input = fmt.Sprintf("%d", input)
		info.Output = fmt.Sprintf("%d", output)
	}

	recordCount, err := d.u32()
	if err != nil {
		return fmt.Errorf("missing record count: %w", err)
	}

	foundPackets := 0
	for i := uint32(0); i < recordCount; i++ {
		recFormat, err := d.u32()
		if err != nil {
			return fmt.Errorf("record %d missing format: %w", i+1, err)
		}
		recLen, err := d.u32()
		if err != nil {
			return fmt.Errorf("record %d missing length: %w", i+1, err)
		}
		recBody, err := d.bytes(int(recLen))
		if err != nil {
			return fmt.Errorf("record %d truncated: %w", i+1, err)
		}

		recEnterprise := recFormat >> 12
		recType := recFormat & 0x0FFF
		if recEnterprise != 0 || recType != 1 {
			continue
		}

		pkt, ok, err := parseRawPacketHeaderRecord(recBody, remoteAddr, agentIP, datagramSequence, info, i+1)
		if err != nil {
			log.Printf("sample seq=%d record=%d raw packet header parse error: %v", info.SampleSequence, i+1, err)
			continue
		}
		if !ok {
			continue
		}

		foundPackets++
		packets.add(pkt)
		log.Printf(
			"inner packet sampleSeq=%d record=%d src=%s:%d dst=%s:%d proto=%s",
			pkt.SampleSequence,
			pkt.RecordIndex,
			zeroIfEmpty(pkt.SrcIP),
			pkt.SrcPort,
			zeroIfEmpty(pkt.DstIP),
			pkt.DstPort,
			bestProtocol(pkt),
		)
	}

	log.Printf(
		"%s seq=%d source=%s rate=%d pool=%d drops=%d in=%s out=%s records=%d innerPackets=%d",
		info.SampleType,
		info.SampleSequence,
		info.SourceID,
		info.SamplingRate,
		info.SamplePool,
		info.Drops,
		info.Input,
		info.Output,
		recordCount,
		foundPackets,
	)

	return nil
}

func parseRawPacketHeaderRecord(body []byte, remoteAddr, agentIP string, datagramSequence uint32, info flowSampleInfo, recordIndex uint32) (packetEvent, bool, error) {
	d := decoder{buf: body}

	headerProtocol, err := d.u32()
	if err != nil {
		return packetEvent{}, false, fmt.Errorf("missing header protocol: %w", err)
	}
	frameLength, err := d.u32()
	if err != nil {
		return packetEvent{}, false, fmt.Errorf("missing frame length: %w", err)
	}
	stripped, err := d.u32()
	if err != nil {
		return packetEvent{}, false, fmt.Errorf("missing stripped count: %w", err)
	}
	headerLength, err := d.u32()
	if err != nil {
		return packetEvent{}, false, fmt.Errorf("missing header length: %w", err)
	}
	headerBytes, err := d.bytes(int(headerLength))
	if err != nil {
		return packetEvent{}, false, fmt.Errorf("truncated header bytes: %w", err)
	}
	if len(headerBytes) == 0 {
		return packetEvent{}, false, nil
	}

	pkt := packetEvent{
		Timestamp:        time.Now(),
		AgentIP:          agentIP,
		RemoteAddr:       remoteAddr,
		DatagramSequence: datagramSequence,
		SampleSequence:   info.SampleSequence,
		SampleType:       info.SampleType,
		SourceID:         info.SourceID,
		Input:            info.Input,
		Output:           info.Output,
		SamplingRate:     info.SamplingRate,
		SamplePool:       info.SamplePool,
		Drops:            info.Drops,
		RecordIndex:      recordIndex,
		HeaderProtocol:   headerProtocol,
		FrameLength:      frameLength,
		Stripped:         stripped,
		HeaderLength:     headerLength,
		PayloadHex:       formatHexDump(headerBytes),
	}

	decodePacketLayers(headerBytes, &pkt)
	pkt.Summary = buildSummary(pkt)

	return pkt, true, nil
}

func decodePacketLayers(header []byte, pkt *packetEvent) {
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

func decodeIPv4(payload []byte, pkt *packetEvent) {
	if len(payload) < 20 {
		return
	}

	ihl := int(payload[0]&0x0F) * 4
	if ihl < 20 || len(payload) < ihl {
		return
	}

	pkt.TTL = payload[8]
	proto := payload[9]
	pkt.IPProtocol = transportName(proto)
	pkt.SrcIP = net.IP(payload[12:16]).String()
	pkt.DstIP = net.IP(payload[16:20]).String()

	decodeTransport(proto, payload[ihl:], pkt)
}

func decodeIPv6(payload []byte, pkt *packetEvent) {
	if len(payload) < 40 {
		return
	}

	nextHeader := payload[6]
	pkt.TTL = payload[7]
	pkt.IPProtocol = transportName(nextHeader)
	pkt.SrcIP = net.IP(payload[8:24]).String()
	pkt.DstIP = net.IP(payload[24:40]).String()

	decodeTransport(nextHeader, payload[40:], pkt)
}

func decodeTransport(proto byte, payload []byte, pkt *packetEvent) {
	switch proto {
	case 6:
		pkt.Transport = "TCP"
		pkt.Protocol = "TCP"
		if len(payload) < 20 {
			return
		}
		pkt.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		pkt.DstPort = binary.BigEndian.Uint16(payload[2:4])
		pkt.TCPFlags = strings.ToUpper(fmt.Sprintf("0x%02x", payload[13]))
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

func buildSummary(pkt packetEvent) string {
	base := fmt.Sprintf("%s sample=%d record=%d", pkt.SampleType, pkt.SampleSequence, pkt.RecordIndex)
	proto := bestProtocol(pkt)
	if pkt.SrcIP != "" || pkt.DstIP != "" {
		addr := fmt.Sprintf("%s:%d -> %s:%d", zeroIfEmpty(pkt.SrcIP), pkt.SrcPort, zeroIfEmpty(pkt.DstIP), pkt.DstPort)
		if pkt.Details != "" {
			return fmt.Sprintf("%s %s %s %s", base, proto, addr, pkt.Details)
		}
		return fmt.Sprintf("%s %s %s", base, proto, addr)
	}
	if pkt.Protocol == "ARP" {
		if pkt.Details != "" {
			return fmt.Sprintf("%s %s %s", base, pkt.Protocol, pkt.Details)
		}
		return fmt.Sprintf("%s %s", base, pkt.Protocol)
	}
	return fmt.Sprintf("%s proto=%s frameLen=%d", base, zeroIfEmpty(proto), pkt.FrameLength)
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

func decodeARP(payload []byte, pkt *packetEvent) {
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

func decodeICMP(payload []byte, pkt *packetEvent, ipv6 bool) {
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

func decodeUDPApplication(payload []byte, pkt *packetEvent) {
	if pkt.SrcPort == 53 || pkt.DstPort == 53 {
		if decodeDNS(payload, pkt, false) {
			return
		}
	}
}

func decodeTCPApplication(payload []byte, pkt *packetEvent) {
	if len(payload) == 0 {
		if pkt.SrcPort == 22 || pkt.DstPort == 22 {
			pkt.Protocol = "SSH"
			pkt.Details = "port 22"
		}
		return
	}

	if pkt.SrcPort == 53 || pkt.DstPort == 53 {
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

	if pkt.SrcPort == 22 || pkt.DstPort == 22 {
		pkt.Protocol = "SSH"
		pkt.Details = "port 22"
	}
}

func decodeDNS(payload []byte, pkt *packetEvent, tcp bool) bool {
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
	pkt.Details = fmt.Sprintf("%s %s", pkt.Details, name)
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

func bestProtocol(pkt packetEvent) string {
	if pkt.Protocol != "" {
		return pkt.Protocol
	}
	if pkt.Transport != "" {
		return pkt.Transport
	}
	if pkt.IPProtocol != "" {
		return pkt.IPProtocol
	}
	if pkt.Network != "" {
		return pkt.Network
	}
	return "-"
}

func formatSourceID(v uint32) string {
	return fmt.Sprintf("%d/%d", v>>24, v&0x00FFFFFF)
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

func zeroIfEmpty(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

func init() {
	if _, err := os.Stat("web/index.html"); err != nil {
		log.Printf("warning: web frontend missing: %v", err)
	}
}

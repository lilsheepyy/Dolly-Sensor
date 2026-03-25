package sflow

import (
	"dolly-sensor/filter"
	"dolly-sensor/packet"
	"dolly-sensor/store"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

type Processor struct {
	store     *store.Store
	filters   []filter.Evaluator
	ownedNets []*net.IPNet
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

type decoder struct {
	buf []byte
	off int
}

func NewProcessor(packetStore *store.Store, evaluators []filter.Evaluator, ownedNets []*net.IPNet) *Processor {
	return &Processor{
		store:     packetStore,
		filters:   evaluators,
		ownedNets: ownedNets,
	}
}

func (p *Processor) ParseDatagram(remote *net.UDPAddr, pkt []byte) {
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

	for i := uint32(0); i < sampleCount; i++ {
		if err := p.parseSample(&d, i, remote.String(), agentIP, sequenceNumber); err != nil {
			log.Printf("sample %d parse error: %v", i+1, err)
			return
		}
	}
	_ = subAgentID
	_ = uptimeMS
}

func (p *Processor) parseSample(d *decoder, index uint32, remoteAddr, agentIP string, datagramSequence uint32) error {
	format, err := d.u32()
	if err != nil {
		return fmt.Errorf("missing sample format: %w", err)
	}
	length, err := d.u32()
	if err != nil {
		return fmt.Errorf("missing sample length: %w", err)
	}
	body, err := d.bytes(pad4(int(length)))
	if err != nil {
		return fmt.Errorf("sample body truncated: %w", err)
	}
	body = body[:int(length)]

	enterprise := format >> 12
	sampleType := format & 0x0FFF

	if enterprise != 0 {
		log.Printf("sample[%d] enterprise=%d type=%d length=%d skipped", index+1, enterprise, sampleType, length)
		return nil
	}

	switch sampleType {
	case 1:
		return p.parseFlowSample(body, false, remoteAddr, agentIP, datagramSequence)
	case 3:
		return p.parseFlowSample(body, true, remoteAddr, agentIP, datagramSequence)
	default:
		log.Printf("sample[%d] type=%d length=%d skipped", index+1, sampleType, length)
		return nil
	}
}

func (p *Processor) parseFlowSample(body []byte, expanded bool, remoteAddr, agentIP string, datagramSequence uint32) error {
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
		recBody, err := d.bytes(pad4(int(recLen)))
		if err != nil {
			return fmt.Errorf("record %d truncated: %w", i+1, err)
		}
		recBody = recBody[:int(recLen)]

		recEnterprise := recFormat >> 12
		recType := recFormat & 0x0FFF
		if recEnterprise != 0 || recType != 1 {
			continue
		}

		pkt, ok, err := p.parseRawPacketHeaderRecord(recBody, remoteAddr, agentIP, datagramSequence, info, i+1)
		if err != nil {
			log.Printf("sample seq=%d record=%d raw packet header parse error: %v", info.SampleSequence, i+1, err)
			continue
		}
		if !ok {
			continue
		}
		if !p.isInbound(pkt) {
			continue
		}

		foundPackets++
		if seDescarto := p.store.Add(pkt); seDescarto {
			stats := p.store.Stats()
			log.Printf(
				"dropped event reason=store_capacity sampleSeq=%d record=%d src=%s:%d dst=%s:%d proto=%s capacity=%d",
				pkt.SampleSequence,
				pkt.RecordIndex,
				zeroIfEmpty(pkt.SrcIP),
				pkt.SrcPort,
				zeroIfEmpty(pkt.DstIP),
				pkt.DstPort,
				pkt.BestProtocol(),
				stats.Capacity,
			)
		}
		p.logBlockedPacket(pkt)
	}

	if info.Drops > 0 {
		log.Printf(
			"dropped event reason=sflow_sampler_drops sampleType=%s sampleSeq=%d source=%s drops=%d rate=%d pool=%d in=%s out=%s records=%d innerPackets=%d",
			info.SampleType,
			info.SampleSequence,
			info.SourceID,
			info.Drops,
			info.SamplingRate,
			info.SamplePool,
			info.Input,
			info.Output,
			recordCount,
			foundPackets,
		)
	}

	return nil
}

func (p *Processor) logBlockedPacket(pkt packet.Event) {
	if pkt.Allowed {
		return
	}

	log.Printf(
		"blocked packet src=%s:%d dst=%s:%d proto=%s filter=%s reason=%s alert=%t alertName=%s",
		zeroIfEmpty(pkt.SrcIP),
		pkt.SrcPort,
		zeroIfEmpty(pkt.DstIP),
		pkt.DstPort,
		pkt.BestProtocol(),
		zeroIfEmpty(pkt.FilterName),
		zeroIfEmpty(pkt.FilterReason),
		pkt.Alert,
		zeroIfEmpty(pkt.AlertName),
	)
}

func (p *Processor) isInbound(pkt packet.Event) bool {
	for _, candidate := range []string{pkt.DstIP, pkt.ARPTargetIP} {
		ip := net.ParseIP(candidate)
		if ip == nil {
			continue
		}
		for _, network := range p.ownedNets {
			if network.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (p *Processor) parseRawPacketHeaderRecord(body []byte, remoteAddr, agentIP string, datagramSequence uint32, info flowSampleInfo, recordIndex uint32) (packet.Event, bool, error) {
	d := decoder{buf: body}

	headerProtocol, err := d.u32()
	if err != nil {
		return packet.Event{}, false, fmt.Errorf("missing header protocol: %w", err)
	}
	frameLength, err := d.u32()
	if err != nil {
		return packet.Event{}, false, fmt.Errorf("missing frame length: %w", err)
	}
	stripped, err := d.u32()
	if err != nil {
		return packet.Event{}, false, fmt.Errorf("missing stripped count: %w", err)
	}
	headerLength, err := d.u32()
	if err != nil {
		return packet.Event{}, false, fmt.Errorf("missing header length: %w", err)
	}
	headerBytes, err := d.bytes(pad4(int(headerLength)))
	if err != nil {
		return packet.Event{}, false, fmt.Errorf("truncated header bytes: %w", err)
	}
	headerBytes = headerBytes[:int(headerLength)]
	if len(headerBytes) == 0 {
		return packet.Event{}, false, nil
	}

	pkt := packet.Event{
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
	p.applyFilters(&pkt)
	pkt.Summary = pkt.SummaryString()

	return pkt, true, nil
}

func (p *Processor) applyFilters(pkt *packet.Event) {
	input := filter.Packet{
		SourceIP:  pkt.SrcIP,
		SrcPort:   pkt.SrcPort,
		DstIP:     pkt.DstIP,
		Transport: pkt.Transport,
		DstPort:   pkt.DstPort,
	}

	decisions := make([]filter.Decision, 0, len(p.filters))
	for _, evaluator := range p.filters {
		decisions = append(decisions, evaluator.Evaluate(input))
	}

	pkt.FilterName = joinDecisionNames(decisions)
	pkt.FilterAction = "allowed"
	pkt.Allowed = true

	blockReasons := make([]string, 0)
	allowReasons := make([]string, 0)
	alertNames := make([]string, 0)
	alertReasons := make([]string, 0)
	for _, decision := range decisions {
		if decision.Action == "blocked" {
			pkt.FilterAction = "blocked"
			pkt.Allowed = false
			blockReasons = append(blockReasons, decision.Reason)
		} else if decision.Reason != "" {
			allowReasons = append(allowReasons, decision.Reason)
		}

		if decision.Alert {
			pkt.Alert = true
			if decision.AlertName != "" {
				alertNames = append(alertNames, decision.AlertName)
			}
			if decision.AlertReason != "" {
				alertReasons = append(alertReasons, decision.AlertReason)
			}
		}
		if decision.ProfileActive {
			pkt.CurrentPPS = decision.CurrentPPS
			pkt.BaselinePPS = decision.BaselinePPS
			pkt.SpikePPS = decision.SpikePPS
			pkt.ProfileActive = true
			pkt.ProfileKey = decision.ProfileKey
			pkt.DestinationIsLocal = decision.DestinationIsLocal
		}
	}

	if len(blockReasons) > 0 {
		pkt.AlertName = joinUnique(alertNames)
		pkt.AlertReason = strings.Join(alertReasons, " | ")
		pkt.FilterReason = strings.Join(blockReasons, " | ")
		return
	}
	pkt.AlertName = joinUnique(alertNames)
	pkt.AlertReason = strings.Join(alertReasons, " | ")
	pkt.FilterReason = strings.Join(allowReasons, " | ")
}

func joinDecisionNames(decisions []filter.Decision) string {
	names := make([]string, 0, len(decisions))
	for _, decision := range decisions {
		if decision.Name != "" {
			names = append(names, decision.Name)
		}
	}
	return strings.Join(names, ",")
}

func joinUnique(values []string) string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return strings.Join(out, ",")
}

func pad4(n int) int {
	return (n + 3) &^ 3
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

func formatSourceID(v uint32) string {
	return fmt.Sprintf("%d/%d", v>>24, v&0x00FFFFFF)
}

func zeroIfEmpty(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

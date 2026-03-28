package sflow

import (
	"dolly-sensor/analyzer"
	"dolly-sensor/config"
	"dolly-sensor/packet"
	"dolly-sensor/store"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type Processor struct {
	store         *store.Store
	perfilInbound *analyzer.PerfilInboundGlobal
	ownedNets     []*net.IPNet
	samplingRate  int
	cfg           config.Config
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

func NewProcessor(packetStore *store.Store, perfilInbound *analyzer.PerfilInboundGlobal, ownedNets []*net.IPNet, samplingRate int, cfg config.Config) *Processor {
	return &Processor{
		store:         packetStore,
		perfilInbound: perfilInbound,
		ownedNets:     ownedNets,
		samplingRate:  samplingRate,
		cfg:           cfg,
	}
}

func (p *Processor) ParseDatagram(remote *net.UDPAddr, pkt []byte) {
	d := decoder{buf: pkt}
	version, err := d.u32()
	if err != nil || version != 5 { return }

	ipVersion, err := d.u32()
	if err != nil { return }
	agentIP, err := readAgentAddress(&d, ipVersion)
	if err != nil { return }

	_, _ = d.u32()
	sequenceNumber, _ := d.u32()
	_, _ = d.u32()
	sampleCount, _ := d.u32()

	for i := uint32(0); i < sampleCount; i++ {
		p.parseSample(&d, i, remote.String(), agentIP, sequenceNumber)
	}
}

func (p *Processor) parseSample(d *decoder, index uint32, remoteAddr, agentIP string, datagramSequence uint32) error {
	format, _ := d.u32()
	length, _ := d.u32()
	body, err := d.bytes(pad4(int(length)))
	if err != nil { return err }
	body = body[:int(length)]

	sampleType := format & 0x0FFF
	if (format >> 12) != 0 { return nil }

	switch sampleType {
	case 1: return p.parseFlowSample(body, false, remoteAddr, agentIP, datagramSequence)
	case 3: return p.parseFlowSample(body, true, remoteAddr, agentIP, datagramSequence)
	}
	return nil
}

func (p *Processor) parseFlowSample(body []byte, expanded bool, remoteAddr, agentIP string, datagramSequence uint32) error {
	d := decoder{buf: body}
	seq, _ := d.u32()
	info := flowSampleInfo{SampleSequence: seq, SampleType: "flow_sample"}
	
	if expanded {
		dsClass, _ := d.u32()
		dsIndex, _ := d.u32()
		info.SourceID = fmt.Sprintf("%d/%d", dsClass, dsIndex)
		info.SamplingRate, _ = d.u32()
		info.SamplePool, _ = d.u32()
		info.Drops, _ = d.u32()
		inF, _ := d.u32(); inV, _ := d.u32(); _, _ = d.u32()
		outF, _ := d.u32(); outV, _ := d.u32(); _, _ = d.u32()
		info.Input, info.Output = fmt.Sprintf("%d/%d", inF, inV), fmt.Sprintf("%d/%d", outF, outV)
	} else {
		sourceID, _ := d.u32()
		info.SourceID = formatSourceID(sourceID)
		info.SamplingRate, _ = d.u32()
		info.SamplePool, _ = d.u32()
		info.Drops, _ = d.u32()
		input, _ := d.u32()
		output, _ := d.u32()
		info.Input, info.Output = fmt.Sprintf("%d", input), fmt.Sprintf("%d", output)
	}

	recordCount, _ := d.u32()
	for i := uint32(0); i < recordCount; i++ {
		recFormat, _ := d.u32()
		recLen, _ := d.u32()
		recBody, err := d.bytes(pad4(int(recLen)))
		if err != nil { continue }
		if (recFormat >> 12) == 0 && (recFormat & 0x0FFF) == 1 {
			pkt, ok, _ := p.parseRawPacketHeaderRecord(recBody[:int(recLen)], remoteAddr, agentIP, datagramSequence, info, i+1)
			if ok && (p.isLocal(pkt.DstIP) || p.isLocal(pkt.SrcIP)) {
				p.store.Add(pkt)
			}
		}
	}
	return nil
}

func (p *Processor) isLocal(ipStr string) bool {
	if ipStr == "" { return false }
	ip := net.ParseIP(ipStr)
	if ip == nil { return false }
	for _, network := range p.ownedNets {
		if network.Contains(ip) { return true }
	}
	return false
}

func (p *Processor) parseRawPacketHeaderRecord(body []byte, remoteAddr, agentIP string, datagramSequence uint32, info flowSampleInfo, recordIndex uint32) (packet.Event, bool, error) {
	d := decoder{buf: body}
	hProto, _ := d.u32()
	fLen, _ := d.u32()
	stripped, _ := d.u32()
	hLen, _ := d.u32()
	headerBytes, err := d.bytes(pad4(int(hLen)))
	if err != nil || len(headerBytes) == 0 { return packet.Event{}, false, err }

	pkt := packet.Event{
		Timestamp: time.Now(), AgentIP: agentIP, RemoteAddr: remoteAddr,
		DatagramSequence: datagramSequence, SampleSequence: info.SampleSequence, SampleType: info.SampleType,
		SourceID: info.SourceID, Input: info.Input, Output: info.Output,
		SamplingRate: info.SamplingRate, SamplePool: info.SamplePool, Drops: info.Drops,
		RecordIndex: recordIndex, HeaderProtocol: hProto, FrameLength: fLen, Stripped: stripped, HeaderLength: hLen,
		PayloadHex: formatHexDump(headerBytes[:int(hLen)]),
	}

	decodePacketLayers(headerBytes[:int(hLen)], &pkt)
	p.evaluarPerfilInbound(&pkt)
	pkt.Summary = pkt.SummaryString()
	return pkt, true, nil
}

func (p *Processor) evaluarPerfilInbound(pkt *packet.Event) {
	resultado := p.perfilInbound.Evaluar(pkt, p.cfg)
	pkt.Allowed, pkt.FilterAction, pkt.FilterName = true, "allowed", "global-inbound"
	pkt.FilterReason = "global profile evaluated"

	if !resultado.CoincideDestinoPropio {
		pkt.FilterReason = "destination outside owned cidrs"
		return
	}

	pkt.ProfileActive, pkt.ProfileKey, pkt.DestinationIsLocal = true, pkt.DstIP, true
	pkt.CurrentPPS, pkt.SourcePPS, pkt.BaselinePPS, pkt.SpikePPS = resultado.PPSActual, resultado.SourcePPS, resultado.PPSBase, resultado.PPSThreshold

	if resultado.Alerta {
		pkt.Alert, pkt.AlertName, pkt.AlertReason = true, resultado.NombreAlerta, resultado.RazonAlerta
	}
}

func pad4(n int) int              { return (n + 3) &^ 3 }
func (d *decoder) remaining() int { return len(d.buf) - d.off }
func (d *decoder) u32() (uint32, error) {
	if d.remaining() < 4 { return 0, fmt.Errorf("short") }
	v := binary.BigEndian.Uint32(d.buf[d.off : d.off+4])
	d.off += 4
	return v, nil
}
func (d *decoder) bytes(n int) ([]byte, error) {
	if n < 0 || d.remaining() < n { return nil, fmt.Errorf("short") }
	v := d.buf[d.off : d.off+n]
	d.off += n
	return v, nil
}
func readAgentAddress(d *decoder, ipVersion uint32) (string, error) {
	if ipVersion == 1 {
		b, err := d.bytes(4); if err != nil { return "", err }; return net.IP(b).String(), nil
	}
	b, err := d.bytes(16); if err != nil { return "", err }; return net.IP(b).String(), nil
}
func formatSourceID(v uint32) string { return fmt.Sprintf("%d/%d", v>>24, v&0x00FFFFFF) }

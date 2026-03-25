package sflow

import (
	"dolly-sensor/packet"
	"dolly-sensor/store"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

type Processor struct {
	store         *store.Store
	perfilInbound *PerfilInboundGlobal
	ownedNets     []*net.IPNet
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

func NewProcessor(packetStore *store.Store, perfilInbound *PerfilInboundGlobal, ownedNets []*net.IPNet) *Processor {
	return &Processor{store: packetStore, perfilInbound: perfilInbound, ownedNets: ownedNets}
}

func (p *Processor) ParseDatagram(remote *net.UDPAddr, pkt []byte) {
	d := decoder{buf: pkt}
	version, err := d.u32()
	if err != nil || version != 5 {
		return
	}

	ipVersion, err := d.u32()
	if err != nil {
		return
	}
	agentIP, err := readAgentAddress(&d, ipVersion)
	if err != nil {
		return
	}

	_, err = d.u32()
	if err != nil {
		return
	}
	sequenceNumber, err := d.u32()
	if err != nil {
		return
	}
	_, err = d.u32()
	if err != nil {
		return
	}
	sampleCount, err := d.u32()
	if err != nil {
		return
	}

	for i := uint32(0); i < sampleCount; i++ {
		if err := p.parseSample(&d, i, remote.String(), agentIP, sequenceNumber); err != nil {
			log.Printf("sample %d parse error: %v", i+1, err)
			return
		}
	}
}

func (p *Processor) parseSample(d *decoder, index uint32, remoteAddr, agentIP string, datagramSequence uint32) error {
	format, err := d.u32()
	if err != nil {
		return err
	}
	length, err := d.u32()
	if err != nil {
		return err
	}
	body, err := d.bytes(pad4(int(length)))
	if err != nil {
		return err
	}
	body = body[:int(length)]

	enterprise := format >> 12
	sampleType := format & 0x0FFF
	if enterprise != 0 {
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
		return err
	}

	info := flowSampleInfo{SampleSequence: seq, SampleType: "flow_sample"}
	if expanded {
		info.SampleType = "expanded_flow_sample"
		dsClass, err := d.u32()
		if err != nil {
			return err
		}
		dsIndex, err := d.u32()
		if err != nil {
			return err
		}
		info.SourceID = fmt.Sprintf("%d/%d", dsClass, dsIndex)
		if info.SamplingRate, err = d.u32(); err != nil {
			return err
		}
		if info.SamplePool, err = d.u32(); err != nil {
			return err
		}
		if info.Drops, err = d.u32(); err != nil {
			return err
		}
		inFormat, err := d.u32()
		if err != nil {
			return err
		}
		inValue, err := d.u32()
		if err != nil {
			return err
		}
		outFormat, err := d.u32()
		if err != nil {
			return err
		}
		outValue, err := d.u32()
		if err != nil {
			return err
		}
		info.Input = fmt.Sprintf("%d/%d", inFormat, inValue)
		info.Output = fmt.Sprintf("%d/%d", outFormat, outValue)
	} else {
		sourceID, err := d.u32()
		if err != nil {
			return err
		}
		info.SourceID = formatSourceID(sourceID)
		if info.SamplingRate, err = d.u32(); err != nil {
			return err
		}
		if info.SamplePool, err = d.u32(); err != nil {
			return err
		}
		if info.Drops, err = d.u32(); err != nil {
			return err
		}
		input, err := d.u32()
		if err != nil {
			return err
		}
		output, err := d.u32()
		if err != nil {
			return err
		}
		info.Input = fmt.Sprintf("%d", input)
		info.Output = fmt.Sprintf("%d", output)
	}

	recordCount, err := d.u32()
	if err != nil {
		return err
	}

	for i := uint32(0); i < recordCount; i++ {
		recFormat, err := d.u32()
		if err != nil {
			return err
		}
		recLen, err := d.u32()
		if err != nil {
			return err
		}
		recBody, err := d.bytes(pad4(int(recLen)))
		if err != nil {
			return err
		}
		recBody = recBody[:int(recLen)]

		recEnterprise := recFormat >> 12
		recType := recFormat & 0x0FFF
		if recEnterprise != 0 || recType != 1 {
			continue
		}

		pkt, ok, err := p.parseRawPacketHeaderRecord(recBody, remoteAddr, agentIP, datagramSequence, info, i+1)
		if err != nil || !ok || !p.isInbound(pkt) {
			continue
		}
		if dropped := p.store.Add(pkt); dropped {
			stats := p.store.Stats()
			log.Printf("dropped event reason=store_capacity sampleSeq=%d record=%d capacity=%d", pkt.SampleSequence, pkt.RecordIndex, stats.Capacity)
		}
	}
	return nil
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
		return packet.Event{}, false, err
	}
	frameLength, err := d.u32()
	if err != nil {
		return packet.Event{}, false, err
	}
	stripped, err := d.u32()
	if err != nil {
		return packet.Event{}, false, err
	}
	headerLength, err := d.u32()
	if err != nil {
		return packet.Event{}, false, err
	}
	headerBytes, err := d.bytes(pad4(int(headerLength)))
	if err != nil {
		return packet.Event{}, false, err
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
	p.evaluarPerfilInbound(&pkt)
	pkt.Summary = pkt.SummaryString()
	return pkt, true, nil
}

func (p *Processor) evaluarPerfilInbound(pkt *packet.Event) {
	resultado := p.perfilInbound.Evaluar(pkt.DstIP, pkt.BestProtocol(), pkt.FrameLength)
	pkt.Allowed = true
	pkt.FilterAction = "allowed"
	pkt.FilterName = "global-inbound"
	pkt.FilterReason = "global profile evaluated"

	if !resultado.CoincideDestinoPropio {
		pkt.FilterReason = "destination outside owned cidrs"
		return
	}

	pkt.ProfileActive = true
	pkt.ProfileKey = pkt.DstIP
	pkt.DestinationIsLocal = true
	pkt.CurrentPPS = resultado.PPSActual
	pkt.BaselinePPS = resultado.PPSBase
	pkt.SpikePPS = resultado.PPSThreshold

	if resultado.Alerta {
		pkt.Alert = true
		pkt.AlertName = resultado.NombreAlerta
		pkt.AlertReason = resultado.RazonAlerta
	}
}

func pad4(n int) int              { return (n + 3) &^ 3 }
func (d *decoder) remaining() int { return len(d.buf) - d.off }
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
			return "", err
		}
		return net.IP(b).String(), nil
	case 2:
		b, err := d.bytes(16)
		if err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	default:
		return "", fmt.Errorf("unknown agent address type %d", ipVersion)
	}
}
func formatSourceID(v uint32) string { return fmt.Sprintf("%d/%d", v>>24, v&0x00FFFFFF) }

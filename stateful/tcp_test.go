package stateful

import (
	"dolly-sensor/packet"
	"testing"
)

func TestTCPHandshakeTracking(t *testing.T) {
	tracker := NewTCPTracker()
	isLocal := func(ip string) bool { return ip == "10.0.0.1" }

	src := "1.2.3.4"
	dst := "10.0.0.1"
	sPort := uint16(12345)
	dPort := uint16(80)

	// 1. Enviar SYN
	syn := &packet.Event{SrcIP: src, DstIP: dst, SrcPort: sPort, DstPort: dPort, Transport: "TCP", TCPFlags: "SYN", TCPSeq: 100}
	tracker.Track(syn, isLocal)
	if syn.HandshakeStep != 1 {
		t.Errorf("Esperado HandshakeStep 1, obtenido %d", syn.HandshakeStep)
	}

	// 2. Recibir SYN/ACK (del servidor local al cliente remoto)
	synAck := &packet.Event{SrcIP: dst, DstIP: src, SrcPort: dPort, DstPort: sPort, Transport: "TCP", TCPFlags: "SYN/ACK", TCPSeq: 500}
	tracker.Track(synAck, isLocal)
	if synAck.HandshakeStep != 2 {
		t.Errorf("Esperado HandshakeStep 2, obtenido %d", synAck.HandshakeStep)
	}

	// 3. Enviar ACK final para completar handshake
	ack := &packet.Event{SrcIP: src, DstIP: dst, SrcPort: sPort, DstPort: dPort, Transport: "TCP", TCPFlags: "ACK", TCPSeq: 101, TCPAck: 501}
	tracker.Track(ack, isLocal)
	if ack.HandshakeStep != 3 || !ack.HandshakeComplete {
		t.Errorf("Esperado HandshakeStep 3 y HandshakeComplete true")
	}

	// Verificar que la conexión está activa
	if !tracker.HasConnection(src, sPort, dst, dPort) {
		t.Error("La conexión debería estar en el mapa de conexiones activas")
	}
}

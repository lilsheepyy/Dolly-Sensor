package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

func main() {
	destAddr := "127.0.0.1:6343"
	conn, err := net.Dial("udp", destAddr)
	if err != nil {
		fmt.Printf("Error conectando a %s: %v\n", destAddr, err)
		return
	}
	defer conn.Close()

	// Simulamos un cliente externo
	clientIP := net.ParseIP("142.250.74.74").To4()
	// Nuestra IP protegida (debe estar en owned_cidrs del config.json)
	myIP := net.ParseIP("192.168.1.38").To4()
	
	clientPort := uint16(45678)
	serverPort := uint16(443)

	fmt.Println("🚀 Iniciando simulación de Handshake TCP via sFlow...")
	fmt.Printf("Origen: %s:%d -> Destino: %s:%d\n", "142.250.74.74", clientPort, "192.168.1.38", serverPort)

	// 1. SYN (Handshake Step 1)
	fmt.Println("[1/3] Enviando SYN...")
	conn.Write(buildSFlow(clientIP, myIP, clientPort, serverPort, "SYN", 1000, 0))
	time.Sleep(500 * time.Millisecond)

	// 2. SYN/ACK (Handshake Step 2 - Saliente)
	fmt.Println("[2/3] Enviando SYN/ACK...")
	conn.Write(buildSFlow(myIP, clientIP, serverPort, clientPort, "SYN/ACK", 5000, 1001))
	time.Sleep(500 * time.Millisecond)

	// 3. ACK (Handshake Step 3 - Finalización)
	fmt.Println("[3/3] Enviando ACK...")
	conn.Write(buildSFlow(clientIP, myIP, clientPort, serverPort, "ACK", 1001, 5001))

	fmt.Println("\n✅ Simulación completada. Pasos a seguir:")
	fmt.Println("1. Mira el dashboard en la pestaña 'Connections'.")
	fmt.Println("2. Busca la IP 142.250.74.74 en 'Intelligence' o 'Blocklist'.")
	fmt.Println("3. Debería tener Handshake: DONE y +5 puntos por el handshake.")
}

func buildSFlow(src, dst net.IP, srcP, dstP uint16, flags string, seq, ack uint32) []byte {
	buf := make([]byte, 1500)
	off := 0

	// sFlow Datagram Header
	binary.BigEndian.PutUint32(buf[off:], 5); off += 4 // Version 5
	binary.BigEndian.PutUint32(buf[off:], 1); off += 4 // IP Version (IPv4)
	copy(buf[off:], net.ParseIP("127.0.0.1").To4()); off += 4 // Agent IP
	binary.BigEndian.PutUint32(buf[off:], 0); off += 4 // Sub-agent ID
	binary.BigEndian.PutUint32(buf[off:], 1); off += 4 // Sequence
	binary.BigEndian.PutUint32(buf[off:], 1000); off += 4 // Uptime
	binary.BigEndian.PutUint32(buf[off:], 1); off += 4 // 1 Sample

	// Flow Sample (Enterprise 0, Format 1)
	binary.BigEndian.PutUint32(buf[off:], 1); off += 4
	sampleLenOff := off; off += 4
	startSample := off

	binary.BigEndian.PutUint32(buf[off:], 1); off += 4 // Sample Sequence
	binary.BigEndian.PutUint32(buf[off:], 1); off += 4 // Source ID
	binary.BigEndian.PutUint32(buf[off:], 1); off += 4 // Sampling Rate (1:1)
	binary.BigEndian.PutUint32(buf[off:], 1); off += 4 // Sample Pool
	binary.BigEndian.PutUint32(buf[off:], 0); off += 4 // Drops
	binary.BigEndian.PutUint32(buf[off:], 1); off += 4 // Input Interface
	binary.BigEndian.PutUint32(buf[off:], 2); off += 4 // Output Interface
	binary.BigEndian.PutUint32(buf[off:], 1); off += 4 // 1 Record

	// Raw Packet Header Record (Enterprise 0, Format 1)
	binary.BigEndian.PutUint32(buf[off:], 1); off += 4
	recordLenOff := off; off += 4
	startRecord := off

	binary.BigEndian.PutUint32(buf[off:], 1); off += 4 // Header Protocol (Ethernet)
	binary.BigEndian.PutUint32(buf[off:], 64); off += 4 // Frame Length
	binary.BigEndian.PutUint32(buf[off:], 0); off += 4 // Stripped
	headerLenOff := off; off += 4
	startHeader := off

	// Ethernet Header
	off += 12 // MACs
	binary.BigEndian.PutUint16(buf[off:], 0x0800); off += 2 // EtherType IPv4

	// IPv4 Header
	buf[off] = 0x45; off++ // Version/IHL
	off++ // TOS
	binary.BigEndian.PutUint16(buf[off:], 40); off += 2 // Total Length
	off += 4 // ID/Flags/Offset
	buf[off] = 64; off++ // TTL
	buf[off] = 6; off++ // Protocol TCP
	off += 2 // Checksum
	copy(buf[off:], src); off += 4
	copy(buf[off:], dst); off += 4

	// TCP Header
	binary.BigEndian.PutUint16(buf[off:], srcP); off += 2
	binary.BigEndian.PutUint16(buf[off:], dstP); off += 2
	binary.BigEndian.PutUint32(buf[off:], seq); off += 4
	binary.BigEndian.PutUint32(buf[off:], ack); off += 4
	buf[off] = 0x50; off++ // Offset

	var f byte
	switch flags {
	case "SYN": f = 0x02
	case "SYN/ACK": f = 0x12
	case "ACK": f = 0x10
	case "FIN": f = 0x01
	case "RST": f = 0x04
	default: f = 0x10
	}
	buf[off] = f; off++
	off += 6 // Win, Sum, Urg

	// Padding & Lengths
	headerLen := off - startHeader
	binary.BigEndian.PutUint32(buf[headerLenOff:], uint32(headerLen))
	
	// Pad to 4 bytes
	for off%4 != 0 { buf[off] = 0; off++ }

	binary.BigEndian.PutUint32(buf[recordLenOff:], uint32(off-startRecord))
	binary.BigEndian.PutUint32(buf[sampleLenOff:], uint32(off-startSample))

	return buf[:off]
}

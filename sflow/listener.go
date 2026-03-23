package sflow

import (
	"fmt"
	"log"
	"net"
)

const maxDatagramSize = 65535

func Listen(listenAddr string, processor *Processor) error {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", listenAddr, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
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

		processor.ParseDatagram(remote, append([]byte(nil), buf[:n]...))
	}
}

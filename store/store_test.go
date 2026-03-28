package store

import (
	"dolly-sensor/packet"
	"net"
	"sync"
	"testing"
)

func TestStoreConcurrency(t *testing.T) {
	_, ownedNet, _ := net.ParseCIDR("127.0.0.1/32")
	ownedNets := []*net.IPNet{ownedNet}
	s := New(100000, ownedNets, 128, 300, 60)

	const numGoroutines = 50
	const pktsPerRoutine = 100
	var wg sync.WaitGroup

	victimIP := "127.0.0.1"

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()
			for j := 0; j < pktsPerRoutine; j++ {
				pkt := packet.Event{
					SrcIP: "1.1.1.1",
					DstIP: victimIP,
					SrcPort: uint16(2000 + j),
					DstPort: 80,
					Transport: "TCP",
				}
				s.Add(pkt)
			}
		}(i)
	}

	wg.Wait()

	destStats := s.GetDestStats()
	found := false
	for _, info := range destStats {
		if info.IP == victimIP {
			found = true
			total := uint64(0)
			for _, src := range info.SourceIPs {
				total += src.Count
			}
			if total != uint64(numGoroutines*pktsPerRoutine) {
				t.Errorf("Conteo total incorrecto: esperado %d, obtenido %d", numGoroutines*pktsPerRoutine, total)
			}
		}
	}
	if !found {
		t.Errorf("No se encontró la víctima %s", victimIP)
	}
}

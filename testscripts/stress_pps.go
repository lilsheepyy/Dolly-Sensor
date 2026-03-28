package main

import (
	"dolly-sensor/analyzer"
	"dolly-sensor/config"
	"dolly-sensor/mitigation"
	"dolly-sensor/packet"
	"dolly-sensor/store"
	"fmt"
	"net"
	"sync"
	"time"
)

func runTest(name string, totalPackets int, numWorkers int, cfg config.Config, anz *analyzer.PerfilInboundGlobal, s *store.Store) {
	fmt.Printf("\n--- ESCENARIO: %s (%d paquetes) ---\n", name, totalPackets)
	
	packetsPerWorker := totalPackets / numWorkers
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			// Objeto base para evitar alocaciones en el bucle
			pkt := packet.Event{
				SrcIP:        fmt.Sprintf("192.168.1.%d", workerID),
				DstIP:        "10.0.0.1",
				SrcPort:      uint16(10000 + workerID),
				DstPort:      21, // Puerto FTP para activar filtros
				Transport:    "TCP",
				SamplingRate: 1,
				Timestamp:    time.Now(),
			}

			for j := 0; j < packetsPerWorker; j++ {
				pkt.Timestamp = pkt.Timestamp.Add(time.Microsecond)
				// Ejecutar lógica de filtros + guardado en Store Sharded
				_ = anz.Evaluar(&pkt, cfg)
				s.Add(pkt)
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)
	pps := float64(totalPackets) / duration.Seconds()
	
	fmt.Printf("⏱️  Tiempo: %v\n", duration)
	fmt.Printf("🚀 PPS:     %.2f\n", pps)
	if pps >= 1000000 {
		fmt.Println("✅ RENDIMIENTO EXCELENTE")
	}
}

func main() {
	fmt.Println("🔥 DOLLY-SENSOR HARDWARE BENCHMARK (Ryzen 7 Optimized)")
	
	cfg := config.Default()
	ownedNets := []*net.IPNet{{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(24, 32)}}
	
	// Mock BGP para el test
	bgp := mitigation.NewBGPManager(cfg.BGP)
	bgp.Executor = func(args []string) error { return nil }
	blocklist := mitigation.NewBlocklistEngine()
	
	// 16 Workers (igual al número de hilos del Ryzen 7)
	const numWorkers = 16

	// Escenarios
	levels := []struct {
		name  string
		count int
	}{
		{"CARGA LIGERA", 500_000},
		{"ATAQUE MODERADO", 2_000_000},
		{"OBJETIVO CARRIER (1M PPS)", 5_000_000},
		{"STRESS EXTREMO", 10_000_000},
	}

	for _, level := range levels {
		// Creamos un Store nuevo para cada test para limpiar memoria
		s := store.New(100000, ownedNets, 64, 300, 60)
		anz := analyzer.NuevoPerfilInboundGlobal(ownedNets, blocklist, bgp, cfg, nil)
		runTest(level.name, level.count, numWorkers, cfg, anz, s)
	}
}

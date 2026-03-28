package analyzer

import (
	"dolly-sensor/config"
	"dolly-sensor/mitigation"
	"dolly-sensor/packet"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFullMitigationPipeline(t *testing.T) {
	// 1. Configuración del Entorno
	cfg := config.Default()
	cfg.BGP.Enabled = true
	ownedNets := []*net.IPNet{{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(24, 32)}}
	
	// Mock de BGP para capturar comandos
	var mu sync.Mutex
	capturedCommands := []string{}
	bgp := mitigation.NewBGPManager(cfg.BGP)
	bgp.Executor = func(args []string) error {
		mu.Lock()
		capturedCommands = append(capturedCommands, strings.Join(args, " "))
		mu.Unlock()
		return nil
	}

	blocklist := mitigation.NewBlocklistEngine()
	analyzer := NuevoPerfilInboundGlobal(ownedNets, blocklist, bgp, cfg, nil)

	// 2. Simular Ataque FTP (Flood desde IP atacante)
	attackerIP := "192.168.1.100"
	victimIP := "10.0.0.5"
	
	// Necesitamos que el Z-Score llegue a > 1000. 
	// Si enviamos 1500 unidades por segundo (SamplingRate=1500)
	ahora := time.Now()
	for i := 0; i < 10; i++ {
		pkt := &packet.Event{
			SrcIP: attackerIP,
			DstIP: victimIP,
			SrcPort: 22222, 
			DstPort: 21,
			Transport: "TCP",
			FrameLength: 64,
			SamplingRate: 1500, 
			Timestamp: ahora.Add(time.Duration(i) * 1100 * time.Millisecond),
		}
		
		res := analyzer.Evaluar(pkt, cfg)
		if res.Alerta {
			t.Logf("Alerta disparada en iteración %d: %s", i, res.NombreAlerta)
		}
	}

	// Dar tiempo a la goroutine de BGP
	time.Sleep(100 * time.Millisecond)

	// 3. Verificación
	mu.Lock()
	defer mu.Unlock()
	
	foundFlowspec := false
	for _, cmd := range capturedCommands {
		if strings.Contains(cmd, "ipv4-flowspec") && strings.Contains(cmd, "rate-limit 250") {
			foundFlowspec = true
			break
		}
	}

	if !foundFlowspec {
		t.Errorf("El pipeline no generó el comando Flowspec esperado. Comandos capturados: %v", capturedCommands)
	}
}

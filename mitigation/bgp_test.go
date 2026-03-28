package mitigation

import (
	"dolly-sensor/config"
	"dolly-sensor/packet"
	"sync"
	"testing"
	"time"
)

func TestBGPAutoWithdraw(t *testing.T) {
	cfg := config.BGPConfig{Enabled: true}
	mgr := NewBGPManager(cfg)

	var mu sync.Mutex
	calls := []string{}
	mgr.Executor = func(args []string) error {
		mu.Lock()
		calls = append(calls, args[2]) // "add" o "del"
		mu.Unlock()
		return nil
	}

	m := packet.Mitigation{
		SourceIP: "1.1.1.1",
		Name:     "TEST-RULE",
		Duration: 1, // 1 segundo
	}

	err := mgr.AnnounceFlowspec(m)
	if err != nil {
		t.Fatalf("Error en AnnounceFlowspec: %v", err)
	}

	// Verificar anuncio inmediato
	mu.Lock()
	if len(calls) != 1 || calls[0] != "add" {
		t.Errorf("Se esperaba 1 llamada 'add', obtenidas: %v", calls)
	}
	mu.Unlock()

	// Esperar a la retirada (1.1s para margen)
	time.Sleep(1200 * time.Millisecond)

	mu.Lock()
	if len(calls) != 2 || calls[1] != "del" {
		t.Errorf("Se esperaba 2 llamadas (add + del), obtenidas: %v", calls)
	}
	mu.Unlock()
}

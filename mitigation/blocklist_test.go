package mitigation

import (
	"testing"
)

func TestBlocklist(t *testing.T) {
	e := NewBlocklistEngine()

	// 1. Test Triggered logic
	if !e.MarkTriggered("test-1") {
		t.Error("Debería haber marcado como triggered por primera vez")
	}
	if e.MarkTriggered("test-1") {
		t.Error("No debería permitir marcar dos veces lo mismo")
	}

	e.ClearTriggered("test-1")
	if !e.MarkTriggered("test-1") {
		t.Error("Debería permitir marcar de nuevo tras el Clear")
	}

	// 2. Test IPs (Simulando carga manual)
	e.ips["1.2.3.4"] = struct{}{}
	if !e.IsBlocked("1.2.3.4") {
		t.Error("IP 1.2.3.4 debería estar bloqueada")
	}
	if e.IsBlocked("8.8.8.8") {
		t.Error("IP 8.8.8.8 NO debería estar bloqueada")
	}
}

package filter

import (
	"path/filepath"
	"testing"
)

func TestAlmacenPerfilesInboundGuardaYCarga(t *testing.T) {
	dirTemp := t.TempDir()
	almacen := nuevoAlmacenPerfilesInbound(filepath.Join(dirTemp, "inbound_profiles.json"))

	archivo := archivoPerfilesInbound{
		PerfilesPorIPDestino: []registroPerfilInbound{
			{
				IP:        "192.168.1.20",
				UltimaVez: 1_700_000_002,
				PPS: SnapshotPerfilZScore{
					Media:    100,
					M2:       20,
					Cantidad: 5,
				},
				Mbps: SnapshotPerfilZScore{
					Media:    250,
					M2:       30,
					Cantidad: 5,
				},
				Protocolos: map[string]int{"TCP": 1000, "UDP": 250},
			},
		},
	}

	if err := almacen.guardar(archivo); err != nil {
		t.Fatalf("guardar inbound profiles: %v", err)
	}

	cargado, err := almacen.cargar()
	if err != nil {
		t.Fatalf("cargar inbound profiles: %v", err)
	}
	if cargado == nil || len(cargado.PerfilesPorIPDestino) != 1 {
		t.Fatalf("expected one inbound profile")
	}
	if cargado.PerfilesPorIPDestino[0].Protocolos["TCP"] != 1000 {
		t.Fatalf("expected protocol counters to persist")
	}
}

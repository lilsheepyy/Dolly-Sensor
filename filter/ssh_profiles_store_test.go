package filter

import (
	"path/filepath"
	"testing"
)

func TestAlmacenPerfilesSSHGuardaYCargaPerfilesDestino(t *testing.T) {
	dirTemp := t.TempDir()
	almacen := nuevoAlmacenPerfilesSSH(filepath.Join(dirTemp, "ssh_profiles.json"))

	archivo := archivoPerfilesSSH{
		PerfilesPorIPDestino: []registroPerfilSSH{
			{
				IP:        "192.168.1.10",
				UltimaVez: 1_700_000_001,
				SnapshotEstadistico: SnapshotPerfilZScore{
					Media:    12.5,
					M2:       2.2,
					Cantidad: 10,
				},
			},
		},
	}

	if err := almacen.guardar(archivo); err != nil {
		t.Fatalf("guardar perfiles: %v", err)
	}

	cargado, err := almacen.cargar()
	if err != nil {
		t.Fatalf("cargar perfiles: %v", err)
	}
	if cargado == nil {
		t.Fatalf("expected non nil file")
	}
	if len(cargado.PerfilesPorIPDestino) != 1 {
		t.Fatalf("expected one destination profile")
	}
	if cargado.PerfilesPorIPDestino[0].IP != "192.168.1.10" {
		t.Fatalf("expected destination IP profile to be restored")
	}
}

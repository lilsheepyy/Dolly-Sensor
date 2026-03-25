package filter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type perfilDestinoSSH struct {
	perfil   *PerfilZScore
	lastSeen time.Time
}

type registroPerfilSSH struct {
	IP                  string               `json:"ip"`
	UltimaVez           int64                `json:"ultima_vez"`
	Muestras            int                  `json:"muestras"`
	MediaPPS            float64              `json:"media_pps"`
	DesvioEstandarPPS   float64              `json:"desvio_estandar_pps"`
	SnapshotEstadistico SnapshotPerfilZScore `json:"snapshot_estadistico"`
}

type archivoPerfilesSSH struct {
	Version              int                 `json:"version"`
	GeneradoEn           int64               `json:"generado_en"`
	PerfilesPorIPDestino []registroPerfilSSH `json:"perfiles_por_ip_destino"`
}

type almacenPerfilesSSH struct {
	path string
	mu   sync.Mutex
}

func nuevoAlmacenPerfilesSSH(path string) *almacenPerfilesSSH {
	return &almacenPerfilesSSH{path: path}
}

func (a *almacenPerfilesSSH) cargar() (*archivoPerfilesSSH, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	contenido, err := os.ReadFile(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var archivo archivoPerfilesSSH
	if err := json.Unmarshal(contenido, &archivo); err != nil {
		return nil, err
	}
	return &archivo, nil
}

func (a *almacenPerfilesSSH) guardar(archivo archivoPerfilesSSH) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(a.path), 0o755); err != nil {
		return err
	}

	archivo.Version = 1
	archivo.GeneradoEn = time.Now().Unix()
	bytesJSON, err := json.MarshalIndent(archivo, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := a.path + ".tmp"
	if err := os.WriteFile(tmpPath, bytesJSON, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, a.path)
}

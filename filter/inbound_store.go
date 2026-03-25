package filter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type perfilDestinoInbound struct {
	perfil   *PerfilInbound
	lastSeen time.Time
}

type registroPerfilInbound struct {
	IP         string               `json:"ip"`
	UltimaVez  int64                `json:"ultima_vez"`
	PPS        SnapshotPerfilZScore `json:"pps"`
	Mbps       SnapshotPerfilZScore `json:"mbps"`
	Protocolos map[string]int       `json:"protocolos"`
}

type archivoPerfilesInbound struct {
	Version              int                     `json:"version"`
	GeneradoEn           int64                   `json:"generado_en"`
	PerfilesPorIPDestino []registroPerfilInbound `json:"perfiles_por_ip_destino"`
}

type almacenPerfilesInbound struct {
	path string
	mu   sync.Mutex
}

func nuevoAlmacenPerfilesInbound(path string) *almacenPerfilesInbound {
	return &almacenPerfilesInbound{path: path}
}

func (a *almacenPerfilesInbound) cargar() (*archivoPerfilesInbound, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	contenido, err := os.ReadFile(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var archivo archivoPerfilesInbound
	if err := json.Unmarshal(contenido, &archivo); err != nil {
		return nil, err
	}
	return &archivo, nil
}

func (a *almacenPerfilesInbound) guardar(archivo archivoPerfilesInbound) error {
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

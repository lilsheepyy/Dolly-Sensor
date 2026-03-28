package mitigation

import (
	"bufio"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// BlocklistEngine maneja grandes listas de IPs y CIDRs para bloqueo
type BlocklistEngine struct {
	mu       sync.RWMutex
	ips      map[string]struct{}
	networks []*net.IPNet
	path     string
	
	// Para no disparar BGP repetidamente para la misma IP
	triggered   map[string]bool
	triggeredMu sync.Mutex
}

func NewBlocklistEngine() *BlocklistEngine {
	return &BlocklistEngine{
		ips:       make(map[string]struct{}),
		triggered: make(map[string]bool),
	}
}

// LoadFromPath lee todos los archivos .txt o .list de una carpeta y carga las IPs
func (e *BlocklistEngine) LoadFromPath(path string) error {
	e.mu.Lock()
	e.path = path
	e.mu.Unlock()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0755)
	}

	files, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	newIPs := make(map[string]struct{})
	var newNets []*net.IPNet

	for _, f := range files {
		if f.IsDir() { continue }
		fullPath := filepath.Join(path, f.Name())
		e.parseFile(fullPath, newIPs, &newNets)
	}

	e.mu.Lock()
	e.ips = newIPs
	e.networks = newNets
	e.mu.Unlock()

	log.Printf("[BLOCKLIST] Loaded %d IPs and %d CIDRs from %s", len(newIPs), len(newNets), path)
	return nil
}

func (e *BlocklistEngine) parseFile(path string, ips map[string]struct{}, nets *[]*net.IPNet) {
	file, err := os.Open(path)
	if err != nil {
		log.Printf("[BLOCKLIST] Error opening %s: %v", path, err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "/") {
			_, ipnet, err := net.ParseCIDR(line)
			if err == nil {
				*nets = append(*nets, ipnet)
			}
		} else {
			ip := net.ParseIP(line)
			if ip != nil {
				ips[ip.String()] = struct{}{}
			}
		}
	}
}

// Count retorna el total de entradas cargadas
func (e *BlocklistEngine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.ips) + len(e.networks)
}

// IsBlocked verifica si una IP está en la lista negra
func (e *BlocklistEngine) IsBlocked(ipStr string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if _, ok := e.ips[ipStr]; ok {
		return true
	}

	ip := net.ParseIP(ipStr)
	if ip == nil { return false }
	for _, network := range e.networks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// AddManualBlock añade una IP o CIDR al archivo manual.list y recarga
func (e *BlocklistEngine) AddManualBlock(entry string) error {
	e.mu.RLock()
	basePath := e.path
	e.mu.RUnlock()

	if basePath == "" { basePath = "blocklists/" }
	filePath := filepath.Join(basePath, "manual.list")
	
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil { return err }
	defer f.Close()

	if _, err := f.WriteString(entry + "\n"); err != nil { return err }
	return e.LoadFromPath(basePath)
}

// GetFiles retorna la lista de archivos en la carpeta de blocklists
func (e *BlocklistEngine) GetFiles() []string {
	e.mu.RLock()
	basePath := e.path
	e.mu.RUnlock()

	files, err := os.ReadDir(basePath)
	if err != nil { return nil }

	var out []string
	for _, f := range files {
		if !f.IsDir() && !strings.HasPrefix(f.Name(), ".") {
			out = append(out, f.Name())
		}
	}
	return out
}

// MarkTriggered marca una IP como ya procesada por BGP para evitar spam
func (e *BlocklistEngine) MarkTriggered(ip string) bool {
	e.triggeredMu.Lock()
	defer e.triggeredMu.Unlock()
	if e.triggered[ip] {
		return false
	}
	e.triggered[ip] = true
	return true
}

func (e *BlocklistEngine) ClearTriggered(ip string) {
	e.triggeredMu.Lock()
	defer e.triggeredMu.Unlock()
	delete(e.triggered, ip)
}

package packet

import (
	"dolly-sensor/trustscore"
	"sync"
	"time"
)

type IPProfile struct {
	IP             string    `json:"ip"`
	LastUpdated    time.Time `json:"last_updated"`

	// 1. Entropía y Diversidad
	SourceDiversity float64   `json:"source_diversity_index"` // unique_ips / total_packets
	UniqueSources   int       `json:"unique_sources"`

	// 2. Ratios de Conexión
	SYNAckRatio    float64   `json:"syn_ack_ratio"` // SYNs / (ACKs + 1)
	TCPFlagsCount  map[string]int `json:"tcp_flags_distribution"`

	// 3. Distribución de Tamaños (Histograma)
	SizeDistribution struct {
		Small  int `json:"64_128b"`
		Medium int `json:"129_512b"`
		Large  int `json:"513_1500b"`
	} `json:"packet_size_distribution"`

	// 4. Huellas de TTL
	TopTTLs map[uint8]int `json:"top_ttl_fingerprints"`

	// 5. Baselines (Volumen)
	CurrentPPS float64 `json:"current_pps"`
	CurrentMbps float64 `json:"current_mbps"`

	// Metadata para alertas
	IsAnomalous        bool    `json:"is_anomalous"`
	RiskScore          int     `json:"risk_score"`
	TrustedTrafficRatio float64 `json:"trusted_traffic_ratio"`
}

// PersistentProfile representa el estado a largo plazo de una IP nuestra en data/IP.json
type PersistentProfile struct {
	mu          sync.RWMutex `json:"-"`
	IP          string       `json:"ip"`
	FirstSeen   time.Time    `json:"first_seen"`
	LastUpdated time.Time    `json:"last_updated"`

	StatsHistoricas struct {
		MaxPPS                float64 `json:"max_pps"`
		MaxMbps               float64 `json:"max_mbps"`
		TotalPacketsProcessed uint64  `json:"total_packets_processed"`
		TotalBytesProcessed   uint64  `json:"total_bytes_processed"`
	} `json:"stats_historicas"`

	DistribucionFlagsTotal map[string]uint64 `json:"distribucion_flags_total"`
	ProtocolosFrecuentes   map[string]uint64 `json:"protocolos_frecuentes"`
	DistribucionTTL        map[uint8]uint64  `json:"distribucion_ttl"`

	// Reputación de orígenes específica para esta IP de destino (Migrado a TrustScore)
	ReputacionOrigenes map[string]*trustscore.SourceTrust `json:"reputacion_origenes"`

	PuertosFrecuentes       map[uint16]uint64 `json:"puertos_frecuentes"`
	SourcePortsFrecuentes   map[uint16]uint64 `json:"source_ports_frecuentes"`

	PerfilTrafico struct {
		TTLDominante uint8 `json:"ttl_dominante"`
		MTUPromedio  int   `json:"mtu_promedio"`
	} `json:"perfil_trafico"`
}

func (p *PersistentProfile) Lock() { p.mu.Lock() }
func (p *PersistentProfile) Unlock() { p.mu.Unlock() }
func (p *PersistentProfile) RLock() { p.mu.RLock() }
func (p *PersistentProfile) RUnlock() { p.mu.RUnlock() }

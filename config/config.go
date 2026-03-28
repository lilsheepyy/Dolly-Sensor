package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

const DefaultPath = "config.json"

type Config struct {
	SFlow      SFlowConfig      `json:"sflow"`
	HTTP       HTTPConfig       `json:"http"`
	Store      StoreConfig      `json:"store"`
	Local      LocalConfig      `json:"local"`
	Alert      AlertConfig      `json:"alert"`
	Detection  DetectionConfig  `json:"detection"`
	BGP        BGPConfig        `json:"bgp"`
	Mitigation MitigationConfig `json:"mitigation"`
	Protocols  ProtocolConfig   `json:"protocols_tuning"`
	Trust      TrustConfig      `json:"trust_tuning"`
	Performance PerformanceConfig `json:"performance"`
}

type PerformanceConfig struct {
	Shards            int `json:"shards"`              // Número de particiones (64 por defecto)
	CleanupInterval   int `json:"cleanup_interval"`    // Segundos entre limpiezas de memoria
	StatsTTL          int `json:"stats_ttl"`           // Cuánto tiempo recordar una IP inactiva (segundos)
	ProfilerInterval  int `json:"profiler_interval"`   // Segundos entre snapshots del profiler
}

type ProtocolConfig struct {
	FTP struct {
		MaxPPS        float64 `json:"max_pps"`
		RateLimitPPS  uint32  `json:"ratelimit_pps"`
		BlockDuration int     `json:"block_duration"`
	} `json:"ftp"`
	FTPData struct {
		MaxPPS        float64 `json:"max_pps"`
		RateLimitPPS  uint32  `json:"ratelimit_pps"`
		BlockDuration int     `json:"block_duration"`
	} `json:"ftp_data"`
}

type TrustConfig struct {
	MinScoreForExemption int `json:"min_score_for_exemption"`
}

type BGPConfig struct {
	Enabled   bool   `json:"enabled"`
	LocalAS   uint32 `json:"local_as"`
	PeerIP    string `json:"peer_ip"`
	PeerAS    uint32 `json:"peer_as"`
	Community string `json:"community"` // ej: "65000:666" (RTBH)
	NextHop   string `json:"next_hop"`
}

type MitigationConfig struct {
	BlocklistPath string `json:"blocklist_path"`
	AutoBlock     bool   `json:"auto_block"`
}

type SFlowConfig struct {
	Sampling  int             `json:"sampling"`
	Polling   int             `json:"polling"`
	Collector CollectorConfig `json:"collector"`
}

type CollectorConfig struct {
	IP      string `json:"ip"`
	UDPPort int    `json:"udpport"`
}

type HTTPConfig struct {
	Listen string `json:"listen"`
}

type StoreConfig struct {
	MaxRecentPackets int `json:"max_recent_packets"`
}

type LocalConfig struct {
	OwnedCIDRs []string `json:"owned_cidrs"`
	TrustedIPs []string `json:"trusted_ips"`
}

type AlertConfig struct {
	DiscordWebhookURL string `json:"discord_webhook_url"`
}

type DetectionConfig struct {
	Sensitivity string `json:"sensitivity"` // relaxed, balanced, aggressive, ultra, instant
	NetworkType string `json:"network_type"` // home, office, datacenter
}

func Default() Config {
	return Config{
		SFlow: SFlowConfig{Sampling: 1, Polling: 30, Collector: CollectorConfig{IP: "127.0.0.1", UDPPort: 6343}},
		HTTP:  HTTPConfig{Listen: "127.0.0.1:8080"},
		Store: StoreConfig{MaxRecentPackets: 100000},
		Local: LocalConfig{OwnedCIDRs: []string{"127.0.0.0/8", "192.168.1.0/24"}},
		Alert: AlertConfig{DiscordWebhookURL: ""},
		Detection: DetectionConfig{
			Sensitivity: "balanced",
			NetworkType: "home",
		},
		BGP: BGPConfig{
			Enabled:   false,
			LocalAS:   65000,
			Community: "65000:666",
		},
		Mitigation: MitigationConfig{
			BlocklistPath: "blocklists/",
			AutoBlock:     true,
		},
		Protocols: ProtocolConfig{
			FTP: struct {
				MaxPPS        float64 `json:"max_pps"`
				RateLimitPPS  uint32  `json:"ratelimit_pps"`
				BlockDuration int     `json:"block_duration"`
			}{MaxPPS: 1000, RateLimitPPS: 250, BlockDuration: 60},
			FTPData: struct {
				MaxPPS        float64 `json:"max_pps"`
				RateLimitPPS  uint32  `json:"ratelimit_pps"`
				BlockDuration int     `json:"block_duration"`
			}{MaxPPS: 5000, RateLimitPPS: 1000, BlockDuration: 60},
		},
		Trust: TrustConfig{
			MinScoreForExemption: 60,
		},
		Performance: PerformanceConfig{
			Shards:           64,
			CleanupInterval:  60,
			StatsTTL:         300,
			ProfilerInterval: 30,
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.applyDefaults()
	return cfg, nil
}

func (c Config) CollectorAddr() string {
	return fmt.Sprintf("%s:%d", c.SFlow.Collector.IP, c.SFlow.Collector.UDPPort)
}

func (c *Config) applyDefaults() {
	def := Default()
	if c.SFlow.Sampling <= 0 { c.SFlow.Sampling = def.SFlow.Sampling }
	if c.SFlow.Collector.IP == "" { c.SFlow.Collector.IP = def.SFlow.Collector.IP }
	if c.SFlow.Collector.UDPPort <= 0 { c.SFlow.Collector.UDPPort = def.SFlow.Collector.UDPPort }
	if c.HTTP.Listen == "" { c.HTTP.Listen = def.HTTP.Listen }
	if c.Store.MaxRecentPackets <= 0 { c.Store.MaxRecentPackets = def.Store.MaxRecentPackets }
	if len(c.Local.OwnedCIDRs) == 0 {
		c.Local.OwnedCIDRs = append([]string(nil), def.Local.OwnedCIDRs...)
	}
	if c.Detection.Sensitivity == "" { c.Detection.Sensitivity = "balanced" }
	if c.Detection.NetworkType == "" { c.Detection.NetworkType = "home" }
	
	if c.Protocols.FTP.MaxPPS <= 0 { c.Protocols.FTP.MaxPPS = def.Protocols.FTP.MaxPPS }
	if c.Protocols.FTP.RateLimitPPS == 0 { c.Protocols.FTP.RateLimitPPS = def.Protocols.FTP.RateLimitPPS }
	if c.Protocols.FTP.BlockDuration == 0 { c.Protocols.FTP.BlockDuration = def.Protocols.FTP.BlockDuration }

	if c.Protocols.FTPData.MaxPPS <= 0 { c.Protocols.FTPData.MaxPPS = def.Protocols.FTPData.MaxPPS }
	if c.Protocols.FTPData.RateLimitPPS == 0 { c.Protocols.FTPData.RateLimitPPS = def.Protocols.FTPData.RateLimitPPS }
	if c.Protocols.FTPData.BlockDuration == 0 { c.Protocols.FTPData.BlockDuration = def.Protocols.FTPData.BlockDuration }

	if c.Trust.MinScoreForExemption == 0 { c.Trust.MinScoreForExemption = def.Trust.MinScoreForExemption }

	if c.Performance.Shards <= 0 { c.Performance.Shards = def.Performance.Shards }
	if c.Performance.CleanupInterval <= 0 { c.Performance.CleanupInterval = def.Performance.CleanupInterval }
	if c.Performance.StatsTTL <= 0 { c.Performance.StatsTTL = def.Performance.StatsTTL }
	if c.Performance.ProfilerInterval <= 0 { c.Performance.ProfilerInterval = def.Performance.ProfilerInterval }
}

func (c *Config) Validate() error {
	if c.SFlow.Collector.UDPPort == 0 {
		return fmt.Errorf("sflow collector udp port cannot be 0")
	}
	if len(c.Local.OwnedCIDRs) == 0 {
		return fmt.Errorf("no owned CIDRs defined")
	}
	for _, cidr := range c.Local.OwnedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid CIDR %s: %v", cidr, err)
		}
	}
	if c.HTTP.Listen == "" {
		return fmt.Errorf("HTTP listen address cannot be empty")
	}
	return nil
}

func (c Config) OwnedNetworks() ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(c.Local.OwnedCIDRs))
	for _, cidr := range c.Local.OwnedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse local owned cidr %q: %w", cidr, err)
		}
		out = append(out, network)
	}
	return out, nil
}

package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

const DefaultPath = "config.json"

type Config struct {
	SFlow SFlowConfig `json:"sflow"`
	HTTP  HTTPConfig  `json:"http"`
	Store StoreConfig `json:"store"`
	Local LocalConfig `json:"local"`
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
}

func Default() Config {
	return Config{
		SFlow: SFlowConfig{Sampling: 1, Polling: 30, Collector: CollectorConfig{IP: "127.0.0.1", UDPPort: 6343}},
		HTTP:  HTTPConfig{Listen: "127.0.0.1:8080"},
		Store: StoreConfig{MaxRecentPackets: 4096},
		Local: LocalConfig{OwnedCIDRs: []string{"127.0.0.0/8", "192.168.1.0/24"}},
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
	if c.SFlow.Sampling <= 0 {
		c.SFlow.Sampling = def.SFlow.Sampling
	}
	if c.SFlow.Polling <= 0 {
		c.SFlow.Polling = def.SFlow.Polling
	}
	if c.SFlow.Collector.IP == "" {
		c.SFlow.Collector.IP = def.SFlow.Collector.IP
	}
	if c.SFlow.Collector.UDPPort <= 0 {
		c.SFlow.Collector.UDPPort = def.SFlow.Collector.UDPPort
	}
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = def.HTTP.Listen
	}
	if c.Store.MaxRecentPackets <= 0 {
		c.Store.MaxRecentPackets = def.Store.MaxRecentPackets
	}
	if len(c.Local.OwnedCIDRs) == 0 {
		c.Local.OwnedCIDRs = append([]string(nil), def.Local.OwnedCIDRs...)
	}
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

package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

const DefaultPath = "config.json"

type Config struct {
	SFlow       SFlowConfig       `json:"sflow"`
	HTTP        HTTPConfig        `json:"http"`
	Store       StoreConfig       `json:"store"`
	BGPFlowSpec BGPFlowSpecConfig `json:"bgpflowspec"`
	Local       LocalConfig       `json:"local"`
	Filters     FiltersConfig     `json:"filters"`
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

type BGPFlowSpecConfig struct {
	Enabled       bool     `json:"enabled"`
	Command       string   `json:"command"`
	Args          []string `json:"args"`
	RateLimitArgs []string `json:"rate_limit_args"`
	MaxWorkers    int      `json:"max_workers"`
	QueueSize     int      `json:"queue_size"`
}

type LocalConfig struct {
	OwnedCIDRs []string `json:"owned_cidrs"`
}

type FiltersConfig struct {
	Active []string `json:"active"`
}

func Default() Config {
	return Config{
		SFlow: SFlowConfig{
			Sampling: 1,
			Polling:  30,
			Collector: CollectorConfig{
				IP:      "127.0.0.1",
				UDPPort: 6343,
			},
		},
		HTTP: HTTPConfig{
			Listen: "127.0.0.1:8080",
		},
		Store: StoreConfig{
			MaxRecentPackets: 4096,
		},
		BGPFlowSpec: BGPFlowSpecConfig{
			Enabled:    false,
			Command:    "gobgp",
			MaxWorkers: 8,
			QueueSize:  256,
			Args: []string{
				"global", "rib", "add", "-a", "{{family}}-flowspec",
				"match", "source", "{{source_prefix}}",
				"source-port", "=={{source_port}}",
				"then", "discard",
			},
			RateLimitArgs: []string{
				"global", "rib", "add", "-a", "{{family}}-flowspec",
				"match", "source", "{{source_prefix}}",
				"source-port", "=={{source_port}}",
				"then", "rate-limit", "{{rate_limit_pps}}",
			},
		},
		Local: LocalConfig{
			OwnedCIDRs: []string{
				"127.0.0.0/8",
				"192.168.1.0/24",
			},
		},
		Filters: FiltersConfig{
			Active: []string{"ssh", "dnsamp", "ntpamp", "ftp"},
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
	if c.BGPFlowSpec.Command == "" {
		c.BGPFlowSpec.Command = def.BGPFlowSpec.Command
	}
	if c.BGPFlowSpec.MaxWorkers <= 0 {
		c.BGPFlowSpec.MaxWorkers = def.BGPFlowSpec.MaxWorkers
	}
	if c.BGPFlowSpec.QueueSize <= 0 {
		c.BGPFlowSpec.QueueSize = def.BGPFlowSpec.QueueSize
	}
	if len(c.BGPFlowSpec.Args) == 0 {
		c.BGPFlowSpec.Args = append([]string(nil), def.BGPFlowSpec.Args...)
	}
	if len(c.BGPFlowSpec.RateLimitArgs) == 0 {
		c.BGPFlowSpec.RateLimitArgs = append([]string(nil), def.BGPFlowSpec.RateLimitArgs...)
	}
	if len(c.Local.OwnedCIDRs) == 0 {
		c.Local.OwnedCIDRs = append([]string(nil), def.Local.OwnedCIDRs...)
	}
	if len(c.Filters.Active) == 0 {
		c.Filters.Active = append([]string(nil), def.Filters.Active...)
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

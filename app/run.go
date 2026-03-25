package app

import (
	"dolly-sensor/config"
	"dolly-sensor/dashboard"
	"dolly-sensor/filter"
	"dolly-sensor/flowspec"
	"dolly-sensor/sflow"
	"dolly-sensor/store"
	"fmt"
	"log"
	"net"
)

func Run() error {
	cfg, err := config.Load(config.DefaultPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log.Printf(
		"loaded config sflow sampling=%d polling=%d collector=%s http=%s store.max_recent_packets=%d bgpflowspec.enabled=%t workers=%d queue=%d",
		cfg.SFlow.Sampling,
		cfg.SFlow.Polling,
		cfg.CollectorAddr(),
		cfg.HTTP.Listen,
		cfg.Store.MaxRecentPackets,
		cfg.BGPFlowSpec.Enabled,
		cfg.BGPFlowSpec.MaxWorkers,
		cfg.BGPFlowSpec.QueueSize,
	)
	log.Printf("active filters: %v", cfg.Filters.Active)

	var blocker flowspec.Blocker
	if cfg.BGPFlowSpec.Enabled {
		blocker = flowspec.NewCommandBlocker(
			cfg.BGPFlowSpec.Command,
			cfg.BGPFlowSpec.Args,
			cfg.BGPFlowSpec.RateLimitArgs,
			cfg.BGPFlowSpec.MaxWorkers,
			cfg.BGPFlowSpec.QueueSize,
		)
		log.Printf("bgpflowspec enabled via command %s %v", cfg.BGPFlowSpec.Command, cfg.BGPFlowSpec.Args)
	}

	ownedNets, err := cfg.OwnedNetworks()
	if err != nil {
		return fmt.Errorf("owned networks: %w", err)
	}

	packetStore := store.New(cfg.Store.MaxRecentPackets)
	activeFilters, err := buildFilters(cfg.Filters.Active, blocker, ownedNets)
	if err != nil {
		return err
	}
	processor := sflow.NewProcessor(packetStore, activeFilters, ownedNets)

	go func() {
		if err := dashboard.Run(cfg.HTTP.Listen, "web", packetStore, dashboard.RuntimeConfig{
			CollectorAddr: cfg.CollectorAddr(),
			FrontendAddr:  cfg.HTTP.Listen,
			ActiveFilters: cfg.Filters.Active,
		}); err != nil {
			log.Fatalf("dashboard: %v", err)
		}
	}()

	return sflow.Listen(cfg.CollectorAddr(), processor)
}

func buildFilters(names []string, blocker flowspec.Blocker, ownedNets []*net.IPNet) ([]filter.Evaluator, error) {
	filters := make([]filter.Evaluator, 0, len(names))

	for _, name := range names {
		switch name {
		case "ssh":
			filters = append(filters, filter.NewSSHPort22Inbound(blocker, ownedNets))
		case "dnsamp":
			filters = append(filters, filter.NewDNSAmplificationFilter(blocker))
		case "ntpamp":
			filters = append(filters, filter.NewNTPAmplificationFilter(blocker))
		case "ftp":
			filters = append(filters, filter.NewFTPPort21Inbound(blocker))
		case "inbound":
			filters = append(filters, filter.NewInboundGlobalFilter(ownedNets))
		default:
			return nil, fmt.Errorf("unknown filter %q", name)
		}
	}

	return filters, nil
}

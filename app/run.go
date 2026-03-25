package app

import (
	"dolly-sensor/config"
	"dolly-sensor/dashboard"
	"dolly-sensor/sflow"
	"dolly-sensor/store"
	"fmt"
	"log"
)

func Run() error {
	cfg, err := config.Load(config.DefaultPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ownedNets, err := cfg.OwnedNetworks()
	if err != nil {
		return fmt.Errorf("owned networks: %w", err)
	}

	packetStore := store.New(cfg.Store.MaxRecentPackets)
	perfilInbound := sflow.NuevoPerfilInboundGlobal(ownedNets)
	processor := sflow.NewProcessor(packetStore, perfilInbound, ownedNets)

	runtime := dashboard.RuntimeConfig{
		CollectorAddr:   cfg.CollectorAddr(),
		FrontendAddr:    cfg.HTTP.Listen,
		ObtenerPerfiles: perfilInbound.SnapshotPerfiles,
	}

	go func() {
		if err := dashboard.Run(cfg.HTTP.Listen, "web", packetStore, runtime); err != nil {
			log.Fatalf("dashboard: %v", err)
		}
	}()

	log.Printf(
		"collector=%s http=%s max_recent_packets=%d",
		cfg.CollectorAddr(),
		cfg.HTTP.Listen,
		cfg.Store.MaxRecentPackets,
	)

	return sflow.Listen(cfg.CollectorAddr(), processor)
}

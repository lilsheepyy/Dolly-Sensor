package app

import (
	"dolly-sensor/config"
	"dolly-sensor/dashboard"
	"dolly-sensor/perfilglobal"
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

	redesPropias, err := cfg.OwnedNetworks()
	if err != nil {
		return fmt.Errorf("owned networks: %w", err)
	}

	log.Printf("collector=%s http=%s owned_networks=%d", cfg.CollectorAddr(), cfg.HTTP.Listen, len(redesPropias))

	almacen := store.New(cfg.Store.MaxRecentPackets)
	detector := perfilglobal.NuevoDetector(redesPropias)
	procesador := sflow.NewProcessor(almacen, detector)

	runtime := dashboard.RuntimeConfig{
		CollectorAddr:   cfg.CollectorAddr(),
		FrontendAddr:    cfg.HTTP.Listen,
		ObtenerPerfiles: detector.Perfiles,
	}

	go func() {
		if err := dashboard.Run(cfg.HTTP.Listen, "web", almacen, runtime); err != nil {
			log.Fatalf("dashboard: %v", err)
		}
	}()

	return sflow.Listen(cfg.CollectorAddr(), procesador)
}

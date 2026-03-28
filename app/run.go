package app
import (
	"context"
	"dolly-sensor/analyzer"
	"dolly-sensor/config"
	"dolly-sensor/dashboard"
	"dolly-sensor/mitigation"
	"dolly-sensor/packet"
	"dolly-sensor/profiler"
	"dolly-sensor/sflow"
	"dolly-sensor/store"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func Run() error {
	cfg, err := config.Load("config.json")
	if err != nil {
		log.Printf("[CORE] error loading config.json, using defaults: %v", err)
		cfg = config.Default()
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %v", err)
	}

	ownedNets := parseOwnedNets(cfg.Local.OwnedCIDRs)
	packetStore := store.New(
		cfg.Store.MaxRecentPackets,
		ownedNets,
		cfg.Performance.Shards,
		time.Duration(cfg.Performance.StatsTTL)*time.Second,
		time.Duration(cfg.Performance.CleanupInterval)*time.Second,
	)

	// Cargar mapeos de protocolos
	if err := packet.LoadProtocols("protocols.json"); err != nil {
		log.Printf("[CORE] warning: could not load protocols.json: %v", err)
	}

	// Inicializar Mitigación
	blocklist := mitigation.NewBlocklistEngine()
	if err := blocklist.LoadFromPath(cfg.Mitigation.BlocklistPath); err != nil {
		log.Printf("[CORE] warning: could not load blocklist: %v", err)
	}
	bgp := mitigation.NewBGPManager(cfg.BGP)

	// Iniciar el profiler para snapshots y persistencia
	prof := profiler.NewProfiler(packetStore, cfg, time.Duration(cfg.Performance.ProfilerInterval)*time.Second)
	prof.Start()

	perfilInbound := analyzer.NuevoPerfilInboundGlobal(ownedNets, blocklist, bgp, cfg, prof)
	perfilInbound.HasConn = packetStore.HasActiveConnection
	perfilInbound.ValidateTCP = packetStore.ValidateTCP
	perfilInbound.ValidateTCPFlood = packetStore.ValidateTCPFlood
	processor := sflow.NewProcessor(packetStore, perfilInbound, ownedNets, cfg.SFlow.Sampling, cfg)

	if cfg.Alert.DiscordWebhookURL != "" {
		go startAlertSubscriber(packetStore, cfg.Alert.DiscordWebhookURL)
	}

	dashConfig := dashboard.RuntimeConfig{
		CollectorAddr:   cfg.CollectorAddr(),
		FrontendAddr:    cfg.HTTP.Listen,
		ObtenerPerfiles: perfilInbound.SnapshotPerfiles,
		ObtenerResumen:  perfilInbound.GetGlobalSummary,
		ObtenerDetalleIP: prof.GetProfile,
		SetManualTrust:  prof.SetManualTrust,
		GetAllReputations: prof.GetAllReputations,
		MitigationStatus: func() map[string]interface{} {
			return map[string]interface{}{
				"bgp_enabled":       cfg.BGP.Enabled,
				"blocklist_entries": blocklist.Count(),
				"announcements":     bgp.GetAnnouncements(),
			}
		},
		ReloadBlocklists: func() error {
			return blocklist.LoadFromPath(cfg.Mitigation.BlocklistPath)
		},
		GetBlocklistFiles: func() []string {
			return blocklist.GetFiles()
		},
		AddBlocklistEntry: func(entry string) error {
			return blocklist.AddManualBlock(entry)
		},
	}

	// Servidor Web / Dashboard
	go func() {
		log.Printf("[HTTP] dashboard listening on %s", cfg.HTTP.Listen)
		if err := dashboard.Run(cfg.HTTP.Listen, "web", packetStore, dashConfig); err != nil {
			log.Printf("[HTTP] error: %v", err)
		}
	}()

	log.Printf("[CORE] starting dolly-sensor (sampling=1:%d, max_packets=%d)",
		cfg.SFlow.Sampling, cfg.Store.MaxRecentPackets)

	// Capturar señales de terminación para cierre ordenado
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := sflow.Listen(cfg.CollectorAddr(), processor); err != nil {
			log.Printf("[SFLOW] collector error: %v", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Printf("[CORE] shutting down...")
	return nil
}

func parseOwnedNets(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0)
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[CORE] warning: invalid CIDR %s: %v", cidr, err)
			continue
		}
		nets = append(nets, network)
	}
	return nets
}

func startAlertSubscriber(packetStore *store.Store, webhookURL string) {
	ch := packetStore.Subscribe()
	defer packetStore.Unsubscribe(ch)

	log.Printf("[ALERTS] subscriber started (webhook enabled)")
	for pkt := range ch {
		if pkt.Alert {
			log.Printf("[ALERT] %s on %s: %s", pkt.AlertName, pkt.DstIP, pkt.AlertReason)
			// Aquí se implementaría el envío real al webhook de Discord
		}
	}
}

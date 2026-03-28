package dashboard
import (
	"dolly-sensor/analyzer"
	"dolly-sensor/packet"
	"dolly-sensor/store"
	"dolly-sensor/trustscore"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type RuntimeConfig struct {
	CollectorAddr   string
	FrontendAddr    string
	ObtenerPerfiles func() []analyzer.PerfilGlobalIP
	ObtenerResumen  func() analyzer.GlobalSummary
	ObtenerDetalleIP func(ip string) *packet.PersistentProfile
	SetManualTrust  func(dstIP, srcIP string, trust bool) error
	GetAllReputations func() map[string]*trustscore.SourceTrust
	MitigationStatus func() map[string]interface{}
	ReloadBlocklists func() error
	GetBlocklistFiles func() []string
	AddBlocklistEntry func(entry string) error
}
type statusResponse struct {
	CollectorAddr string `json:"collectorAddr"`
	FrontendAddr  string `json:"frontendAddr"`
}

func Run(listenAddr, staticDir string, packetStore *store.Store, runtime RuntimeConfig) error {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(staticDir)))
	mux.HandleFunc("/api/config", handleConfig(runtime))
	mux.HandleFunc("/api/packets", handlePackets(packetStore))
	mux.HandleFunc("/api/stats", handleStats(packetStore))
	mux.HandleFunc("/api/events", handleEvents(packetStore))
	mux.HandleFunc("/api/profiles", handlePerfiles(runtime))
	mux.HandleFunc("/api/profile-detail", handleProfileDetail(runtime))
	mux.HandleFunc("/api/destinations", handleDestinations(packetStore))
	mux.HandleFunc("/api/connections", handleConnections(packetStore))
	mux.HandleFunc("/api/test-alert", handleTestAlert(packetStore))
	mux.HandleFunc("/api/global-summary", handleGlobalSummary(runtime))
	mux.HandleFunc("/api/alerts", handleAlerts(packetStore))
	mux.HandleFunc("/api/reputation/trust", handleSetTrust(runtime))
	mux.HandleFunc("/api/reputation/all", handleAllReputations(runtime))
	mux.HandleFunc("/api/mitigation/status", handleMitigationStatus(runtime))
	mux.HandleFunc("/api/mitigation/reload", handleReloadBlocklists(runtime))
	mux.HandleFunc("/api/blocklist/files", handleGetBlocklistFiles(runtime))
	mux.HandleFunc("/api/blocklist/add", handleAddBlocklistEntry(runtime))
	return http.ListenAndServe(listenAddr, mux)
}

func handleProfileDetail(runtime RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, "missing ip parameter", http.StatusBadRequest)
			return
		}

		if runtime.ObtenerDetalleIP == nil {
			http.Error(w, "not implemented", http.StatusNotImplemented)
			return
		}

		prof := runtime.ObtenerDetalleIP(ip)
		if prof == nil {
			http.Error(w, "profile not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(prof)
	}
}

func handleConnections(packetStore *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packetStore.GetActiveConnections())
	}
}

func handleTestAlert(packetStore *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		testPkt := packet.Event{
			Timestamp:   time.Now(),
			Alert:       true,
			AlertName:   "MANUAL-TEST-ALERT",
			AlertReason: "This is a manual test to verify Discord Webhook integration.",
			DstIP:       "192.168.1.38",
			SrcIP:       "123.123.123.123",
			SrcPort:     443,
			TCPFlags:    "SYN/ACK",
			CurrentPPS:  9999,
			BaselinePPS: 10,
		}
		
		packetStore.Add(testPkt)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Test alert sent to store"))
	}
}


func handleDestinations(packetStore *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packetStore.GetDestStats())
	}
}

func handleConfig(runtime RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(statusResponse{CollectorAddr: runtime.CollectorAddr, FrontendAddr: runtime.FrontendAddr})
	}
}

func handlePackets(packetStore *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		
		srcIP := r.URL.Query().Get("src_ip")
		dstIP := r.URL.Query().Get("dst_ip")
		
		all := packetStore.Snapshot()
		if srcIP == "" && dstIP == "" {
			_ = json.NewEncoder(w).Encode(all)
			return
		}

		filtered := make([]packet.Event, 0)
		for _, pkt := range all {
			match := true
			if srcIP != "" && pkt.SrcIP != srcIP {
				match = false
			}
			if dstIP != "" && pkt.DstIP != dstIP {
				match = false
			}
			if match {
				filtered = append(filtered, pkt)
			}
		}
		_ = json.NewEncoder(w).Encode(filtered)
	}
}

func handleStats(packetStore *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packetStore.Stats())
	}
}

func handlePerfiles(runtime RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if runtime.ObtenerPerfiles == nil {
			_ = json.NewEncoder(w).Encode([]analyzer.PerfilGlobalIP{})
			return
		}
		_ = json.NewEncoder(w).Encode(runtime.ObtenerPerfiles())
	}
}

func handleEvents(packetStore *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		ch := packetStore.Subscribe()
		defer packetStore.Unsubscribe(ch)

		for {
			select {
			case <-r.Context().Done():
				return
			case pkt := <-ch:
				if err := writeSSE(w, pkt); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
}

func writeSSE(w http.ResponseWriter, pkt packet.Event) error {
	data, err := json.Marshal(pkt)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "data: %s\n\n", data)
	return err
}

func handleAddBlocklistEntry(runtime RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct { Entry string `json:"entry"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if runtime.AddBlocklistEntry == nil {
			http.Error(w, "not implemented", http.StatusNotImplemented)
			return
		}
		if err := runtime.AddBlocklistEntry(req.Entry); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func handleGetBlocklistFiles(runtime RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if runtime.GetBlocklistFiles == nil {
			_ = json.NewEncoder(w).Encode([]string{})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(runtime.GetBlocklistFiles())
	}
}

func handleReloadBlocklists(runtime RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if runtime.ReloadBlocklists == nil {
			http.Error(w, "not implemented", http.StatusNotImplemented)
			return
		}
		if err := runtime.ReloadBlocklists(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func handleMitigationStatus(runtime RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if runtime.MitigationStatus == nil {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(runtime.MitigationStatus())
	}
}

func handleAllReputations(runtime RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if runtime.GetAllReputations == nil {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
			return
		}
		_ = json.NewEncoder(w).Encode(runtime.GetAllReputations())
	}
}

func handleSetTrust(runtime RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			DstIP string `json:"dst_ip"`
			SrcIP string `json:"src_ip"`
			Trust bool   `json:"trust"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		if runtime.SetManualTrust == nil {
			http.Error(w, "manual trust not configured", http.StatusNotImplemented)
			return
		}

		if err := runtime.SetManualTrust(req.DstIP, req.SrcIP, req.Trust); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func handleAlerts(packetStore *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packetStore.GetAlerts())
	}
}

func handleGlobalSummary(runtime RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if runtime.ObtenerResumen == nil {
			_ = json.NewEncoder(w).Encode(analyzer.GlobalSummary{})
			return
		}
		_ = json.NewEncoder(w).Encode(runtime.ObtenerResumen())
	}
}

package dashboard

import (
	"dolly-sensor/filter"
	"dolly-sensor/packet"
	"dolly-sensor/store"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type RuntimeConfig struct {
	CollectorAddr   string
	FrontendAddr    string
	ActiveFilters   []string
	ObtenerPerfiles func() []filter.PerfilGlobalIP
}

type statusResponse struct {
	CollectorAddr string `json:"collectorAddr"`
	FrontendAddr  string `json:"frontendAddr"`
	ActiveFilters string `json:"activeFilters"`
}

func Run(listenAddr, staticDir string, packetStore *store.Store, runtime RuntimeConfig) error {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(staticDir)))
	mux.HandleFunc("/api/config", handleConfig(runtime))
	mux.HandleFunc("/api/packets", handlePackets(packetStore))
	mux.HandleFunc("/api/stats", handleStats(packetStore))
	mux.HandleFunc("/api/events", handleEvents(packetStore))
	mux.HandleFunc("/api/perfiles", handlePerfiles(runtime))

	return http.ListenAndServe(listenAddr, mux)
}

func handleConfig(runtime RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		payload := statusResponse{
			CollectorAddr: runtime.CollectorAddr,
			FrontendAddr:  runtime.FrontendAddr,
			ActiveFilters: strings.Join(runtime.ActiveFilters, ", "),
		}
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func handlePackets(packetStore *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(packetStore.Snapshot()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func handleStats(packetStore *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(packetStore.Stats()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func handlePerfiles(runtime RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if runtime.ObtenerPerfiles == nil {
			http.Error(w, "inbound profiles unavailable", http.StatusNotImplemented)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(runtime.ObtenerPerfiles()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
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

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
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

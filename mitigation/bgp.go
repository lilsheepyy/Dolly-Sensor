package mitigation

import (
	"dolly-sensor/config"
	"dolly-sensor/packet"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type BGPAnnouncement struct {
	ID        string    `json:"id"`
	Prefix    string    `json:"prefix"`
	Type      string    `json:"type"` // "RTBH" o "Flowspec"
	Details   string    `json:"details"`
	Community string    `json:"community"`
	Time      time.Time `json:"time"`
}

// BGPManager maneja la interacción con GoBGP para anunciar bloqueos
type BGPManager struct {
	cfg           config.BGPConfig
	announcements map[string]BGPAnnouncement
	mu            sync.RWMutex
	// Inyectable para tests
	Executor      func(args []string) error
}

func NewBGPManager(cfg config.BGPConfig) *BGPManager {
	m := &BGPManager{
		cfg:           cfg,
		announcements: make(map[string]BGPAnnouncement),
	}
	// Ejecutor por defecto (GoBGP real)
	m.Executor = m.runGoBGP
	return m
}

// AnnounceBlock lanza un comando gobgp para anunciar un RTBH (/32)
func (b *BGPManager) AnnounceBlock(ip string, duration int) error {
	prefix := ip + "/32"

	b.mu.Lock()
	b.announcements[prefix] = BGPAnnouncement{
		ID:        prefix,
		Prefix:    prefix,
		Type:      "RTBH",
		Details:   "Full IP block (RTBH)",
		Community: b.cfg.Community,
		Time:      time.Now(),
	}
	b.mu.Unlock()

	args := []string{"global", "rib", "add", "-a", "ipv4", prefix}
	if b.cfg.Community != "" { args = append(args, "community", b.cfg.Community) }
	if b.cfg.NextHop != "" { args = append(args, "nexthop", b.cfg.NextHop) }

	err := b.Executor(args)
	if err != nil {
		return err
	}

	// Si tiene duración, programar retirada
	if duration > 0 {
		go func() {
			time.Sleep(time.Duration(duration) * time.Second)
			log.Printf("[BGP] Auto-withdrawing RTBH %s after %ds", prefix, duration)
			b.WithdrawBlock(ip)
		}()
	}

	return nil
}

// WithdrawBlock retira un anuncio RTBH
func (b *BGPManager) WithdrawBlock(ip string) error {
	prefix := ip + "/32"
	
	b.mu.Lock()
	delete(b.announcements, prefix)
	b.mu.Unlock()

	args := []string{"global", "rib", "del", "-a", "ipv4", prefix}
	return b.Executor(args)
}

// AnnounceFlowspec lanza un comando gobgp con la receta detallada del filtro
func (b *BGPManager) AnnounceFlowspec(m packet.Mitigation) error {
	if m.SourceIP == "" { return fmt.Errorf("missing source IP for flowspec") }
	
	id := fmt.Sprintf("flow-%s-%s", m.Name, m.SourceIP)
	
	b.mu.Lock()
	b.announcements[id] = BGPAnnouncement{
		ID:        id,
		Prefix:    m.SourceIP,
		Type:      "Flowspec",
		Details:   fmt.Sprintf("%s: %s", m.Name, m.Reason),
		Community: "Flowspec Action",
		Time:      time.Now(),
	}
	b.mu.Unlock()

	// Construir comando GoBGP Flowspec
	args := []string{"global", "rib", "add", "-a", "ipv4-flowspec", "match", "source", m.SourceIP + "/32"}
	
	if m.DestIP != "" {
		args = append(args, "destination", m.DestIP + "/32")
	}
	if m.Protocol != "" {
		args = append(args, "protocol", strings.ToLower(m.Protocol))
	}
	if m.DestPort != 0 {
		args = append(args, "destination-port", strconv.Itoa(int(m.DestPort)))
	}
	if m.SourcePort != 0 {
		args = append(args, "source-port", strconv.Itoa(int(m.SourcePort)))
	}
	if m.PacketLenMin > 0 || m.PacketLenMax > 0 {
		lenMatch := ""
		if m.PacketLenMin > 0 && m.PacketLenMax > 0 {
			lenMatch = fmt.Sprintf(">=%d&<=%d", m.PacketLenMin, m.PacketLenMax)
		} else if m.PacketLenMin > 0 {
			lenMatch = fmt.Sprintf(">=%d", m.PacketLenMin)
		} else {
			lenMatch = fmt.Sprintf("<=%d", m.PacketLenMax)
		}
		args = append(args, "packet-length", lenMatch)
	}

	// Acción técnica
	if m.RateLimit > 0 {
		args = append(args, "then", "rate-limit", strconv.Itoa(int(m.RateLimit)))
	} else {
		args = append(args, "then", "discard")
	}

	if !b.cfg.Enabled {
		log.Printf("[BGP] Simulation: %s", strings.Join(args, " "))
	} else {
		err := b.Executor(args)
		if err != nil {
			return err
		}
	}

	// Si tiene duración, programar la retirada
	if m.Duration > 0 {
		go func() {
			time.Sleep(time.Duration(m.Duration) * time.Second)
			log.Printf("[BGP] Auto-withdrawing rule %s after %ds", id, m.Duration)
			b.WithdrawFlowspec(m)
		}()
	}

	return nil
}

// WithdrawFlowspec retira una regla de Flowspec previamente anunciada
func (b *BGPManager) WithdrawFlowspec(m packet.Mitigation) error {
	id := fmt.Sprintf("flow-%s-%s", m.Name, m.SourceIP)
	
	b.mu.Lock()
	delete(b.announcements, id)
	b.mu.Unlock()

	args := []string{"global", "rib", "del", "-a", "ipv4-flowspec", "match", "source", m.SourceIP + "/32"}
	
	if m.DestIP != "" {
		args = append(args, "destination", m.DestIP + "/32")
	}
	if m.Protocol != "" {
		args = append(args, "protocol", strings.ToLower(m.Protocol))
	}
	if m.DestPort != 0 {
		args = append(args, "destination-port", strconv.Itoa(int(m.DestPort)))
	}

	if !b.cfg.Enabled {
		log.Printf("[BGP] Simulation: (Withdraw) %s", strings.Join(args, " "))
		return nil
	}

	return b.Executor(args)
}

func (b *BGPManager) runGoBGP(args []string) error {
	cmd := exec.Command("gobgp", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gobgp error: %v, output: %s", err, string(output))
	}
	return nil
}

func (b *BGPManager) GetAnnouncements() []BGPAnnouncement {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]BGPAnnouncement, 0, len(b.announcements))
	for _, a := range b.announcements {
		out = append(out, a)
	}
	return out
}

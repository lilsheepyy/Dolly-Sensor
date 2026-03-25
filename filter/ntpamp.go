package filter

import (
	"context"
	"dolly-sensor/flowspec"
	"fmt"
	"net"
	"sync"
	"time"
)

const NTPAmplificationName = "ntp-amplification-guard"

var trustedNTPServers = map[string]struct{}{
	"129.6.15.25":   {},
	"129.6.15.26":   {},
	"129.6.15.27":   {},
	"129.6.15.28":   {},
	"129.6.15.29":   {},
	"129.6.15.30":   {},
	"129.6.15.32":   {},
	"132.163.96.1":  {},
	"132.163.96.2":  {},
	"132.163.96.3":  {},
	"132.163.96.4":  {},
	"132.163.96.5":  {},
	"132.163.96.6":  {},
	"132.163.97.1":  {},
	"132.163.97.2":  {},
	"132.163.97.3":  {},
	"132.163.97.4":  {},
	"132.163.97.5":  {},
	"132.163.97.6":  {},
	"132.163.97.7":  {},
	"216.239.35.0":  {},
	"216.239.35.4":  {},
	"216.239.35.8":  {},
	"216.239.35.12": {},
}

var trustedUbuntuNTPHosts = []string{
	"ntp.ubuntu.com",
	"0.ubuntu.pool.ntp.org",
	"1.ubuntu.pool.ntp.org",
	"2.ubuntu.pool.ntp.org",
	"3.ubuntu.pool.ntp.org",
}

type ntpHostResolver func(ctx context.Context, host string) ([]string, error)

type NTPAmplificationFilter struct {
	blocker         flowspec.Blocker
	resolveHost     ntpHostResolver
	refreshInterval time.Duration

	mu                 sync.RWMutex
	dynamicTrustedIPs  map[string]struct{}
	lastDynamicRefresh time.Time
}

func NewNTPAmplificationFilter(blocker flowspec.Blocker) *NTPAmplificationFilter {
	return newNTPAmplificationFilter(blocker, net.DefaultResolver.LookupHost, 30*time.Minute)
}

func newNTPAmplificationFilter(blocker flowspec.Blocker, resolveHost ntpHostResolver, refreshInterval time.Duration) *NTPAmplificationFilter {
	if resolveHost == nil {
		resolveHost = net.DefaultResolver.LookupHost
	}
	if refreshInterval <= 0 {
		refreshInterval = 30 * time.Minute
	}

	return &NTPAmplificationFilter{
		blocker:           blocker,
		resolveHost:       resolveHost,
		refreshInterval:   refreshInterval,
		dynamicTrustedIPs: map[string]struct{}{},
	}
}

func (f *NTPAmplificationFilter) Evaluate(pkt Packet) Decision {
	decision := Decision{
		Name:    NTPAmplificationName,
		Action:  "allowed",
		Allowed: true,
		Reason:  "source port 123 traffic matched trusted NTP server list",
	}

	if pkt.SrcPort != 123 {
		decision.Reason = fmt.Sprintf("source port %d is outside NTP amplification policy", pkt.SrcPort)
		return decision
	}

	f.refreshDynamicTrustedIPs()

	if _, ok := trustedNTPServers[pkt.SourceIP]; ok {
		return decision
	}
	if f.isDynamicTrustedIP(pkt.SourceIP) {
		decision.Reason = "source port 123 traffic matched trusted Ubuntu NTP server list"
		return decision
	}

	decision.Action = "blocked"
	decision.Allowed = false
	decision.Reason = fmt.Sprintf("untrusted source port 123 sender %s", fallback(pkt.SourceIP, "unknown"))

	if pkt.SourceIP == "" {
		decision.Reason += " (missing source IP for FlowSpec block)"
		return decision
	}

	if f.blocker != nil {
		if err := f.blocker.Block(context.Background(), flowspec.Match{
			SourceIP:          pkt.SourceIP,
			SourcePort:        pkt.SrcPort,
			IncludeSourcePort: true,
		}); err != nil {
			decision.Reason += fmt.Sprintf(" (flowspec error: %v)", err)
		} else {
			decision.Reason += fmt.Sprintf(" (flowspec block requested for %s:%d)", pkt.SourceIP, pkt.SrcPort)
		}
	}

	return decision
}

func (f *NTPAmplificationFilter) isDynamicTrustedIP(ip string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.dynamicTrustedIPs[ip]
	return ok
}

func (f *NTPAmplificationFilter) refreshDynamicTrustedIPs() {
	f.mu.RLock()
	shouldRefresh := time.Since(f.lastDynamicRefresh) >= f.refreshInterval
	f.mu.RUnlock()
	if !shouldRefresh {
		return
	}

	updatedTrustedIPs := map[string]struct{}{}

	for _, host := range trustedUbuntuNTPHosts {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		addresses, err := f.resolveHost(ctx, host)
		cancel()
		if err != nil {
			continue
		}

		for _, address := range addresses {
			updatedTrustedIPs[address] = struct{}{}
		}
	}

	f.mu.Lock()
	if len(updatedTrustedIPs) > 0 {
		f.dynamicTrustedIPs = updatedTrustedIPs
	}
	f.lastDynamicRefresh = time.Now()
	f.mu.Unlock()
}

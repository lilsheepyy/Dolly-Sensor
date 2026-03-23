package filter

import (
	"context"
	"dolly-sensor/flowspec"
	"fmt"
	"net"
	"sync"
	"time"
)

const SSHPort22InboundName = "ssh-port-22-inbound"
const sshRateLimitPPS = 6000
const sshProfileTTL = 15 * time.Minute
const sshCleanupInterval = 5 * time.Minute

type destinationProfile struct {
	profile  *RateProfile
	lastSeen time.Time
}

type sourceThreshold struct {
	profile  *FixedThresholdProfile
	lastSeen time.Time
}

type SSHFilter struct {
	blocker            flowspec.Blocker
	ownedNets          []*net.IPNet
	profilesMu         sync.Mutex
	profilesByIP       map[string]*destinationProfile
	sourceThresholdsMu sync.Mutex
	sourceThresholds   map[string]*sourceThreshold
}

func NewSSHPort22Inbound(blocker flowspec.Blocker, ownedNets []*net.IPNet) *SSHFilter {
	filter := &SSHFilter{
		blocker:          blocker,
		ownedNets:        ownedNets,
		profilesByIP:     make(map[string]*destinationProfile),
		sourceThresholds: make(map[string]*sourceThreshold),
	}
	go filter.cleanupLoop()
	return filter
}

func (f *SSHFilter) Evaluate(pkt Packet) Decision {
	decision := Decision{
		Name:    SSHPort22InboundName,
		Action:  "allowed",
		Allowed: true,
		Reason:  "destination port 22 policy not triggered",
	}

	if pkt.DstPort != 22 {
		return decision
	}

	if f.isOwnedDestination(pkt.DstIP) {
		profile := f.profileForDestination(pkt.DstIP).Observe(time.Now())
		decision.ProfileActive = true
		decision.ProfileKey = pkt.DstIP
		decision.DestinationIsLocal = true
		decision.CurrentPPS = profile.CurrentPPS
		decision.BaselinePPS = profile.BaselinePPS
		decision.SpikePPS = profile.SpikePPS
		if profile.Alert {
			decision.Alert = true
			decision.AlertName = "ssh-ddos-suspected"
			decision.AlertReason = fmt.Sprintf(
				"ssh traffic spike detected on %s current=%.1fpps baseline=%.1fpps threshold=%.1fpps",
				pkt.DstIP,
				profile.CurrentPPS,
				profile.BaselinePPS,
				profile.SpikePPS,
			)
		}
	}

	if pkt.SourceIP != "" {
		currentPPS, exceeded := f.sourceThresholdFor(pkt.SourceIP, pkt.SrcPort).Observe(time.Now())
		if exceeded && f.blocker != nil {
			if err := f.blocker.RateLimit(context.Background(), flowspec.Match{
				SourceIP:          pkt.SourceIP,
				SourcePort:        pkt.SrcPort,
				IncludeSourcePort: true,
			}, sshRateLimitPPS); err != nil {
				decision.Alert = true
				decision.AlertName = "ssh-rate-limit-error"
				decision.AlertReason = fmt.Sprintf("ssh source threshold exceeded at %.1fpps but rate-limit failed: %v", currentPPS, err)
			} else {
				decision.Alert = true
				decision.AlertName = "ssh-rate-limit-applied"
				decision.AlertReason = fmt.Sprintf("ssh source %s:%d exceeded %.0fpps, flowspec rate-limit %dpps requested", pkt.SourceIP, pkt.SrcPort, currentPPS, sshRateLimitPPS)
			}
		}
	}

	decision.Reason = "TCP destination port 22 policy not violated"
	if pkt.Transport == "TCP" {
		return decision
	}

	decision.Action = "blocked"
	decision.Allowed = false
	decision.Reason = fmt.Sprintf("requires TCP on destination port 22, got %s/%d", fallback(pkt.Transport, "unknown"), pkt.DstPort)

	if pkt.SourceIP == "" {
		decision.Reason += " (missing source IP for FlowSpec block)"
		return decision
	}

	if f.blocker != nil {
		if err := f.blocker.Block(context.Background(), flowspec.Match{
			SourceIP: pkt.SourceIP,
		}); err != nil {
			decision.Reason += fmt.Sprintf(" (flowspec error: %v)", err)
		} else {
			decision.Reason += fmt.Sprintf(" (flowspec block requested for %s)", pkt.SourceIP)
		}
	}

	return decision
}

func (f *SSHFilter) isOwnedDestination(dstIP string) bool {
	ip := net.ParseIP(dstIP)
	if ip == nil {
		return false
	}

	for _, network := range f.ownedNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (f *SSHFilter) profileForDestination(dstIP string) *RateProfile {
	f.profilesMu.Lock()
	defer f.profilesMu.Unlock()

	now := time.Now()
	if profile, ok := f.profilesByIP[dstIP]; ok {
		profile.lastSeen = now
		return profile.profile
	}

	profile := &destinationProfile{
		profile:  NewRateProfile(5, 4, 25),
		lastSeen: now,
	}
	f.profilesByIP[dstIP] = profile
	return profile.profile
}

func (f *SSHFilter) sourceThresholdFor(sourceIP string, sourcePort uint16) *FixedThresholdProfile {
	f.sourceThresholdsMu.Lock()
	defer f.sourceThresholdsMu.Unlock()

	now := time.Now()
	key := fmt.Sprintf("%s:%d", sourceIP, sourcePort)
	if profile, ok := f.sourceThresholds[key]; ok {
		profile.lastSeen = now
		return profile.profile
	}

	profile := &sourceThreshold{
		profile:  NewFixedThresholdProfile(sshRateLimitPPS),
		lastSeen: now,
	}
	f.sourceThresholds[key] = profile
	return profile.profile
}

func (f *SSHFilter) cleanupLoop() {
	ticker := time.NewTicker(sshCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-sshProfileTTL)
		f.cleanupProfiles(cutoff)
		f.cleanupSourceThresholds(cutoff)
	}
}

func (f *SSHFilter) cleanupProfiles(cutoff time.Time) {
	f.profilesMu.Lock()
	defer f.profilesMu.Unlock()

	for key, profile := range f.profilesByIP {
		if profile.lastSeen.Before(cutoff) {
			delete(f.profilesByIP, key)
		}
	}
}

func (f *SSHFilter) cleanupSourceThresholds(cutoff time.Time) {
	f.sourceThresholdsMu.Lock()
	defer f.sourceThresholdsMu.Unlock()

	for key, threshold := range f.sourceThresholds {
		if threshold.lastSeen.Before(cutoff) {
			delete(f.sourceThresholds, key)
		}
	}
}

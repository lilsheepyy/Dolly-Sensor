package profiler

import (
	"dolly-sensor/config"
	"dolly-sensor/packet"
	"dolly-sensor/store"
	"dolly-sensor/trustscore"
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Profiler struct {
	store      *store.Store
	cfg        config.Config
	interval   time.Duration
	baseDir    string // profiles/
	dataDir    string // data/

	// Cache de perfiles persistentes en memoria
	muCache    sync.RWMutex
	cache      map[string]*packet.PersistentProfile
}

func NewProfiler(s *store.Store, cfg config.Config, interval time.Duration) *Profiler {
	baseDir := "profiles"
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		log.Printf("[PROFILER] error creating profiles dir: %v", err)
	}
	dataDir := "data"
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Printf("[PROFILER] error creating data dir: %v", err)
	}
	
	p := &Profiler{
		store:    s, 
		cfg:      cfg, 
		interval: interval, 
		baseDir:  baseDir, 
		dataDir:  dataDir,
		cache:    make(map[string]*packet.PersistentProfile),
	}
	p.warmupCache()
	return p
}

func (p *Profiler) warmupCache() {
	entries, err := os.ReadDir(p.dataDir)
	if err != nil { return }
	for _, entry := range entries {
		if entry.IsDir() {
			ip := entry.Name()
			if net.ParseIP(ip) != nil {
				p.loadPersistentProfile(ip)
			}
		}
	}
	log.Printf("[PROFILER] Cache warmed up with %d profiles", len(p.cache))
}

func (p *Profiler) Start() {
	log.Printf("[PROFILER] starting with interval %v", p.interval)
	ticker := time.NewTicker(p.interval)
	saveTicker := time.NewTicker(5 * time.Minute)

	go func() {
		for {
			select {
			case <-ticker.C:
				p.processAllDestinations()
			case <-saveTicker.C:
				p.saveAllToDisk()
			}
		}
	}()
}

func (p *Profiler) saveAllToDisk() {
	p.muCache.RLock()
	ips := make([]string, 0, len(p.cache))
	for ip := range p.cache { ips = append(ips, ip) }
	p.muCache.RUnlock()

	for _, ip := range ips {
		p.muCache.RLock()
		pers := p.cache[ip]
		p.muCache.RUnlock()
		if pers != nil {
			p.savePersistentProfile(pers)
		}
	}
}

func (p *Profiler) processAllDestinations() {
	packets := p.store.Snapshot()
	if len(packets) == 0 {
		return
	}

	byDest := make(map[string][]packet.Event)
	cutoff := time.Now().Add(-p.interval)
	
	for _, pkt := range packets {
		if pkt.Timestamp.After(cutoff) && pkt.DstIP != "" {
			byDest[pkt.DstIP] = append(byDest[pkt.DstIP], pkt)
		}
	}

	for ip, pkts := range byDest {
		pers := p.loadPersistentProfile(ip)
		profile := p.calculateProfile(ip, pkts, pers)
		p.updatePersistentProfile(pers, profile, pkts)
		p.saveProfile(profile)
	}
}

func (p *Profiler) calculateProfile(ip string, pkts []packet.Event, pers *packet.PersistentProfile) packet.IPProfile {
	prof := packet.IPProfile{
		IP:             ip,
		LastUpdated:    time.Now(),
		TCPFlagsCount:  make(map[string]int),
		TopTTLs:        make(map[uint8]int),
	}

	uniqueSources := make(map[string]struct{})
	synCount, ackCount := 0, 0
	var totalBytes uint64
	var trustedPkts int

	manualTrusted := make(map[string]bool)
	for _, tip := range p.cfg.Local.TrustedIPs { manualTrusted[tip] = true }

	pers.Lock()
	defer pers.Unlock()

	for _, pkt := range pkts {
		isManual := manualTrusted[pkt.SrcIP]
		rep, ok := pers.ReputacionOrigenes[pkt.SrcIP]
		if !ok {
			rep = &trustscore.SourceTrust{IP: pkt.SrcIP}
			pers.ReputacionOrigenes[pkt.SrcIP] = rep
		}
		
		// Mapear packet.Event a trustscore.TrustEvent para evitar ciclos
		ev := trustscore.TrustEvent{
			Protocol:           pkt.Protocol,
			BestProtocol:       pkt.BestProtocol(),
			SrcPort:            pkt.SrcPort,
			TCPFlags:           pkt.TCPFlags,
			HandshakeComplete:  pkt.HandshakeComplete,
			InEstablishedSession: pkt.InEstablishedSession,
		}
		trustscore.UpdateTrustScore(rep, ev, isManual)

		if isManual || rep.TrustScore >= 70 {
			trustedPkts++
		}

		if pkt.SrcIP != "" { uniqueSources[pkt.SrcIP] = struct{}{} }

		if pkt.Transport == "TCP" {
			flags := strings.ToUpper(pkt.TCPFlags)
			if strings.Contains(flags, "SYN") { synCount++ }
			if strings.Contains(flags, "ACK") { ackCount++ }
			prof.TCPFlagsCount[flags]++
		}

		size := pkt.IPTotalLen
		if size <= 128 { prof.SizeDistribution.Small++ } else if size <= 512 { prof.SizeDistribution.Medium++ } else { prof.SizeDistribution.Large++ }

		prof.TopTTLs[pkt.TTL]++
		totalBytes += uint64(pkt.IPTotalLen)
		if pkt.CurrentPPS > prof.CurrentPPS { prof.CurrentPPS = pkt.CurrentPPS }
	}

	totalPkts := len(pkts)
	if totalPkts > 0 {
		prof.UniqueSources = len(uniqueSources)
		prof.SourceDiversity = float64(prof.UniqueSources) / float64(totalPkts)
		prof.SYNAckRatio = float64(synCount) / float64(ackCount+1)
		prof.TrustedTrafficRatio = float64(trustedPkts) / float64(totalPkts)
		prof.CurrentMbps = (float64(totalBytes) * 8 / 1000000) / p.interval.Seconds()
	}

	if prof.SYNAckRatio > 10 { prof.RiskScore += 20 }
	if prof.SourceDiversity < 0.05 { prof.RiskScore += 30 }
	if prof.CurrentPPS > 10000 { prof.RiskScore += 10 }

	if prof.TrustedTrafficRatio > 0.8 { prof.RiskScore /= 4; prof.IsAnomalous = false } else if prof.RiskScore > 40 { prof.IsAnomalous = true }

	return prof
}

func (p *Profiler) loadPersistentProfile(ip string) *packet.PersistentProfile {
	p.muCache.RLock()
	if pers, ok := p.cache[ip]; ok {
		p.muCache.RUnlock()
		return pers
	}
	p.muCache.RUnlock()

	p.muCache.Lock()
	defer p.muCache.Unlock()
	if pers, ok := p.cache[ip]; ok { return pers }

	path := filepath.Join(p.dataDir, ip, "ip.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		pers := &packet.PersistentProfile{
			IP:                     ip,
			FirstSeen:              time.Now(),
			LastUpdated:            time.Now(),
			DistribucionFlagsTotal: make(map[string]uint64),
			ProtocolosFrecuentes:   make(map[string]uint64),
			DistribucionTTL:        make(map[uint8]uint64),
			ReputacionOrigenes:     make(map[string]*trustscore.SourceTrust),
			PuertosFrecuentes:      make(map[uint16]uint64),
			SourcePortsFrecuentes:  make(map[uint16]uint64),
		}
		p.cache[ip] = pers
		return pers
	}

	var pers packet.PersistentProfile
	json.Unmarshal(raw, &pers)
	if pers.DistribucionFlagsTotal == nil { pers.DistribucionFlagsTotal = make(map[string]uint64) }
	if pers.ProtocolosFrecuentes == nil { pers.ProtocolosFrecuentes = make(map[string]uint64) }
	if pers.DistribucionTTL == nil { pers.DistribucionTTL = make(map[uint8]uint64) }
	if pers.ReputacionOrigenes == nil { pers.ReputacionOrigenes = make(map[string]*trustscore.SourceTrust) }
	if pers.PuertosFrecuentes == nil { pers.PuertosFrecuentes = make(map[uint16]uint64) }
	if pers.SourcePortsFrecuentes == nil { pers.SourcePortsFrecuentes = make(map[uint16]uint64) }
	p.cache[ip] = &pers
	return &pers
}

func (p *Profiler) updatePersistentProfile(pers *packet.PersistentProfile, prof packet.IPProfile, pkts []packet.Event) {
	pers.Lock()
	defer pers.Unlock()

	pers.LastUpdated = time.Now()
	if prof.CurrentPPS > pers.StatsHistoricas.MaxPPS { pers.StatsHistoricas.MaxPPS = prof.CurrentPPS }
	if prof.CurrentMbps > pers.StatsHistoricas.MaxMbps { pers.StatsHistoricas.MaxMbps = prof.CurrentMbps }

	var intervalBytes uint64
	for _, pkt := range pkts {
		pers.ProtocolosFrecuentes[pkt.Transport]++
		pers.DistribucionTTL[pkt.TTL]++
		
		if pkt.Transport == "TCP" && pkt.TCPFlags != "" {
			pers.DistribucionFlagsTotal[strings.ToUpper(pkt.TCPFlags)]++
		}
		if pkt.DstPort != 0 { pers.PuertosFrecuentes[pkt.DstPort]++ }
		if pkt.SrcPort != 0 { pers.SourcePortsFrecuentes[pkt.SrcPort]++ }
		intervalBytes += uint64(pkt.IPTotalLen)
	}

	pers.StatsHistoricas.TotalPacketsProcessed += uint64(len(pkts))
	pers.StatsHistoricas.TotalBytesProcessed += intervalBytes

	var maxCount int
	for ttl, count := range prof.TopTTLs {
		if count > maxCount {
			maxCount = count
			pers.PerfilTrafico.TTLDominante = ttl
		}
	}
	
	trustscore.ApplyDecay(pers.ReputacionOrigenes)

	now := time.Now()
	for _, conn := range p.store.GetActiveConnections() {
		if conn.DstIP == pers.IP {
			rep, ok := pers.ReputacionOrigenes[conn.SrcIP]
			if !ok {
				rep = &trustscore.SourceTrust{IP: conn.SrcIP, FirstSeen: now, SeenDays: make(map[string]bool)}
				pers.ReputacionOrigenes[conn.SrcIP] = rep
			}

			// Si la conexión está activa, significa que hubo un handshake exitoso.
			// Si aún no hemos marcado el handshake en la reputación, lo hacemos ahora.
			if !rep.HandshakeCompleted {
				rep.HandshakeCompleted = true
				rep.AddScoreEvent(10, "Verified Established Connection")
				rep.LastHandshakeAward = now
			}

			// Premios por persistencia
			duration := now.Sub(conn.StartTime)
			if duration >= 15*time.Minute && (rep.Last15mAward.IsZero() || now.Sub(rep.Last15mAward) >= 15*time.Minute) {
				rep.AddScoreEvent(5, "Active connection (15m)")
				rep.Last15mAward = now
			}
			if duration >= 30*time.Minute && (rep.Last30mAward.IsZero() || now.Sub(rep.Last30mAward) >= 30*time.Minute) {
				rep.AddScoreEvent(10, "Persistent session bonus (30m)")
				rep.Last30mAward = now
			}
		}
	}
}

func (p *Profiler) savePersistentProfile(pers *packet.PersistentProfile) {
	pers.RLock()
	defer pers.RUnlock()
	
	dir := filepath.Join(p.dataDir, pers.IP)
	_ = os.MkdirAll(dir, 0755)
	
	path := filepath.Join(dir, "ip.json")
	data, _ := json.MarshalIndent(pers, "", "  ")
	os.WriteFile(path, data, 0644)
}

func (p *Profiler) SetManualTrust(dstIP, srcIP string, trust bool) error {
	pers := p.loadPersistentProfile(dstIP)
	pers.Lock()
	defer pers.Unlock()

	rep, ok := pers.ReputacionOrigenes[srcIP]
	if !ok {
		rep = &trustscore.SourceTrust{IP: srcIP, FirstSeen: time.Now(), SeenDays: make(map[string]bool)}
		pers.ReputacionOrigenes[srcIP] = rep
	}
	rep.IsManualTrust = trust
	rep.LastSeen = time.Now()
	if trust { rep.TrustScore = 100 } else { rep.UpdateScore() }
	
	go p.savePersistentProfile(pers)
	return nil
}

func (p *Profiler) GetAllReputations() map[string]*trustscore.SourceTrust {
	p.muCache.RLock()
	defer p.muCache.RUnlock()

	allReps := make(map[string]*trustscore.SourceTrust)
	for _, pers := range p.cache {
		pers.RLock()
		for srcIP, rep := range pers.ReputacionOrigenes {
			if existing, ok := allReps[srcIP]; !ok || rep.TrustScore > existing.TrustScore {
				allReps[srcIP] = rep
			}
		}
		pers.RUnlock()
	}
	return allReps
}

func (p *Profiler) GetProfile(ip string) *packet.PersistentProfile {
	return p.loadPersistentProfile(ip)
}

func (p *Profiler) saveProfile(prof packet.IPProfile) {
	filename := filepath.Join(p.baseDir, prof.IP+".json")
	data, _ := json.MarshalIndent(prof, "", "  ")
	os.WriteFile(filename, data, 0644)
}

package store

import (
	"dolly-sensor/packet"
	"dolly-sensor/stateful"
	"hash/fnv"
	"net"
	"sync"
	"time"
)

type shard struct {
	mu    sync.RWMutex
	stats map[string]*DestStats
}

type shardedMap []*shard

func newShardedMap(n int) shardedMap {
	sm := make(shardedMap, n)
	for i := 0; i < n; i++ {
		sm[i] = &shard{stats: make(map[string]*DestStats)}
	}
	return sm
}

func (sm shardedMap) getShard(key string) *shard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return sm[h.Sum32()%uint32(len(sm))]
}

// Store maneja el almacenamiento en memoria de paquetes, alertas y estadísticas
type Store struct {
	mu      sync.RWMutex
	packets []*packet.Event
	alerts  []*packet.Event 
	head    int 
	full    bool
	nextID  int64
	dropped uint64
	clients map[chan packet.Event]struct{}

	ownedNets   []*net.IPNet
	destStats   shardedMap
	numShards   int
	tcpTracker  *stateful.TCPTracker
	statsTTL    time.Duration
}

type Stats struct {
	Buffered int    `json:"buffered"`
	Capacity int    `json:"capacity"`
	Dropped  uint64 `json:"dropped"`
}

type DestStats struct {
	mu          sync.Mutex // Lock para proteger los mapas internos de este destino
	SourceIPs   map[string]*IPStat `json:"source_ips"`
	SourcePorts map[uint16]*IPStat `json:"source_ports"`
	TCPFlags    map[string]uint64  `json:"tcp_flags"`
	LastSeen    time.Time          `json:"last_seen"`
}

type IPStat struct {
	Count    uint64    `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

type DestInfo struct {
	IP          string      `json:"ip"`
	SourceIPs   []IPStatRow `json:"source_ips"`
	SourcePorts []PortStat  `json:"source_ports"`
	TCPFlags    []FlagStat  `json:"tcp_flags"`
	LastSeen    time.Time   `json:"last_seen"`
}

type IPStatRow struct {
	IP    string `json:"ip"`
	Count uint64 `json:"count"`
}

type PortStat struct {
	Port  uint16 `json:"port"`
	Count uint64 `json:"count"`
}

type FlagStat struct {
	Flags string `json:"flags"`
	Count uint64 `json:"count"`
}

func New(capacity int, ownedNets []*net.IPNet, numShards int, statsTTL time.Duration, cleanupInterval time.Duration) *Store {
	s := &Store{
		packets:     make([]*packet.Event, capacity),
		alerts:      make([]*packet.Event, 0, 100),
		clients:     make(map[chan packet.Event]struct{}),
		ownedNets:   ownedNets,
		destStats:   newShardedMap(numShards),
		numShards:   numShards,
		tcpTracker:  stateful.NewTCPTracker(),
		statsTTL:    statsTTL,
	}
	go s.cleanupLoop(cleanupInterval)
	return s
}

func (s *Store) isOwned(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil { return false }
	for _, network := range s.ownedNets {
		if network.Contains(ip) { return true }
	}
	// fmt.Printf("DEBUG: IP %s NOT in %v\n", ipStr, s.ownedNets)
	return false
}

func (s *Store) GetAlerts() []packet.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]packet.Event, len(s.alerts))
	for i, p := range s.alerts {
		out[i] = *p
	}
	return out
}

func (s *Store) Snapshot() []packet.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]packet.Event, 0, len(s.packets))
	
	add := func(p *packet.Event) {
		if p != nil { out = append(out, *p) }
	}

	if !s.full {
		for i := 0; i < s.head; i++ { add(s.packets[i]) }
		return out
	}
	for i := s.head; i < len(s.packets); i++ { add(s.packets[i]) }
	for i := 0; i < s.head; i++ { add(s.packets[i]) }
	return out
}

func (s *Store) Subscribe() chan packet.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := make(chan packet.Event, 1024)
	s.clients[ch] = struct{}{}
	return ch
}

func (s *Store) Unsubscribe(ch chan packet.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, ch)
}

func (s *Store) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		s.Cleanup(s.statsTTL)
	}
}

func (s *Store) Cleanup(ttl time.Duration) {
	now := time.Now()
	for i := 0; i < s.numShards; i++ {
		shard := s.destStats[i]
		shard.mu.Lock()
		for destIP, stats := range shard.stats {
			if now.Sub(stats.LastSeen) > ttl*2 {
				delete(shard.stats, destIP)
				continue
			}
			stats.mu.Lock()
			for srcIP, stat := range stats.SourceIPs {
				if now.Sub(stat.LastSeen) > ttl { delete(stats.SourceIPs, srcIP) }
			}
			for port, stat := range stats.SourcePorts {
				if now.Sub(stat.LastSeen) > ttl { delete(stats.SourcePorts, port) }
			}
			stats.mu.Unlock()
		}
		shard.mu.Unlock()
	}

	s.tcpTracker.Cleanup(ttl)
}

func (s *Store) HasActiveConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16) bool {
	return s.tcpTracker.HasConnection(srcIP, srcPort, dstIP, dstPort)
}

func (s *Store) ValidateTCP(pkt *packet.Event) stateful.SecurityCheck {
	return s.tcpTracker.Validate(pkt)
}

func (s *Store) ValidateTCPFlood(pkt *packet.Event, syn, ack int) stateful.SecurityCheck {
	return s.tcpTracker.ValidateFlood(pkt, syn, ack)
}

func (s *Store) GetActiveConnections() []stateful.ActiveConn {
	return s.tcpTracker.GetActiveConnections()
}

func (s *Store) Add(pkt packet.Event) bool {
	// 1. Asignar ID y Alertas bajo lock global rápido
	s.mu.Lock()
	s.nextID++
	pkt.ID = s.nextID
	
	// Guardar una COPIA en el buffer circular (Heap allocation para evitar problemas de punteros)
	pktPtr := new(packet.Event)
	*pktPtr = pkt

	if pkt.Alert {
		s.alerts = append(s.alerts, pktPtr)
		if len(s.alerts) > 100 { s.alerts = s.alerts[1:] }
	}
	s.packets[s.head] = pktPtr
	s.head++
	if s.head >= len(s.packets) {
		s.head = 0
		s.full = true
	}
	if s.full { s.dropped++ }
	
	numClients := len(s.clients)
	var clients []chan packet.Event
	if numClients > 0 {
		clients = make([]chan packet.Event, 0, numClients)
		for ch := range s.clients { clients = append(clients, ch) }
	}
	s.mu.Unlock()

	// 2. Trackeo de conexiones
	s.tcpTracker.Track(&pkt, s.isOwned)

	// 3. Estadísticas por destino (SHARDED)
	dstIP := pkt.DstIP
	if dstIP != "" && s.isOwned(dstIP) {
		shard := s.destStats.getShard(dstIP)
		
		shard.mu.Lock()
		stats, ok := shard.stats[dstIP]
		if !ok {
			stats = &DestStats{
				SourceIPs:   make(map[string]*IPStat),
				SourcePorts: make(map[uint16]*IPStat),
				TCPFlags:    make(map[string]uint64),
			}
			shard.stats[dstIP] = stats
		}
		shard.mu.Unlock()

		stats.mu.Lock()
		stats.LastSeen = time.Now()
		if pkt.SrcIP != "" {
			ipStat, ok := stats.SourceIPs[pkt.SrcIP]
			if !ok {
				ipStat = &IPStat{}
				stats.SourceIPs[pkt.SrcIP] = ipStat
			}
			ipStat.Count++
			ipStat.LastSeen = stats.LastSeen
		}
		if pkt.SrcPort != 0 {
			pStat, ok := stats.SourcePorts[pkt.SrcPort]
			if !ok {
				pStat = &IPStat{}
				stats.SourcePorts[pkt.SrcPort] = pStat
			}
			pStat.Count++
			pStat.LastSeen = stats.LastSeen
		}
		if pkt.TCPFlags != "" {
			stats.TCPFlags[pkt.TCPFlags]++
		}
		stats.mu.Unlock()
	}

	for _, ch := range clients {
		select {
		case ch <- pkt:
		default:
		}
	}
	return s.full
}

func (s *Store) GetDestStats() []DestInfo {
	var out []DestInfo
	for i := 0; i < s.numShards; i++ {
		shard := s.destStats[i]
		shard.mu.RLock()
		for ip, stats := range shard.stats {
			stats.mu.Lock()
			info := DestInfo{ IP: ip, LastSeen: stats.LastSeen }
			for srcIP, stat := range stats.SourceIPs {
				info.SourceIPs = append(info.SourceIPs, IPStatRow{IP: srcIP, Count: stat.Count})
			}
			for port, stat := range stats.SourcePorts {
				info.SourcePorts = append(info.SourcePorts, PortStat{Port: port, Count: stat.Count})
			}
			for flags, count := range stats.TCPFlags {
				info.TCPFlags = append(info.TCPFlags, FlagStat{Flags: flags, Count: count})
			}
			stats.mu.Unlock()
			out = append(out, info)
		}
		shard.mu.RUnlock()
	}
	return out
}

func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	buffered := s.head
	if s.full { buffered = len(s.packets) }
	return Stats{ Buffered: buffered, Capacity: len(s.packets), Dropped: s.dropped }
}

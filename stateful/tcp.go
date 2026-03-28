package stateful

import (
	"dolly-sensor/packet"
	"fmt"
	"strings"
	"sync"
	"time"
)

type ActiveConn struct {
	SrcIP     string    `json:"src_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstIP     string    `json:"dst_ip"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  string    `json:"protocol"`
	StartTime time.Time `json:"start_time"`
	LastSeen  time.Time `json:"last_seen"`
}

type handshakeState struct {
	ExpectedClientSeq uint32
	ExpectedClientAck uint32
	Timestamp         time.Time
}

type TCPTracker struct {
	muConns     sync.RWMutex
	activeConns map[string]*ActiveConn

	muSyn    sync.Mutex
	synCache map[string]handshakeState
}

func NewTCPTracker() *TCPTracker {
	t := &TCPTracker{
		activeConns: make(map[string]*ActiveConn),
		synCache:    make(map[string]handshakeState),
	}
	go t.synCacheCleaner()
	return t
}

func (t *TCPTracker) synCacheCleaner() {
	ticker := time.NewTicker(1 * time.Second)
	for range ticker.C {
		t.muSyn.Lock()
		now := time.Now()
		for k, state := range t.synCache {
			if now.Sub(state.Timestamp) > 5*time.Second {
				delete(t.synCache, k)
			}
		}
		t.muSyn.Unlock()
	}
}

func (t *TCPTracker) Track(pkt *packet.Event, isLocal func(string) bool) {
	if pkt.Transport != "TCP" {
		return
	}

	flags := strings.ToUpper(pkt.TCPFlags)
	key := fmt.Sprintf("%s:%d->%s:%d", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)

	t.muSyn.Lock()
	if flags == "SYN" {
		if isLocal(pkt.DstIP) {
			pkt.HandshakeStep = 1
			t.synCache[key] = handshakeState{ExpectedClientSeq: pkt.TCPSeq + 1, Timestamp: time.Now()}
		}
	} else if flags == "SYN/ACK" {
		revKey := fmt.Sprintf("%s:%d->%s:%d", pkt.DstIP, pkt.DstPort, pkt.SrcIP, pkt.SrcPort)
		if state, exists := t.synCache[revKey]; exists {
			pkt.HandshakeStep = 2
			state.ExpectedClientAck = pkt.TCPSeq + 1
			state.Timestamp = time.Now()
			t.synCache[revKey] = state
		}
	} else if flags == "ACK" {
		if state, exists := t.synCache[key]; exists {
			if isLocal(pkt.DstIP) && state.ExpectedClientAck > 0 {
				if pkt.TCPSeq == state.ExpectedClientSeq && pkt.TCPAck == state.ExpectedClientAck {
					pkt.HandshakeStep = 3
					pkt.HandshakeComplete = true
				}
			}
			delete(t.synCache, key)
		}
	}
	t.muSyn.Unlock()

	t.muConns.Lock()
	defer t.muConns.Unlock()

	if pkt.HandshakeComplete {
		pkt.InEstablishedSession = true
		t.activeConns[key] = &ActiveConn{
			SrcIP:     pkt.SrcIP,
			SrcPort:   pkt.SrcPort,
			DstIP:     pkt.DstIP,
			DstPort:   pkt.DstPort,
			Protocol:  pkt.Protocol,
			StartTime: time.Now(),
			LastSeen:  time.Now(),
		}
	} else if conn, ok := t.activeConns[key]; ok {
		pkt.InEstablishedSession = true
		conn.LastSeen = time.Now()
		if strings.Contains(flags, "FIN") || strings.Contains(flags, "RST") {
			delete(t.activeConns, key)
		}
	}
}

func (t *TCPTracker) HasConnection(srcIP string, srcPort uint16, dstIP string, dstPort uint16) bool {
	t.muConns.RLock()
	defer t.muConns.RUnlock()
	key := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
	_, exists := t.activeConns[key]
	return exists
}

func (t *TCPTracker) GetActiveConnections() []ActiveConn {
	t.muConns.RLock()
	defer t.muConns.RUnlock()
	out := make([]ActiveConn, 0, len(t.activeConns))
	for _, conn := range t.activeConns {
		out = append(out, *conn)
	}
	return out
}

func (t *TCPTracker) ValidateFlood(pkt *packet.Event, syn, ack int) SecurityCheck {
	if pkt.Transport != "TCP" {
		return SecurityCheck{}
	}
	
	// Si hay muchos SYNs y pocos ACKs de esta IP hacia el destino, es SYN Flood
	if syn > 50 && (ack == 0 || syn/ack > 10) {
		return SecurityCheck{
			Alert:  true,
			Name:   "🛡️ TCP-SYN-FLOOD",
			Reason: fmt.Sprintf("High SYN/ACK ratio (%d/%d) from %s", syn, ack, pkt.SrcIP),
		}
	}
	return SecurityCheck{}
}

func (t *TCPTracker) Cleanup(ttl time.Duration) {
	t.muConns.Lock()
	defer t.muConns.Unlock()
	now := time.Now()
	for key, conn := range t.activeConns {
		if now.Sub(conn.LastSeen) > ttl {
			delete(t.activeConns, key)
		}
	}
}

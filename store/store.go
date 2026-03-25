package store

import (
	"dolly-sensor/packet"
	"sync"
)

type Store struct {
	mu      sync.RWMutex
	packets []packet.Event
	nextID  int64
	dropped uint64
	clients map[chan packet.Event]struct{}
}

type Stats struct {
	Buffered int    `json:"buffered"`
	Capacity int    `json:"capacity"`
	Dropped  uint64 `json:"dropped"`
}

func New(capacity int) *Store {
	return &Store{
		packets: make([]packet.Event, 0, capacity),
		clients: make(map[chan packet.Event]struct{}),
	}
}

func (s *Store) Snapshot() []packet.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]packet.Event, len(s.packets))
	copy(out, s.packets)
	return out
}

func (s *Store) Subscribe() chan packet.Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := make(chan packet.Event, 32)
	s.clients[ch] = struct{}{}
	return ch
}

func (s *Store) Unsubscribe(ch chan packet.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.clients, ch)
}

func (s *Store) Add(pkt packet.Event) bool {
	s.mu.Lock()
	s.nextID++
	pkt.ID = s.nextID

	seDescarto := false
	if len(s.packets) == cap(s.packets) {
		s.dropped++
		seDescarto = true
		copy(s.packets, s.packets[1:])
		s.packets[len(s.packets)-1] = pkt
	} else {
		s.packets = append(s.packets, pkt)
	}

	clients := make([]chan packet.Event, 0, len(s.clients))
	for ch := range s.clients {
		clients = append(clients, ch)
	}
	s.mu.Unlock()

	for _, ch := range clients {
		select {
		case ch <- pkt:
		default:
		}
	}

	return seDescarto
}

func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return Stats{
		Buffered: len(s.packets),
		Capacity: cap(s.packets),
		Dropped:  s.dropped,
	}
}

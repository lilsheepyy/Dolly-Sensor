package trustscore

import (
	"time"
)

type ScoreEvent struct {
	Delta     int       `json:"delta"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

type TrustEvent struct {
	Protocol           string
	BestProtocol       string
	SrcPort            uint16
	TCPFlags           string
	HandshakeComplete  bool
	InEstablishedSession bool
}

type SourceTrust struct {
	IP             string             `json:"ip"`
	FirstSeen      time.Time          `json:"first_seen"`
	LastSeen       time.Time          `json:"last_seen"`
	SeenDays       map[string]bool    `json:"seen_days"`
	Fingerprints   map[string]int     `json:"fingerprints"`
	
	// Contadores históricos
	SYNCount       int                `json:"syn_count"`
	ACKCount       int                `json:"ack_count"`
	PSHCount       int                `json:"psh_count"`
	
	// Estadísticas por protocolo y flags
	Protocols      map[string]uint64  `json:"protocols"`
	TCPFlags       map[string]uint64  `json:"tcp_flags_stats"`

	// Estado del Handshake
	HandshakeCompleted bool           `json:"handshake_completed"`
	LastHandshakeAward time.Time      `json:"last_handshake_award"`
	Last15mAward       time.Time      `json:"last_15m_award"`
	Last30mAward       time.Time      `json:"last_30m_award"`

	// Puntuación de Confianza (0-100)
	TrustScore     int                `json:"trust_score"`
	History        []ScoreEvent       `json:"history"`
	IsManualTrust  bool               `json:"is_manual_trust"`
}

func (s *SourceTrust) AddScoreEvent(delta int, reason string) {
	s.History = append(s.History, ScoreEvent{
		Delta:     delta,
		Reason:    reason,
		Timestamp: time.Now(),
	})
	if len(s.History) > 50 {
		s.History = s.History[1:]
	}
	s.UpdateScore()
}

func (s *SourceTrust) UpdateScore() {
	if s.IsManualTrust {
		s.TrustScore = 100
		return
	}
	score := 0
	for _, ev := range s.History {
		score += ev.Delta
	}
	if score < 0 { score = 0 }
	if score > 100 { score = 100 }
	s.TrustScore = score
}

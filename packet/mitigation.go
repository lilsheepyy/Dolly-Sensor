package packet

// Mitigation representa una decisión de bloqueo o acción técnica tomada por un filtro
type Mitigation struct {
	Alert  bool   `json:"alert"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Block  bool   `json:"block"`
	
	// Receta de Bloqueo (Flowspec Ready)
	SourceIP      string `json:"source_ip"`
	DestIP        string `json:"dest_ip"`
	Protocol      string `json:"protocol"` // "TCP", "UDP", etc
	SourcePort    uint16 `json:"source_port"`
	DestPort      uint16 `json:"dest_port"`
	PacketLenMin  uint16 `json:"packet_len_min"`
	PacketLenMax  uint16 `json:"packet_len_max"`
	
	// Tipo de acción técnica
	Drop          bool   `json:"drop"`
	RateLimit     uint32 `json:"rate_limit"` // PPS si no es drop total
	Duration      int    `json:"duration"`   // Segundos antes de retirar la regla
}

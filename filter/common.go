package filter

type Packet struct {
	SourceIP  string
	SrcPort   uint16
	DstIP     string
	Transport string
	DstPort   uint16
}

type Decision struct {
	Name               string
	Action             string
	Allowed            bool
	Reason             string
	Alert              bool
	AlertName          string
	AlertReason        string
	CurrentPPS         float64
	BaselinePPS        float64
	SpikePPS           float64
	ProfileActive      bool
	ProfileKey         string
	DestinationIsLocal bool
}

type Evaluator interface {
	Evaluate(Packet) Decision
}

func fallback(v, alt string) string {
	if v == "" {
		return alt
	}
	return v
}

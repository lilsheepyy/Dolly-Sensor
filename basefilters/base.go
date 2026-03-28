package basefilters

import (
	"dolly-sensor/config"
	"dolly-sensor/packet"
)

type BaseFilter interface {
	Name() string
	Protocol() string 
	Process(pkt *packet.Event, cfg config.Config) packet.Mitigation
}

var registry = []BaseFilter{}

func Register(f BaseFilter) {
	registry = append(registry, f)
}

func GetAll() []BaseFilter {
	return registry
}

func Evaluate(pkt *packet.Event, cfg config.Config) packet.Mitigation {
	for _, f := range registry {
		if pkt.Protocol == f.Protocol() || f.Protocol() == "*" {
			if m := f.Process(pkt, cfg); m.Alert {
				return m
			}
		}
	}
	return packet.Mitigation{}
}

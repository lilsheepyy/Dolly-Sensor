package packet

import (
	"encoding/json"
	"os"
)

type PortMapping struct {
	Port  uint16   `json:"port,omitempty"`
	Range []uint16 `json:"range,omitempty"`
	Name  string   `json:"name"`
}

type ProtocolMap struct {
	TCP []PortMapping `json:"TCP"`
	UDP []PortMapping `json:"UDP"`
}

var GlobalProtocols ProtocolMap

func LoadProtocols(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &GlobalProtocols)
}

func (pm ProtocolMap) GetName(transport string, port uint16) string {
	var list []PortMapping
	if transport == "TCP" {
		list = pm.TCP
	} else if transport == "UDP" {
		list = pm.UDP
	}

	for _, m := range list {
		if m.Port != 0 && m.Port == port {
			return m.Name
		}
		if len(m.Range) == 2 && port >= m.Range[0] && port <= m.Range[1] {
			return m.Name
		}
	}
	return ""
}

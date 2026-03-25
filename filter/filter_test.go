package filter

import (
	"context"
	"dolly-sensor/flowspec"
	"net"
	"testing"
)

type blockerStub struct {
	blockCalls     []flowspec.Match
	rateLimitCalls []flowspec.Match
}

func (b *blockerStub) Block(_ context.Context, match flowspec.Match) error {
	b.blockCalls = append(b.blockCalls, match)
	return nil
}

func (b *blockerStub) RateLimit(_ context.Context, match flowspec.Match, _ int) error {
	b.rateLimitCalls = append(b.rateLimitCalls, match)
	return nil
}

func TestSSHFilterBlocksNonTCPBySourceIPOnly(t *testing.T) {
	stub := &blockerStub{}
	_, ownedNet, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}

	f := NewSSHPort22Inbound(stub, []*net.IPNet{ownedNet})
	decision := f.Evaluate(Packet{
		SourceIP:  "5.5.5.5",
		SrcPort:   40000,
		DstIP:     "192.168.1.10",
		Transport: "UDP",
		DstPort:   22,
	})

	if decision.Allowed {
		t.Fatalf("expected packet to be blocked")
	}
	if len(stub.blockCalls) != 1 {
		t.Fatalf("expected one block call, got %d", len(stub.blockCalls))
	}
	if stub.blockCalls[0].IncludeSourcePort {
		t.Fatalf("ssh block should not include source port")
	}
}

func TestDNSAmplificationBlocksBySourceIPAndPort(t *testing.T) {
	stub := &blockerStub{}
	f := NewDNSAmplificationFilter(stub)

	decision := f.Evaluate(Packet{
		SourceIP: "5.5.5.5",
		SrcPort:  53,
	})

	if decision.Allowed {
		t.Fatalf("expected packet to be blocked")
	}
	if len(stub.blockCalls) != 1 {
		t.Fatalf("expected one block call, got %d", len(stub.blockCalls))
	}
	if !stub.blockCalls[0].IncludeSourcePort {
		t.Fatalf("dns amplification block should include source port")
	}
	if stub.blockCalls[0].SourcePort != 53 {
		t.Fatalf("expected source port 53, got %d", stub.blockCalls[0].SourcePort)
	}
}

func TestNTPAmplificationBlocksBySourceIPAndPort(t *testing.T) {
	stub := &blockerStub{}
	f := NewNTPAmplificationFilter(stub)

	decision := f.Evaluate(Packet{
		SourceIP: "5.5.5.5",
		SrcPort:  123,
	})

	if decision.Allowed {
		t.Fatalf("expected packet to be blocked")
	}
	if len(stub.blockCalls) != 1 {
		t.Fatalf("expected one block call, got %d", len(stub.blockCalls))
	}
	if !stub.blockCalls[0].IncludeSourcePort {
		t.Fatalf("ntp amplification block should include source port")
	}
	if stub.blockCalls[0].SourcePort != 123 {
		t.Fatalf("expected source port 123, got %d", stub.blockCalls[0].SourcePort)
	}
}

func TestFTPFilterBlocksNonTCPBySourceIPOnly(t *testing.T) {
	stub := &blockerStub{}
	f := NewFTPPort21Inbound(stub)

	decision := f.Evaluate(Packet{
		SourceIP:  "5.5.5.5",
		DstIP:     "192.168.1.10",
		SrcPort:   12345,
		DstPort:   21,
		Transport: "UDP",
	})

	if decision.Allowed {
		t.Fatalf("expected non-tcp ftp traffic to be blocked")
	}
	if len(stub.blockCalls) != 1 {
		t.Fatalf("expected one block call, got %d", len(stub.blockCalls))
	}
	if stub.blockCalls[0].IncludeSourcePort {
		t.Fatalf("ftp block should not include source port")
	}
}

func TestFTPFilterIgnoresSourcePort21Only(t *testing.T) {
	f := NewFTPPort21Inbound(nil)

	decision := f.Evaluate(Packet{
		SourceIP:  "5.5.5.5",
		DstIP:     "192.168.1.10",
		SrcPort:   21,
		DstPort:   45000,
		Transport: "UDP",
	})

	if !decision.Allowed {
		t.Fatalf("expected source-port-only ftp traffic to be ignored")
	}
}

func TestFTPFilterBlocksNonEphemeralSourcePort(t *testing.T) {
	stub := &blockerStub{}
	f := NewFTPPort21Inbound(stub)

	decision := f.Evaluate(Packet{
		SourceIP:  "5.5.5.5",
		DstIP:     "192.168.1.10",
		SrcPort:   1024,
		DstPort:   21,
		Transport: "TCP",
	})

	if decision.Allowed {
		t.Fatalf("expected source port <=1024 to be blocked")
	}
	if len(stub.blockCalls) != 1 {
		t.Fatalf("expected one block call, got %d", len(stub.blockCalls))
	}
}

func TestFTPFilterAllowsTCPOnPort21WithEphemeralSourcePort(t *testing.T) {
	f := NewFTPPort21Inbound(nil)

	decision := f.Evaluate(Packet{
		SourceIP:  "5.5.5.5",
		DstIP:     "192.168.1.10",
		SrcPort:   12345,
		DstPort:   21,
		Transport: "TCP",
	})

	if !decision.Allowed {
		t.Fatalf("expected tcp ftp traffic with source port >1024 to be allowed")
	}
}

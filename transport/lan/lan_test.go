package lan

import (
	"context"
	"net"
	"testing"
)

func TestProbeAddrs_FindsListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	addr := ln.Addr().String()
	found := probeAddrs(context.Background(), []string{addr, "127.0.0.1:1"})
	if len(found) != 1 || found[0] != addr {
		t.Fatalf("expected [%s], got %v", addr, found)
	}
}

func TestProbeAddrs_EmptyOnNoListeners(t *testing.T) {
	found := probeAddrs(context.Background(), []string{"127.0.0.1:1", "127.0.0.1:2"})
	if len(found) != 0 {
		t.Fatalf("expected no results, got %v", found)
	}
}

func TestProbeAddrs_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	found := probeAddrs(ctx, []string{"127.0.0.1:1"})
	if len(found) != 0 {
		t.Fatalf("expected no results after cancel, got %v", found)
	}
}

func TestLocalSubnets_NonEmpty(t *testing.T) {
	localIPs, subnets, err := localSubnets()
	if err != nil {
		t.Fatalf("localSubnets: %v", err)
	}
	// In most environments there's at least one non-loopback interface.
	// If not (e.g. isolated CI), skip rather than fail.
	if len(subnets) == 0 {
		t.Skip("no non-loopback IPv4 interfaces found")
	}
	for _, ip := range localIPs {
		if ip.To4() == nil {
			t.Errorf("localIPs contains non-IPv4: %v", ip)
		}
	}
	for _, s := range subnets {
		if s.To4() == nil || s[3] != 0 {
			t.Errorf("subnet not a /24 base: %v", s)
		}
	}
}

func TestIsLocal(t *testing.T) {
	locals := []net.IP{net.ParseIP("192.168.1.5").To4()}
	if !isLocal(net.ParseIP("192.168.1.5").To4(), locals) {
		t.Error("expected 192.168.1.5 to be local")
	}
	if isLocal(net.ParseIP("192.168.1.6").To4(), locals) {
		t.Error("expected 192.168.1.6 to not be local")
	}
}

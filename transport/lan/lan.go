package lan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Port is the well-known sneakernet LAN discovery port ("snk" in base32).
const Port = 14786

const (
	probeTimeout   = 500 * time.Millisecond
	scanConcurrent = 64
)

// Scan probes all IPs in local /24 subnets for the sneakernet LAN port.
// Returns "host:port" strings for each responding host, excluding self.
func Scan(ctx context.Context) ([]string, error) {
	localIPs, subnets, err := localSubnets()
	if err != nil {
		return nil, err
	}

	var targets []string
	for _, subnet := range subnets {
		for i := 1; i <= 254; i++ {
			ip := net.IP{subnet[0], subnet[1], subnet[2], byte(i)}
			if isLocal(ip, localIPs) {
				continue
			}
			targets = append(targets, fmt.Sprintf("%s:%d", ip, Port))
		}
	}

	return probeAddrs(ctx, targets), ctx.Err()
}

// Discover runs Scan periodically and sends discovered "host:port" addresses
// to the returned channel. Duplicates are suppressed until the next scan interval.
func Discover(ctx context.Context, interval time.Duration) <-chan string {
	out := make(chan string, 16)
	go func() {
		defer close(out)
		scan := func() {
			addrs, err := Scan(ctx)
			if err != nil || ctx.Err() != nil {
				return
			}
			for _, addr := range addrs {
				select {
				case out <- addr:
				case <-ctx.Done():
					return
				}
			}
		}
		scan()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				scan()
			}
		}
	}()
	return out
}

// probeAddrs dials each address concurrently and returns those that accept a connection.
func probeAddrs(ctx context.Context, addrs []string) []string {
	sem := make(chan struct{}, scanConcurrent)
	var mu sync.Mutex
	var found []string
	var wg sync.WaitGroup
	for _, addr := range addrs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(addr string) {
			defer wg.Done()
			defer func() { <-sem }()
			d := net.Dialer{Timeout: probeTimeout}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
				mu.Lock()
				found = append(found, addr)
				mu.Unlock()
			}
		}(addr)
	}
	wg.Wait()
	return found
}

func localSubnets() (localIPs []net.IP, subnets []net.IP, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	seen := make(map[[3]byte]bool)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP.To4()
			case *net.IPAddr:
				ip = v.IP.To4()
			}
			if ip == nil {
				continue
			}
			localIPs = append(localIPs, ip)
			key := [3]byte{ip[0], ip[1], ip[2]}
			if !seen[key] {
				seen[key] = true
				subnets = append(subnets, net.IP{ip[0], ip[1], ip[2], 0})
			}
		}
	}
	return
}

func isLocal(ip net.IP, localIPs []net.IP) bool {
	for _, local := range localIPs {
		if local.Equal(ip) {
			return true
		}
	}
	return false
}

package relay

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
	"github.com/oschwald/geoip2-golang"
)

type regionSpec struct {
	country     string // ISO 3166-1 alpha-2, e.g. "US"
	subdivision string // ISO 3166-2 code after the dash, e.g. "GA"; empty = whole country
}

// GeoIP classifies IP addresses by geographic region using a locally cached
// MaxMind-format MMDB database. It downloads the database at startup and
// refreshes it on a configurable interval.
type GeoIP struct {
	dbPath  string
	url     string
	refresh time.Duration
	regions []regionSpec
	mu      sync.RWMutex
	reader  *geoip2.Reader // nil until first successful load
}

// NewGeoIP constructs a GeoIP classifier. regions is a slice of ISO 3166 codes
// such as "US", "US-GA", or "CA-ON". Call Start to begin downloading and
// periodic refresh.
func NewGeoIP(dbPath, downloadURL string, regions []string, refreshInterval time.Duration) *GeoIP {
	g := &GeoIP{
		dbPath:  dbPath,
		url:     downloadURL,
		refresh: refreshInterval,
	}
	for _, r := range regions {
		r = strings.ToUpper(strings.TrimSpace(r))
		if r == "" {
			continue
		}
		if idx := strings.Index(r, "-"); idx != -1 {
			g.regions = append(g.regions, regionSpec{
				country:     r[:idx],
				subdivision: r[idx+1:],
			})
		} else {
			g.regions = append(g.regions, regionSpec{country: r})
		}
	}
	return g
}

// Start downloads the database if it is missing or stale, loads it, then
// launches a background goroutine that refreshes on the configured interval.
func (g *GeoIP) Start(ctx context.Context) {
	if err := g.ensureFresh(); err != nil {
		log.Printf("geoip: initial download failed: %v", err)
	}
	if err := g.load(); err != nil {
		log.Printf("geoip: load failed: %v", err)
	}

	go func() {
		t := time.NewTicker(g.refresh)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := g.download(); err != nil {
					log.Printf("geoip: refresh download failed: %v", err)
					continue
				}
				if err := g.load(); err != nil {
					log.Printf("geoip: refresh load failed: %v", err)
				}
			}
		}
	}()
}

// Tag classifies a remote address as TagLan, TagRegional, or TagGlobal.
func (g *GeoIP) Tag(addr string) blockstore.Tag {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return blockstore.TagGlobal
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return blockstore.TagLan
	}
	if g.isRegional(ip) {
		return blockstore.TagRegional
	}
	return blockstore.TagGlobal
}

func (g *GeoIP) isRegional(ip net.IP) bool {
	if len(g.regions) == 0 {
		return false
	}
	g.mu.RLock()
	r := g.reader
	g.mu.RUnlock()
	if r == nil {
		return false
	}
	rec, err := r.City(ip)
	if err != nil {
		return false
	}
	country := rec.Country.IsoCode
	var subdiv string
	if len(rec.Subdivisions) > 0 {
		subdiv = rec.Subdivisions[0].IsoCode
	}
	for _, spec := range g.regions {
		if spec.country != country {
			continue
		}
		if spec.subdivision == "" || spec.subdivision == subdiv {
			return true
		}
	}
	return false
}

func (g *GeoIP) ensureFresh() error {
	info, err := os.Stat(g.dbPath)
	if err == nil && time.Since(info.ModTime()) < g.refresh {
		return nil
	}
	return g.download()
}

func (g *GeoIP) download() error {
	log.Printf("geoip: downloading %s", g.url)
	resp, err := http.Get(g.url) //nolint:gosec // URL is operator-configured
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	tmp := g.dbPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, g.dbPath)
}

func (g *GeoIP) load() error {
	r, err := geoip2.Open(g.dbPath)
	if err != nil {
		return err
	}
	g.mu.Lock()
	old := g.reader
	g.reader = r
	g.mu.Unlock()
	if old != nil {
		old.Close()
	}
	log.Printf("geoip: loaded %s", g.dbPath)
	return nil
}

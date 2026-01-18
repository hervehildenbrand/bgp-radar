package detector

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/hervehildenbrand/bgp-radar/pkg/models"
	"github.com/redis/go-redis/v9"
)

// HijackDetector detects BGP origin hijacks by tracking prefix origins.
type HijackDetector struct {
	events chan<- models.BGPEvent
	redis  *redis.Client
	ctx    context.Context

	// Local cache for performance (prefix -> origin ASN)
	cache     sync.Map
	cacheTTL  time.Duration
	cacheTime sync.Map // prefix -> time.Time
}

// NewHijackDetector creates a new hijack detector.
func NewHijackDetector(events chan<- models.BGPEvent, redisClient *redis.Client) *HijackDetector {
	return &HijackDetector{
		events:   events,
		redis:    redisClient,
		ctx:      context.Background(),
		cacheTTL: 5 * time.Minute,
	}
}

// Process checks a BGP update for origin hijacks.
func (d *HijackDetector) Process(update models.BGPUpdate) {
	if !update.Announcement || update.OriginASN == 0 {
		return
	}

	// Skip if this is through a scrubbing center (DDoS mitigation, not hijack)
	if HasScrubbingCenter(update.ASPath) {
		return
	}

	// Get known origin for this prefix
	knownOrigin := d.getKnownOrigin(update.Prefix)
	if knownOrigin == 0 {
		// First time seeing this prefix, store it
		d.setKnownOrigin(update.Prefix, update.OriginASN)
		return
	}

	// Same origin, nothing to report
	if knownOrigin == update.OriginASN {
		return
	}

	// Origin changed - potential hijack!
	// Check if it's a known MOAS (Multiple Origin AS)
	if d.isKnownMOAS(update.Prefix, update.OriginASN) {
		return
	}

	// Determine severity
	severity := models.SeverityMedium
	if IsTier1(knownOrigin) || IsTier1(update.OriginASN) {
		severity = models.SeverityCritical
	} else if prefixLen := getPrefixLength(update.Prefix); prefixLen < 16 {
		severity = models.SeverityHigh
	}

	// Calculate confidence based on evidence
	confidence := 0.7 // Base confidence for origin change
	flags := []string{"origin_change"}
	if severity == models.SeverityCritical {
		confidence = 0.9
		flags = append(flags, "tier1_involved")
	} else if severity == models.SeverityHigh {
		confidence = 0.8
		flags = append(flags, "large_prefix")
	}

	event := models.BGPEvent{
		EventType:      models.EventTypeHijack,
		Severity:       severity,
		EventCategory:  models.CategoryAttack,
		AffectedASN:    knownOrigin,
		AffectedPrefix: update.Prefix,
		DetectedAt:     time.Now(),
		IsActive:       true,
		Details: map[string]interface{}{
			"original_origin": knownOrigin,
			"hijacking_asn":   update.OriginASN,
			"as_path":         update.ASPath,
			"peer_asn":        update.PeerASN,
			"collector":       update.Collector,
			"flags":           flags,
			"confidence":      confidence,
		},
	}

	// Non-blocking send
	select {
	case d.events <- event:
	default:
	}

	// Add to MOAS list (might be legitimate)
	d.addKnownMOAS(update.Prefix, update.OriginASN)
}

func (d *HijackDetector) getKnownOrigin(prefix string) uint32 {
	// Check local cache first
	if val, ok := d.cache.Load(prefix); ok {
		if t, ok := d.cacheTime.Load(prefix); ok {
			if time.Since(t.(time.Time)) < d.cacheTTL {
				return val.(uint32)
			}
		}
	}

	// Check Redis
	if d.redis != nil {
		key := "bgp:prefix:" + prefix + ":origin"
		val, err := d.redis.Get(d.ctx, key).Uint64()
		if err == nil {
			origin := uint32(val)
			d.cache.Store(prefix, origin)
			d.cacheTime.Store(prefix, time.Now())
			return origin
		}
	}

	return 0
}

func (d *HijackDetector) setKnownOrigin(prefix string, origin uint32) {
	// Update local cache
	d.cache.Store(prefix, origin)
	d.cacheTime.Store(prefix, time.Now())

	// Update Redis
	if d.redis != nil {
		key := "bgp:prefix:" + prefix + ":origin"
		if err := d.redis.Set(d.ctx, key, origin, 48*time.Hour).Err(); err != nil {
			log.Printf("Redis set error: %v", err)
		}
	}
}

func (d *HijackDetector) isKnownMOAS(prefix string, origin uint32) bool {
	if d.redis == nil {
		return false
	}

	key := "bgp:prefix:" + prefix + ":origins"
	return d.redis.SIsMember(d.ctx, key, origin).Val()
}

func (d *HijackDetector) addKnownMOAS(prefix string, origin uint32) {
	if d.redis == nil {
		return
	}

	key := "bgp:prefix:" + prefix + ":origins"
	d.redis.SAdd(d.ctx, key, origin)
	d.redis.Expire(d.ctx, key, 48*time.Hour)
}

package detector

import (
	"time"

	"github.com/hervehildenbrand/bgp-radar/pkg/models"
)

// LeakDetector detects BGP route leaks.
// A leak is when a small AS appears to be providing transit between two Tier-1s.
type LeakDetector struct {
	events chan<- models.BGPEvent
}

// NewLeakDetector creates a new leak detector.
func NewLeakDetector(events chan<- models.BGPEvent) *LeakDetector {
	return &LeakDetector{events: events}
}

// Process checks a BGP update for route leak patterns.
func (d *LeakDetector) Process(update models.BGPUpdate) {
	if !update.Announcement || len(update.ASPath) < 3 {
		return // Need at least 3 ASNs for leak pattern
	}

	// Look for pattern: Tier1 -> SmallAS -> Tier1
	// This would mean SmallAS is acting as transit between two Tier-1s
	leakASN, tier1Before, tier1After := d.findLeakPattern(update.ASPath)
	if leakASN == 0 {
		return
	}

	event := models.BGPEvent{
		EventType:      models.EventTypeLeak,
		Severity:       models.SeverityHigh,
		EventCategory:  models.CategoryMisconfiguration,
		AffectedASN:    leakASN,
		AffectedPrefix: update.Prefix,
		DetectedAt:     time.Now(),
		IsActive:       true,
		Details: map[string]interface{}{
			"pattern":          "tier1_transit_leak",
			"leaking_asn":      leakASN,
			"upstream_tier1":   tier1Before,
			"downstream_tier1": tier1After,
			"as_path":          update.ASPath,
			"peer_asn":         update.PeerASN,
			"collector":        update.Collector,
			"confidence":       0.85, // High confidence for Tier-1 transit pattern
		},
	}

	// Non-blocking send
	select {
	case d.events <- event:
	default:
	}
}

// findLeakPattern looks for Tier1 -> SmallAS -> Tier1 pattern.
// Returns (leakASN, tier1Before, tier1After) or (0, 0, 0) if not found.
func (d *LeakDetector) findLeakPattern(asPath []uint32) (uint32, uint32, uint32) {
	// Scan through the path looking for the pattern
	for i := 0; i < len(asPath)-2; i++ {
		asn1 := asPath[i]
		asn2 := asPath[i+1]
		asn3 := asPath[i+2]

		// Check if asn1 and asn3 are Tier-1s and asn2 is not
		if IsTier1(asn1) && IsTier1(asn3) && !IsTier1(asn2) {
			// asn2 is a small AS providing transit between two Tier-1s
			// This is a route leak unless asn2 is a known legitimate transit
			if !IsScrubbing(asn2) { // Not a scrubbing center
				return asn2, asn1, asn3
			}
		}
	}

	return 0, 0, 0
}

package detector

import (
	"time"

	"github.com/hervehildenbrand/bgp-radar/pkg/models"
)

// BlackholeDetector detects blackhole announcements via BGP communities.
type BlackholeDetector struct {
	events chan<- models.BGPEvent
}

// NewBlackholeDetector creates a new blackhole detector.
func NewBlackholeDetector(events chan<- models.BGPEvent) *BlackholeDetector {
	return &BlackholeDetector{events: events}
}

// Process checks a BGP update for blackhole communities.
func (d *BlackholeDetector) Process(update models.BGPUpdate) {
	if !update.Announcement {
		return // Withdrawals don't have communities
	}

	if !HasBlackholeCommunity(update.Communities) {
		return
	}

	// Get blackhole communities found
	blackholeCommunities := GetBlackholeCommunities(update.Communities)
	prefixLen := getPrefixLength(update.Prefix)
	isHostRoute := (prefixLen == 32) || (prefixLen == 128)

	// Calculate confidence based on evidence
	confidence := 0.6 // Base confidence for blackhole community
	if isHostRoute {
		confidence = 0.95 // Host routes are almost always legitimate blackholes
	} else if prefixLen >= 24 {
		confidence = 0.85 // /24 or smaller is typical for blackholing
	}

	// Determine severity based on evidence
	severity := models.SeverityMedium
	if isHostRoute {
		severity = models.SeverityMedium // Host route blackhole is normal DDoS defense
	} else if prefixLen < 16 {
		severity = models.SeverityHigh // Large prefix blackhole is unusual
	}

	// Found a blackhole announcement
	event := models.BGPEvent{
		EventType:      models.EventTypeBlackhole,
		Severity:       severity,
		EventCategory:  models.CategoryDefense,
		AffectedASN:    update.OriginASN,
		AffectedPrefix: update.Prefix,
		DetectedAt:     time.Now(),
		IsActive:       true,
		Details: map[string]interface{}{
			"communities":          update.Communities,
			"blackhole_communities": blackholeCommunities,
			"as_path":              update.ASPath,
			"peer_asn":             update.PeerASN,
			"collector":            update.Collector,
			"signal":               "blackhole_community",
			"is_host_route":        isHostRoute,
			"confidence":           confidence,
		},
	}

	// Non-blocking send
	select {
	case d.events <- event:
	default:
	}
}

func getPrefixLength(prefix string) int {
	for i := len(prefix) - 1; i >= 0; i-- {
		if prefix[i] == '/' {
			length := 0
			for j := i + 1; j < len(prefix); j++ {
				length = length*10 + int(prefix[j]-'0')
			}
			return length
		}
	}
	return 32 // Assume /32 if no slash found
}

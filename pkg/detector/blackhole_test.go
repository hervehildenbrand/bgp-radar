package detector

import (
	"testing"
	"time"

	"github.com/hervehildenbrand/bgp-radar/pkg/models"
)

func TestBlackholeDetector_RFC7999(t *testing.T) {
	events := make(chan models.BGPEvent, 10)
	d := NewBlackholeDetector(events)

	update := models.BGPUpdate{
		Timestamp:    time.Now(),
		PeerASN:      6939,
		Prefix:       "192.0.2.1/32",
		ASPath:       []uint32{6939, 3356, 13335},
		OriginASN:    13335,
		Communities:  []string{"65535:666"}, // RFC7999 blackhole
		Announcement: true,
		Collector:    "rrc00",
	}

	d.Process(update)

	select {
	case event := <-events:
		if event.EventType != models.EventTypeBlackhole {
			t.Errorf("Expected event type %s, got %s", models.EventTypeBlackhole, event.EventType)
		}
		if event.AffectedASN != 13335 {
			t.Errorf("Expected affected ASN 13335, got %d", event.AffectedASN)
		}
		if event.AffectedPrefix != "192.0.2.1/32" {
			t.Errorf("Expected affected prefix 192.0.2.1/32, got %s", event.AffectedPrefix)
		}
		if event.EventCategory != models.CategoryDefense {
			t.Errorf("Expected category %s, got %s", models.CategoryDefense, event.EventCategory)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Expected blackhole event, got none")
	}
}

func TestBlackholeDetector_ProviderCommunity(t *testing.T) {
	events := make(chan models.BGPEvent, 10)
	d := NewBlackholeDetector(events)

	update := models.BGPUpdate{
		Timestamp:    time.Now(),
		PeerASN:      174,
		Prefix:       "203.0.113.0/24",
		ASPath:       []uint32{174, 3356, 12345},
		OriginASN:    12345,
		Communities:  []string{"3356:9999"}, // Level3/Lumen blackhole (non-standard!)
		Announcement: true,
		Collector:    "rrc01",
	}

	d.Process(update)

	select {
	case event := <-events:
		if event.EventType != models.EventTypeBlackhole {
			t.Errorf("Expected event type %s, got %s", models.EventTypeBlackhole, event.EventType)
		}
		// Check details
		if communities, ok := event.Details["blackhole_communities"].([]string); ok {
			if len(communities) != 1 || communities[0] != "3356:9999" {
				t.Errorf("Expected blackhole community 3356:9999, got %v", communities)
			}
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Expected blackhole event, got none")
	}
}

func TestBlackholeDetector_NoBlackhole(t *testing.T) {
	events := make(chan models.BGPEvent, 10)
	d := NewBlackholeDetector(events)

	update := models.BGPUpdate{
		Timestamp:    time.Now(),
		PeerASN:      6939,
		Prefix:       "8.8.8.0/24",
		ASPath:       []uint32{6939, 15169},
		OriginASN:    15169,
		Communities:  []string{"6939:1234"}, // Not a blackhole community
		Announcement: true,
		Collector:    "rrc00",
	}

	d.Process(update)

	select {
	case <-events:
		t.Error("Expected no event for non-blackhole update")
	case <-time.After(50 * time.Millisecond):
		// Expected - no event
	}
}

func TestBlackholeDetector_Withdrawal(t *testing.T) {
	events := make(chan models.BGPEvent, 10)
	d := NewBlackholeDetector(events)

	update := models.BGPUpdate{
		Timestamp:    time.Now(),
		PeerASN:      6939,
		Prefix:       "192.0.2.0/24",
		Announcement: false, // Withdrawal
		Collector:    "rrc00",
	}

	d.Process(update)

	select {
	case <-events:
		t.Error("Expected no event for withdrawal")
	case <-time.After(50 * time.Millisecond):
		// Expected - no event
	}
}

func TestHasBlackholeCommunity(t *testing.T) {
	tests := []struct {
		name        string
		communities []string
		expected    bool
	}{
		{
			name:        "RFC7999 blackhole",
			communities: []string{"65535:666"},
			expected:    true,
		},
		{
			name:        "Level3 blackhole",
			communities: []string{"3356:9999"},
			expected:    true,
		},
		{
			name:        "NTT blackhole",
			communities: []string{"2914:666"},
			expected:    true,
		},
		{
			name:        "Regular community",
			communities: []string{"6939:1234"},
			expected:    false,
		},
		{
			name:        "Mixed with blackhole",
			communities: []string{"6939:1234", "65535:666", "174:100"},
			expected:    true,
		},
		{
			name:        "Empty",
			communities: []string{},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasBlackholeCommunity(tt.communities); got != tt.expected {
				t.Errorf("HasBlackholeCommunity(%v) = %v, want %v", tt.communities, got, tt.expected)
			}
		})
	}
}

func TestIsTier1(t *testing.T) {
	tests := []struct {
		asn      uint32
		expected bool
	}{
		{3356, true},  // Lumen/Level3
		{6939, true},  // Hurricane Electric
		{174, true},   // Cogent
		{13335, false}, // Cloudflare (not Tier1)
		{12345, false}, // Random ASN
	}

	for _, tt := range tests {
		if got := IsTier1(tt.asn); got != tt.expected {
			t.Errorf("IsTier1(%d) = %v, want %v", tt.asn, got, tt.expected)
		}
	}
}

func TestIsScrubbing(t *testing.T) {
	tests := []struct {
		asn      uint32
		expected bool
	}{
		{13335, true},  // Cloudflare
		{20940, true},  // Akamai
		{32787, true},  // Akamai Prolexic
		{3356, false},  // Lumen (transit, not scrubbing)
		{12345, false}, // Random ASN
	}

	for _, tt := range tests {
		if got := IsScrubbing(tt.asn); got != tt.expected {
			t.Errorf("IsScrubbing(%d) = %v, want %v", tt.asn, got, tt.expected)
		}
	}
}

func TestGetBlackholeCommunities(t *testing.T) {
	communities := []string{"65535:666", "3356:1234", "3356:9999", "174:100"}
	result := GetBlackholeCommunities(communities)

	if len(result) != 2 {
		t.Fatalf("Expected 2 blackhole communities, got %d", len(result))
	}

	expected := map[string]bool{"65535:666": true, "3356:9999": true}
	for _, c := range result {
		if !expected[c] {
			t.Errorf("Unexpected blackhole community: %s", c)
		}
	}
}

package rislive

import (
	"encoding/json"
	"testing"
)

func TestParseMessage_Announcement(t *testing.T) {
	// Real RIS Live message format
	msg := []byte(`{
		"type": "ris_message",
		"data": {
			"timestamp": 1705320000.123,
			"peer_asn": 6939,
			"path": [6939, 3356, 13335],
			"announcements": [{"prefixes": ["1.1.1.0/24"]}],
			"community": [[65535, 666], [3356, 9999]]
		}
	}`)

	update, err := ParseMessage(msg, "rrc00")
	if err != nil {
		t.Fatalf("ParseMessage failed: %v", err)
	}
	if update == nil {
		t.Fatal("Expected update, got nil")
	}

	if update.Prefix != "1.1.1.0/24" {
		t.Errorf("Expected prefix 1.1.1.0/24, got %s", update.Prefix)
	}
	if update.PeerASN != 6939 {
		t.Errorf("Expected peer ASN 6939, got %d", update.PeerASN)
	}
	if update.OriginASN != 13335 {
		t.Errorf("Expected origin ASN 13335, got %d", update.OriginASN)
	}
	if !update.Announcement {
		t.Error("Expected announcement=true")
	}
	if update.Collector != "rrc00" {
		t.Errorf("Expected collector rrc00, got %s", update.Collector)
	}
	if len(update.ASPath) != 3 {
		t.Errorf("Expected AS path length 3, got %d", len(update.ASPath))
	}
	if len(update.Communities) != 2 {
		t.Errorf("Expected 2 communities, got %d", len(update.Communities))
	}
	if update.Communities[0] != "65535:666" {
		t.Errorf("Expected community 65535:666, got %s", update.Communities[0])
	}
}

func TestParseMessage_Withdrawal(t *testing.T) {
	msg := []byte(`{
		"type": "ris_message",
		"data": {
			"timestamp": 1705320000.0,
			"peer_asn": "6939",
			"withdrawals": ["192.0.2.0/24"]
		}
	}`)

	update, err := ParseMessage(msg, "rrc01")
	if err != nil {
		t.Fatalf("ParseMessage failed: %v", err)
	}
	if update == nil {
		t.Fatal("Expected update, got nil")
	}

	if update.Prefix != "192.0.2.0/24" {
		t.Errorf("Expected prefix 192.0.2.0/24, got %s", update.Prefix)
	}
	if update.Announcement {
		t.Error("Expected announcement=false for withdrawal")
	}
	if update.PeerASN != 6939 {
		t.Errorf("Expected peer ASN 6939, got %d", update.PeerASN)
	}
}

func TestParseMessage_NonRISMessage(t *testing.T) {
	msg := []byte(`{"type": "ris_error", "data": {"message": "test"}}`)

	update, err := ParseMessage(msg, "rrc00")
	if err != nil {
		t.Fatalf("ParseMessage failed: %v", err)
	}
	if update != nil {
		t.Error("Expected nil for non-ris_message type")
	}
}

func TestParseMessage_NestedASPath(t *testing.T) {
	// AS path with AS_SET (nested array)
	msg := []byte(`{
		"type": "ris_message",
		"data": {
			"timestamp": 1705320000.0,
			"peer_asn": 174,
			"path": [[174], [3356, 7018], 13335],
			"announcements": [{"prefixes": ["8.8.8.0/24"]}]
		}
	}`)

	update, err := ParseMessage(msg, "rrc00")
	if err != nil {
		t.Fatalf("ParseMessage failed: %v", err)
	}
	if update == nil {
		t.Fatal("Expected update, got nil")
	}

	// Nested arrays should be flattened
	expectedPath := []uint32{174, 3356, 7018, 13335}
	if len(update.ASPath) != len(expectedPath) {
		t.Fatalf("Expected AS path length %d, got %d", len(expectedPath), len(update.ASPath))
	}
	for i, asn := range expectedPath {
		if update.ASPath[i] != asn {
			t.Errorf("AS path[%d]: expected %d, got %d", i, asn, update.ASPath[i])
		}
	}
}

func TestParseASN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected uint32
	}{
		{"number", "6939", 6939},
		{"quoted string", `"6939"`, 6939},
		{"empty", "", 0},
		{"null", "null", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseASN([]byte(tt.input))
			if result != tt.expected {
				t.Errorf("parseASN(%s): expected %d, got %d", tt.input, tt.expected, result)
			}
		})
	}
}

func TestParseCommunities(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "tuple format",
			input:    `[[65535, 666], [3356, 9999]]`,
			expected: []string{"65535:666", "3356:9999"},
		},
		{
			name:     "string format",
			input:    `["65535:666", "no-export"]`,
			expected: []string{"65535:666", "no-export"},
		},
		{
			name:     "mixed format",
			input:    `[[65535, 666], "no-export"]`,
			expected: []string{"65535:666", "no-export"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rawMessages []json.RawMessage
			if err := json.Unmarshal([]byte(tt.input), &rawMessages); err != nil {
				t.Fatalf("Failed to parse test input: %v", err)
			}

			result := parseCommunities(rawMessages)
			if len(result) != len(tt.expected) {
				t.Fatalf("Expected %d communities, got %d", len(tt.expected), len(result))
			}
			for i, exp := range tt.expected {
				if result[i] != exp {
					t.Errorf("Community[%d]: expected %s, got %s", i, exp, result[i])
				}
			}
		})
	}
}

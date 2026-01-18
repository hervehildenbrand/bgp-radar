package rislive

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/hervehildenbrand/bgp-radar/pkg/models"
)

// RISMessage is the top-level message from RIS Live.
type RISMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// RISUpdateData is the BGP update data from RIS Live.
type RISUpdateData struct {
	Timestamp     float64           `json:"timestamp"`
	PeerASN       json.RawMessage   `json:"peer_asn"` // Can be string or number
	Path          json.RawMessage   `json:"path"`
	Announcements []RISAnnouncement `json:"announcements"`
	Withdrawals   []string          `json:"withdrawals"`
	Community     []json.RawMessage `json:"community"`
}

// RISAnnouncement represents announced prefixes.
type RISAnnouncement struct {
	Prefixes []string `json:"prefixes"`
}

// ParseMessage parses a RIS Live WebSocket message into a BGPUpdate.
// Returns nil if the message is not a BGP update (e.g., error, rrc_list).
func ParseMessage(data []byte, collector string) (*models.BGPUpdate, error) {
	var msg RISMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("unmarshal message: %w", err)
	}

	// Only process ris_message type
	if msg.Type != "ris_message" {
		return nil, nil
	}

	var updateData RISUpdateData
	if err := json.Unmarshal(msg.Data, &updateData); err != nil {
		return nil, fmt.Errorf("unmarshal update data: %w", err)
	}

	// Parse peer ASN (can be string or number)
	peerASN := parseASN(updateData.PeerASN)

	// Parse AS path (may contain nested arrays for AS_SET)
	asPath, err := parseASPath(updateData.Path)
	if err != nil {
		return nil, fmt.Errorf("parse AS path: %w", err)
	}

	// Get origin ASN (last in path)
	var originASN uint32
	if len(asPath) > 0 {
		originASN = asPath[len(asPath)-1]
	}

	// Parse communities
	communities := parseCommunities(updateData.Community)

	// Convert timestamp
	timestamp := time.Unix(int64(updateData.Timestamp), int64((updateData.Timestamp-float64(int64(updateData.Timestamp)))*1e9))

	// Process announcements (return first prefix, most common case)
	for _, ann := range updateData.Announcements {
		for _, prefix := range ann.Prefixes {
			return &models.BGPUpdate{
				Timestamp:    timestamp,
				PeerASN:      peerASN,
				Prefix:       prefix,
				ASPath:       asPath,
				OriginASN:    originASN,
				Communities:  communities,
				Announcement: true,
				Collector:    collector,
			}, nil
		}
	}

	// Process withdrawals
	for _, prefix := range updateData.Withdrawals {
		return &models.BGPUpdate{
			Timestamp:    timestamp,
			PeerASN:      peerASN,
			Prefix:       prefix,
			ASPath:       nil,
			OriginASN:    0,
			Communities:  nil,
			Announcement: false,
			Collector:    collector,
		}, nil
	}

	return nil, nil
}

// parseASN parses an ASN that can be either a string or number.
func parseASN(data json.RawMessage) uint32 {
	if data == nil || len(data) == 0 {
		return 0
	}

	// Try as number first
	var num uint32
	if err := json.Unmarshal(data, &num); err == nil {
		return num
	}

	// Try as string
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		val, _ := strconv.ParseUint(str, 10, 32)
		return uint32(val)
	}

	return 0
}

// parseASPath flattens the AS path which may contain nested arrays (AS_SET).
// Input can be: [174, 3356, 65001] or [[174], [3356, 65001], 65002]
func parseASPath(data json.RawMessage) ([]uint32, error) {
	if data == nil || len(data) == 0 {
		return nil, nil
	}

	// Try parsing as simple array of numbers first
	var simpleArray []uint32
	if err := json.Unmarshal(data, &simpleArray); err == nil {
		return simpleArray, nil
	}

	// Try parsing as mixed array (may contain nested arrays)
	var mixedArray []json.RawMessage
	if err := json.Unmarshal(data, &mixedArray); err != nil {
		return nil, fmt.Errorf("cannot parse path: %w", err)
	}

	var result []uint32
	for _, elem := range mixedArray {
		// Try as single number
		var num uint32
		if err := json.Unmarshal(elem, &num); err == nil {
			result = append(result, num)
			continue
		}

		// Try as array of numbers (AS_SET)
		var nums []uint32
		if err := json.Unmarshal(elem, &nums); err == nil {
			result = append(result, nums...)
			continue
		}
	}

	return result, nil
}

// parseCommunities converts community data to "ASN:value" string format.
// Input can be: [[65535, 666], [3356, 9999]] or ["65535:666"]
func parseCommunities(data []json.RawMessage) []string {
	if data == nil {
		return nil
	}

	var result []string
	for _, elem := range data {
		// Try as [ASN, value] tuple
		var tuple []uint32
		if err := json.Unmarshal(elem, &tuple); err == nil && len(tuple) == 2 {
			result = append(result, strconv.FormatUint(uint64(tuple[0]), 10)+":"+strconv.FormatUint(uint64(tuple[1]), 10))
			continue
		}

		// Try as string
		var str string
		if err := json.Unmarshal(elem, &str); err == nil {
			result = append(result, str)
		}
	}

	return result
}

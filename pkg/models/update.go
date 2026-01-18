// Package models defines data structures for BGP updates and events.
package models

import "time"

// BGPUpdate represents a parsed BGP update from RIS Live.
type BGPUpdate struct {
	Timestamp    time.Time
	PeerASN      uint32
	Prefix       string
	ASPath       []uint32
	OriginASN    uint32
	Communities  []string // Format: "ASN:value"
	Announcement bool     // true=announcement, false=withdrawal
	Collector    string   // e.g., "rrc00"
}

// BGPEvent represents a detected BGP anomaly.
type BGPEvent struct {
	ID              string
	CountryCode     string
	EventType       string // hijack, leak, blackhole, withdrawal_storm
	Severity        string // low, medium, high, critical
	EventCategory   string // attack, defense, misconfiguration
	RPKIStatus      string // valid, invalid, not_found, unknown
	IsCrossBorder   bool
	AttackerCountry string
	VictimCountry   string
	AffectedASN     uint32
	AffectedPrefix  string
	Details         map[string]interface{}
	DetectedAt      time.Time
	IsActive        bool
}

// Severity levels
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Event types
const (
	EventTypeHijack          = "hijack"
	EventTypeLeak            = "leak"
	EventTypeBlackhole       = "blackhole"
	EventTypeWithdrawalStorm = "withdrawal_storm"
	EventTypeDDoS            = "ddos"
)

// Event categories
const (
	CategoryAttack           = "attack"
	CategoryDefense          = "defense"
	CategoryMisconfiguration = "misconfiguration"
)

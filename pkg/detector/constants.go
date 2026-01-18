// Package detector provides BGP anomaly detection logic.
package detector

// Tier1ASNs contains the ASNs of known Tier-1 transit providers.
// Used for leak detection (SmallAS between two Tier-1s is suspicious).
var Tier1ASNs = map[uint32]string{
	174:   "Cogent Communications",
	209:   "Lumen (CenturyLink)",
	286:   "KPN",
	701:   "Verizon",
	1239:  "Sprint",
	1299:  "Telia",
	1828:  "Unitas Global",
	2914:  "NTT America",
	3257:  "GTT",
	3320:  "Deutsche Telekom",
	3356:  "Lumen (Level3)",
	3491:  "PCCW Global",
	5511:  "Orange",
	6453:  "Tata Communications",
	6461:  "Zayo",
	6762:  "Telecom Italia Sparkle",
	6830:  "Liberty Global",
	6939:  "Hurricane Electric",
	7018:  "AT&T",
	12956: "Telefonica",
}

// ScrubbingASNs contains ASNs of known DDoS mitigation/scrubbing centers.
// Traffic rerouted through these is defensive, not a hijack.
var ScrubbingASNs = map[uint32]string{
	// Radware
	198949: "Radware Ltd",
	48851:  "Radware Ltd - Europe",
	25773:  "Radware Inc - US",
	15823:  "Radware Ltd - Israel",
	// Akamai / Prolexic
	32787: "Akamai Prolexic",
	20940: "Akamai Technologies",
	16625: "Akamai Technologies",
	21342: "Akamai Technologies",
	35994: "Akamai Technologies",
	23454: "Akamai Technologies",
	// Cloudflare
	13335:  "Cloudflare Inc",
	209242: "Cloudflare Inc",
	394536: "Cloudflare Inc",
	395747: "Cloudflare Inc",
	// Imperva / Incapsula
	19551: "Incapsula Inc",
	62571: "Imperva Inc",
	// Vercara / Neustar
	19905:  "UltraDDoS Protect",
	12008:  "Vercara UltraDNS",
	397213: "Vercara LLC",
	// DDoS-Guard
	57724: "DDoS-Guard LTD",
	49612: "DDoS-Guard LTD",
	// Qrator Labs
	197068: "Qrator Labs",
	// Voxility
	3223: "Voxility LLP",
	// Link11
	34309: "Link11 GmbH",
	// Sucuri
	30148: "Sucuri",
	// StackPath
	20446: "StackPath ABC LLC",
	33438: "StackPath / Datum",
	// Path Network
	397031: "Path Network Inc",
	// Cloud providers with DDoS protection
	16509:  "Amazon AWS Shield",
	14618:  "Amazon",
	8075:   "Microsoft Azure DDoS",
	396982: "Google Cloud Armor",
	15169:  "Google",
}

// RFC7999Blackhole is the well-known blackhole community from RFC 7999.
const RFC7999Blackhole = "65535:666"

// ProviderBlackholeCommunities maps provider ASNs to their blackhole community.
// CRITICAL: Many providers use NON-STANDARD suffixes (not :666)!
// Using pattern matching would cause false positives.
var ProviderBlackholeCommunities = map[uint32]string{
	// NON-STANDARD suffixes
	3356: "3356:9999", // Lumen/Level3 (NOT 666!)
	1299: "1299:999",  // Arelion/Telia (NOT 666!)
	3491: "3491:999",  // PCCW (NOT 666!)
	286:  "286:66",    // KPN (NOT 666!)
	// Standard :666 suffix
	2914:  "2914:666",  // NTT
	3257:  "3257:666",  // GTT
	7018:  "7018:666",  // AT&T
	6939:  "6939:666",  // Hurricane Electric
	3320:  "3320:666",  // Deutsche Telekom
	6453:  "6453:666",  // Tata
	6461:  "6461:666",  // Zayo
	701:   "701:666",   // Verizon
	1239:  "1239:666",  // Sprint
	12956: "12956:666", // Telefonica
	6762:  "6762:666",  // Telecom Italia Sparkle
	6830:  "6830:666",  // Liberty Global
	9002:  "9002:666",  // RETN
	20804: "20804:666", // Exatel
}

// KnownBlackholeCommunities is a set of all known blackhole communities for O(1) lookup.
var KnownBlackholeCommunities map[string]bool

func init() {
	KnownBlackholeCommunities = make(map[string]bool)
	KnownBlackholeCommunities[RFC7999Blackhole] = true
	for _, community := range ProviderBlackholeCommunities {
		KnownBlackholeCommunities[community] = true
	}
}

// IsTier1 checks if an ASN is a known Tier-1 provider.
func IsTier1(asn uint32) bool {
	_, ok := Tier1ASNs[asn]
	return ok
}

// IsScrubbing checks if an ASN is a known scrubbing/DDoS mitigation center.
func IsScrubbing(asn uint32) bool {
	_, ok := ScrubbingASNs[asn]
	return ok
}

// IsBlackholeCommunity checks if a community string indicates blackholing.
func IsBlackholeCommunity(community string) bool {
	return KnownBlackholeCommunities[community]
}

// HasBlackholeCommunity checks if any community in the list is a blackhole.
func HasBlackholeCommunity(communities []string) bool {
	for _, c := range communities {
		if IsBlackholeCommunity(c) {
			return true
		}
	}
	return false
}

// HasScrubbingCenter checks if any ASN in the path is a scrubbing center.
func HasScrubbingCenter(asPath []uint32) bool {
	for _, asn := range asPath {
		if IsScrubbing(asn) {
			return true
		}
	}
	return false
}

// GetBlackholeCommunities returns the list of blackhole communities found.
func GetBlackholeCommunities(communities []string) []string {
	var blackholeCommunities []string
	for _, c := range communities {
		if IsBlackholeCommunity(c) {
			blackholeCommunities = append(blackholeCommunities, c)
		}
	}
	return blackholeCommunities
}

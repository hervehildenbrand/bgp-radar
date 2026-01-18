-- BGP Radar - Standalone schema for BGP event storage
-- This schema is independent of bgp-atlas and can be used standalone.

-- BGP Events table - stores detected anomalies (hijacks, leaks, blackholes)
CREATE TABLE IF NOT EXISTS bgp_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,        -- 'hijack', 'leak', 'blackhole'
    severity VARCHAR(20) NOT NULL,           -- 'low', 'medium', 'high', 'critical'
    event_category VARCHAR(20),              -- Additional categorization
    affected_asn INTEGER,                    -- The ASN affected by the event
    affected_prefix VARCHAR(50),             -- The prefix involved (CIDR notation)
    country_code VARCHAR(2),                 -- ISO 3166-1 alpha-2 country code
    details JSONB,                           -- Additional event details (as_path, etc.)
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    is_cross_border BOOLEAN DEFAULT FALSE,   -- Event involves multiple countries
    attacker_country VARCHAR(2),             -- Country of attacking AS (for hijacks)
    victim_country VARCHAR(2)                -- Country of victim AS (for hijacks)
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_events_type ON bgp_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_detected ON bgp_events(detected_at);
CREATE INDEX IF NOT EXISTS idx_events_asn ON bgp_events(affected_asn);
CREATE INDEX IF NOT EXISTS idx_events_prefix ON bgp_events(affected_prefix);
CREATE INDEX IF NOT EXISTS idx_events_country ON bgp_events(country_code);
CREATE INDEX IF NOT EXISTS idx_events_active ON bgp_events(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_events_severity ON bgp_events(severity);

-- Optional: ASN-to-country mapping table (for country resolution)
-- Populate this from CAIDA or similar datasets
CREATE TABLE IF NOT EXISTS asn_countries (
    asn INTEGER PRIMARY KEY,
    country_code VARCHAR(2) NOT NULL,
    name VARCHAR(255),                       -- ASN name/description
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asn_country ON asn_countries(country_code);

-- Comments
COMMENT ON TABLE bgp_events IS 'BGP anomaly events detected by bgp-radar';
COMMENT ON TABLE asn_countries IS 'Optional ASN-to-country mapping for enrichment';
COMMENT ON COLUMN bgp_events.event_type IS 'Type of BGP anomaly: hijack, leak, or blackhole';
COMMENT ON COLUMN bgp_events.details IS 'JSON object with as_path, communities, peer info, etc.';

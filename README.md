# bgp-radar

High-performance real-time BGP anomaly detector using RIPE RIS Live.

## Features

- Real-time BGP update processing via WebSocket
- Hijack detection (origin changes, MOAS)
- Route leak detection (Tier1-SmallAS-Tier1 pattern)
- Blackhole community detection (RFC7999 + provider-specific)
- Multi-collector support (23 RIPE RIS collectors)
- Optional persistence (PostgreSQL + Redis)
- Docker-ready

## Quick Start

### No Dependencies (stdout only)

```bash
bgp-radar -collectors=rrc00,rrc01
```

### With PostgreSQL

```bash
bgp-radar -collectors=rrc00 -database=postgres://user:pass@localhost/bgpradar
```

### With Docker

```bash
docker run -e BGP_RADAR_COLLECTORS=rrc00 ghcr.io/hervehildenbrand/bgp-radar
```

## Installation

### From Source

```bash
go install github.com/hervehildenbrand/bgp-radar/cmd/bgp-radar@latest
```

### From Binary

Download from [Releases](https://github.com/hervehildenbrand/bgp-radar/releases).

### Docker

```bash
docker pull ghcr.io/hervehildenbrand/bgp-radar
```

## Configuration

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-collectors` | Comma-separated RIS collectors | `rrc00` |
| `-database` | PostgreSQL URL | (none) |
| `-redis` | Redis URL | (none) |
| `-asn-data` | Path to ASN-country CSV file | (none) |
| `-buffer` | Update channel buffer size | `100000` |
| `-workers` | Detector worker count | `8` |
| `-stats` | Stats logging interval | `30s` |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `BGP_RADAR_COLLECTORS` | Comma-separated RIS collectors |
| `BGP_RADAR_DATABASE` | PostgreSQL URL |
| `BGP_RADAR_REDIS` | Redis URL |
| `BGP_RADAR_ASN_DATA` | Path to ASN-country CSV file |

Environment variables are used when the corresponding flag is not set.

## Detection Capabilities

| Type | Method | Confidence |
|------|--------|------------|
| Hijack | Origin ASN change | 0.7-0.9 |
| Route Leak | Tier1→SmallAS→Tier1 pattern | 0.85 |
| Blackhole | RFC7999/provider communities | 0.6-0.95 |

### Hijack Detection

Detects when:
- A prefix is announced by a different origin ASN than previously seen
- Multiple Origin AS (MOAS) events occur
- Sub-prefix hijacks (more specific announcements)

### Route Leak Detection

Identifies the classic leak pattern:
- Large transit provider (Tier 1) → Small AS → Large transit provider (Tier 1)
- Indicates a customer AS is improperly announcing routes learned from one provider to another

### Blackhole Detection

Recognizes blackhole communities:
- RFC7999 (65535:666)
- Provider-specific communities (Cogent, Level3, NTT, etc.)

## RIS Collectors

RIPE RIS operates 23 collectors worldwide:

| Collector | Location |
|-----------|----------|
| rrc00 | Amsterdam (multi-hop) |
| rrc01 | London (LINX) |
| rrc03 | Amsterdam (AMS-IX) |
| rrc04 | Geneva (CIXP) |
| rrc05 | Vienna (VIX) |
| rrc06 | Tokyo (DIX-IE) |
| rrc07 | Stockholm (Netnod) |
| rrc10 | Milan (MIX) |
| rrc11 | New York (NYIIX) |
| rrc12 | Frankfurt (DE-CIX) |
| rrc13 | Moscow (MSK-IX) |
| rrc14 | Palo Alto (PAIX) |
| rrc15 | São Paulo (PTTMetro) |
| rrc16 | Miami (NOTA) |
| rrc18 | Barcelona (CATNIX) |
| rrc19 | Johannesburg (NAP Africa) |
| rrc20 | Zurich (SwissIX) |
| rrc21 | Paris (France-IX) |
| rrc22 | Bucharest (InterLAN) |
| rrc23 | Singapore (Equinix) |
| rrc24 | Montevideo (UY) |
| rrc25 | Amsterdam (Global) |
| rrc26 | Dubai (UAE-IX) |

## Database Schema

If using PostgreSQL, apply the schema:

```bash
psql -d bgpradar -f migrations/001_create_events.sql
```

This creates:
- `bgp_events` - Detected anomalies with metadata
- `asn_countries` - Optional ASN-to-country mapping

## ASN-to-Country Resolution

Country codes can be resolved via:

1. **CSV file** (`-asn-data`): Format `asn,country_code`
2. **Database**: `asn_countries` table
3. **None**: Events will have country code "XX"

Example CSV:
```csv
13335,US
15169,US
32934,US
```

## Example Deployment

See `examples/docker-compose.yml` for a complete deployment with PostgreSQL and Redis.

```yaml
version: '3.8'
services:
  bgp-radar:
    image: ghcr.io/hervehildenbrand/bgp-radar
    environment:
      - BGP_RADAR_COLLECTORS=rrc00,rrc01,rrc03
      - BGP_RADAR_DATABASE=postgres://radar:secret@postgres:5432/bgpradar
      - BGP_RADAR_REDIS=redis://redis:6379/0
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: bgpradar
      POSTGRES_USER: radar
      POSTGRES_PASSWORD: secret
    volumes:
      - ./migrations:/docker-entrypoint-initdb.d

  redis:
    image: redis:7-alpine
```

## Performance

bgp-radar is designed for high throughput:

- Handles 10,000+ updates/second on a single core
- Configurable worker pool for parallel detection
- Buffered channels prevent backpressure
- Efficient JSON parsing with minimal allocations

Typical resource usage:
- CPU: 0.5-2 cores depending on collector count
- Memory: 50-200MB depending on Redis cache size
- Network: ~1-5 Mbps per collector

## Output Format

Events are logged as JSON:

```json
{
  "type": "hijack",
  "severity": "high",
  "category": "origin_change",
  "affected_asn": 13335,
  "affected_prefix": "1.1.1.0/24",
  "detected_at": "2024-01-15T10:30:00Z",
  "details": {
    "old_origin": 13335,
    "new_origin": 12345,
    "as_path": [6939, 12345],
    "peer": "80.249.208.1"
  }
}
```

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [RIPE RIS Live](https://ris-live.ripe.net/) for real-time BGP data
- [CAIDA](https://www.caida.org/) for AS relationship data

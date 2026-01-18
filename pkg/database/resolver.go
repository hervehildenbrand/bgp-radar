// Package database provides ASN-to-country resolution with multiple backend options.
package database

import (
	"bufio"
	"database/sql"
	"encoding/csv"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	refreshInterval = 15 * time.Minute // Refresh ASN mapping every 15 minutes
)

// CountryResolver provides ASN-to-country lookups.
type CountryResolver interface {
	// Resolve returns the country code for an ASN, or "" if unknown.
	Resolve(asn uint32) string
	// ResolveFromPath returns the first known country code from an AS path.
	ResolveFromPath(asPath []int) string
	// Count returns the number of ASNs in the mapping.
	Count() int
	// Start begins any background refresh operations.
	Start()
	// Stop stops any background operations.
	Stop()
}

// NullResolver returns "XX" (unknown) for all ASNs.
// Use this when no ASN-to-country data is available.
type NullResolver struct{}

// NewNullResolver creates a new null resolver.
func NewNullResolver() *NullResolver {
	return &NullResolver{}
}

func (r *NullResolver) Resolve(asn uint32) string      { return "" }
func (r *NullResolver) ResolveFromPath([]int) string   { return "" }
func (r *NullResolver) Count() int                     { return 0 }
func (r *NullResolver) Start()                         {}
func (r *NullResolver) Stop()                          {}

// FileResolver loads ASN-to-country mappings from a CSV file.
// Expected format: asn,country_code (e.g., "13335,US")
type FileResolver struct {
	filePath string
	mapping  map[int]string
	mu       sync.RWMutex
}

// NewFileResolver creates a resolver that loads mappings from a CSV file.
func NewFileResolver(filePath string) (*FileResolver, error) {
	r := &FileResolver{
		filePath: filePath,
		mapping:  make(map[int]string),
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *FileResolver) load() error {
	file, err := os.Open(r.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(bufio.NewReader(file))
	// Skip header if present
	header, err := reader.Read()
	if err != nil {
		return err
	}

	// Check if first row is data (numeric ASN) or header
	if len(header) >= 2 {
		if asn, err := strconv.Atoi(strings.TrimSpace(header[0])); err == nil {
			r.mapping[asn] = strings.ToUpper(strings.TrimSpace(header[1]))
		}
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(record) < 2 {
			continue
		}
		asn, err := strconv.Atoi(strings.TrimSpace(record[0]))
		if err != nil {
			continue
		}
		country := strings.ToUpper(strings.TrimSpace(record[1]))
		if len(country) == 2 {
			r.mapping[asn] = country
		}
	}

	log.Printf("FileResolver: Loaded %d ASN mappings from %s", len(r.mapping), r.filePath)
	return nil
}

func (r *FileResolver) Resolve(asn uint32) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mapping[int(asn)]
}

func (r *FileResolver) ResolveFromPath(asPath []int) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, asn := range asPath {
		if country, ok := r.mapping[asn]; ok {
			return country
		}
	}
	return ""
}

func (r *FileResolver) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.mapping)
}

func (r *FileResolver) Start() {}
func (r *FileResolver) Stop()  {}

// DatabaseResolver loads ASN-to-country mappings from a database table.
// Uses a simple schema: SELECT asn, country_code FROM asn_countries
type DatabaseResolver struct {
	db         *sql.DB
	tableName  string
	mapping    map[int]string
	mu         sync.RWMutex
	done       chan struct{}
	wg         sync.WaitGroup
	lastUpdate time.Time
}

// NewDatabaseResolver creates a resolver that loads mappings from a database.
// tableName defaults to "asn_countries" if empty.
func NewDatabaseResolver(db *sql.DB, tableName string) *DatabaseResolver {
	if tableName == "" {
		tableName = "asn_countries"
	}
	return &DatabaseResolver{
		db:        db,
		tableName: tableName,
		mapping:   make(map[int]string),
		done:      make(chan struct{}),
	}
}

// Start begins periodic refresh of the ASN mapping.
func (r *DatabaseResolver) Start() {
	// Load immediately
	r.refresh()

	// Start periodic refresh
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				r.refresh()
			case <-r.done:
				return
			}
		}
	}()
}

// Stop stops the resolver.
func (r *DatabaseResolver) Stop() {
	close(r.done)
	r.wg.Wait()
}

// Resolve returns the country code for an ASN, or "" if unknown.
func (r *DatabaseResolver) Resolve(asn uint32) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mapping[int(asn)]
}

// ResolveFromPath returns the first known country code from an AS path.
func (r *DatabaseResolver) ResolveFromPath(asPath []int) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, asn := range asPath {
		if country, ok := r.mapping[asn]; ok {
			return country
		}
	}
	return ""
}

// Count returns the number of ASNs in the mapping.
func (r *DatabaseResolver) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.mapping)
}

// refresh loads the ASN-to-country mapping from the database.
func (r *DatabaseResolver) refresh() {
	start := time.Now()

	// Query all ASN -> country mappings from the configured table
	query := "SELECT asn, country_code FROM " + r.tableName + " WHERE country_code IS NOT NULL AND country_code != ''"
	rows, err := r.db.Query(query)
	if err != nil {
		log.Printf("DatabaseResolver: Failed to query %s: %v", r.tableName, err)
		return
	}
	defer rows.Close()

	newMapping := make(map[int]string)
	for rows.Next() {
		var asn int
		var country string
		if err := rows.Scan(&asn, &country); err != nil {
			continue
		}
		newMapping[asn] = country
	}

	if err := rows.Err(); err != nil {
		log.Printf("DatabaseResolver: Row iteration error: %v", err)
		return
	}

	// Update mapping
	r.mu.Lock()
	r.mapping = newMapping
	r.lastUpdate = time.Now()
	r.mu.Unlock()

	log.Printf("DatabaseResolver: Loaded %d ASN mappings in %v", len(newMapping), time.Since(start))
}

// ASNResolver is an alias for backwards compatibility.
// Deprecated: Use DatabaseResolver instead.
type ASNResolver = DatabaseResolver

// NewASNResolver creates a new database resolver.
// Deprecated: Use NewDatabaseResolver instead.
func NewASNResolver(db *sql.DB) *ASNResolver {
	return NewDatabaseResolver(db, "asn_countries")
}

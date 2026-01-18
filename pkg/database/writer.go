// Package database provides PostgreSQL event writing with batch support.
package database

import (
	"database/sql"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/hervehildenbrand/bgp-radar/pkg/models"
	_ "github.com/lib/pq"
)

const (
	batchSize     = 50
	batchInterval = 2 * time.Second
	queueSize     = 10000
)

// EventWriter handles batch writing of BGP events to PostgreSQL.
type EventWriter struct {
	db       *sql.DB
	queue    chan models.BGPEvent
	done     chan struct{}
	wg       sync.WaitGroup
	running  bool
	mu       sync.Mutex

	// Stats
	eventsWritten uint64
	eventsDropped uint64
	batchesWritten uint64
}

// NewEventWriter creates a new database event writer.
func NewEventWriter(databaseURL string) (*EventWriter, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	log.Printf("Connected to PostgreSQL database")

	return &EventWriter{
		db:    db,
		queue: make(chan models.BGPEvent, queueSize),
		done:  make(chan struct{}),
	}, nil
}

// Start begins the background writer goroutine.
func (w *EventWriter) Start() {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	w.running = true
	w.mu.Unlock()

	w.wg.Add(1)
	go w.writerLoop()
	log.Printf("Database event writer started")
}

// Stop gracefully shuts down the writer, flushing remaining events.
func (w *EventWriter) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	w.running = false
	w.mu.Unlock()

	close(w.done)
	w.wg.Wait()
	w.db.Close()
	log.Printf("Database event writer stopped (written=%d, dropped=%d, batches=%d)",
		w.eventsWritten, w.eventsDropped, w.batchesWritten)
}

// Write queues an event for batch writing.
func (w *EventWriter) Write(event models.BGPEvent) {
	select {
	case w.queue <- event:
	default:
		// Queue full, drop event
		w.eventsDropped++
		if w.eventsDropped%1000 == 0 {
			log.Printf("Event queue full, dropped %d events", w.eventsDropped)
		}
	}
}

// Stats returns writer statistics.
func (w *EventWriter) Stats() map[string]interface{} {
	return map[string]interface{}{
		"events_written":  w.eventsWritten,
		"events_dropped":  w.eventsDropped,
		"batches_written": w.batchesWritten,
		"queue_len":       len(w.queue),
		"queue_cap":       cap(w.queue),
	}
}

func (w *EventWriter) writerLoop() {
	defer w.wg.Done()

	batch := make([]models.BGPEvent, 0, batchSize)
	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()

	for {
		select {
		case event := <-w.queue:
			batch = append(batch, event)
			if len(batch) >= batchSize {
				w.writeBatch(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				w.writeBatch(batch)
				batch = batch[:0]
			}

		case <-w.done:
			// Flush remaining events
			close(w.queue)
			for event := range w.queue {
				batch = append(batch, event)
				if len(batch) >= batchSize {
					w.writeBatch(batch)
					batch = batch[:0]
				}
			}
			if len(batch) > 0 {
				w.writeBatch(batch)
			}
			return
		}
	}
}

func (w *EventWriter) writeBatch(batch []models.BGPEvent) {
	if len(batch) == 0 {
		return
	}

	tx, err := w.db.Begin()
	if err != nil {
		log.Printf("Failed to begin transaction: %v", err)
		return
	}
	defer tx.Rollback()

	written := 0
	for _, event := range batch {
		if w.writeEvent(tx, event) {
			written++
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit batch: %v", err)
		return
	}

	w.eventsWritten += uint64(written)
	w.batchesWritten++
}

func (w *EventWriter) writeEvent(tx *sql.Tx, event models.BGPEvent) bool {
	// Check for existing active event with same signature (deduplication)
	var existingID int
	var existingSeverity string
	err := tx.QueryRow(`
		SELECT id, severity FROM bgp_events
		WHERE country_code = $1
		AND event_type = $2
		AND affected_asn = $3
		AND affected_prefix = $4
		AND is_active = true
		LIMIT 1
	`, event.CountryCode, event.EventType, event.AffectedASN, event.AffectedPrefix).Scan(&existingID, &existingSeverity)

	if err == nil {
		// Event exists, update last_seen_at and potentially severity
		severityOrder := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
		newSeverity := existingSeverity
		if severityOrder[event.Severity] > severityOrder[existingSeverity] {
			newSeverity = event.Severity
		}

		_, err = tx.Exec(`
			UPDATE bgp_events
			SET last_seen_at = $1, severity = $2
			WHERE id = $3
		`, event.DetectedAt, newSeverity, existingID)

		if err != nil {
			log.Printf("Failed to update event %d: %v", existingID, err)
			return false
		}
		return true
	}

	if err != sql.ErrNoRows {
		log.Printf("Failed to check existing event: %v", err)
		return false
	}

	// Insert new event
	detailsJSON, err := json.Marshal(event.Details)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	_, err = tx.Exec(`
		INSERT INTO bgp_events (
			country_code, event_type, severity, event_category,
			affected_asn, affected_prefix, details,
			detected_at, last_seen_at, is_active,
			is_cross_border, attacker_country, victim_country
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`,
		event.CountryCode,
		event.EventType,
		event.Severity,
		event.EventCategory,
		event.AffectedASN,
		event.AffectedPrefix,
		detailsJSON,
		event.DetectedAt,
		event.DetectedAt,
		true,
		event.IsCrossBorder,
		event.AttackerCountry,
		event.VictimCountry,
	)

	if err != nil {
		log.Printf("Failed to insert event: %v", err)
		return false
	}

	return true
}

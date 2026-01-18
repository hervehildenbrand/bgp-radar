// bgp-radar - High-performance real-time BGP anomaly detector using RIPE RIS Live.
//
// This Go implementation can handle high-traffic collectors (like rrc00)
// and detects hijacks, route leaks, and blackhole events in real-time.
//
// Usage:
//
//	bgp-radar -collectors=rrc00,rrc11,rrc23 -redis=redis://localhost:6379
//
// Environment variables (alternative to flags):
//
//	BGP_RADAR_COLLECTORS - Comma-separated list of RIS collectors
//	BGP_RADAR_REDIS      - Redis URL
//	BGP_RADAR_DATABASE   - PostgreSQL URL
//	BGP_RADAR_ASN_DATA   - Path to ASN-country CSV file
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hervehildenbrand/bgp-radar/pkg/database"
	"github.com/hervehildenbrand/bgp-radar/pkg/detector"
	"github.com/hervehildenbrand/bgp-radar/pkg/models"
	"github.com/hervehildenbrand/bgp-radar/pkg/rislive"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
)

var (
	collectorsFlag  = flag.String("collectors", "", "Comma-separated list of RIS collectors")
	redisURLFlag    = flag.String("redis", "", "Redis URL (optional, e.g., redis://localhost:6379)")
	databaseURLFlag = flag.String("database", "", "PostgreSQL URL (optional, e.g., postgresql://user:pass@host/db)")
	asnDataFlag     = flag.String("asn-data", "", "Path to ASN-country CSV file (optional, format: asn,country_code)")
	bufferSize      = flag.Int("buffer", 100000, "Update channel buffer size")
	workers         = flag.Int("workers", 8, "Number of detector worker goroutines")
	statsInterval   = flag.Duration("stats", 30*time.Second, "Stats logging interval")
)

// getEnvOrFlag returns the flag value if set, otherwise the environment variable, otherwise the default.
func getEnvOrFlag(flagVal *string, envName, defaultVal string) string {
	if *flagVal != "" {
		return *flagVal
	}
	if env := os.Getenv(envName); env != "" {
		return env
	}
	return defaultVal
}

func main() {
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("bgp-radar starting...")

	// Get configuration from flags or environment variables
	collectorsStr := getEnvOrFlag(collectorsFlag, "BGP_RADAR_COLLECTORS", "rrc00")
	redisURL := getEnvOrFlag(redisURLFlag, "BGP_RADAR_REDIS", "")
	databaseURL := getEnvOrFlag(databaseURLFlag, "BGP_RADAR_DATABASE", "")
	asnDataPath := getEnvOrFlag(asnDataFlag, "BGP_RADAR_ASN_DATA", "")

	// Parse collectors
	collectors := strings.Split(collectorsStr, ",")
	for i := range collectors {
		collectors[i] = strings.TrimSpace(collectors[i])
	}
	log.Printf("Collectors: %v", collectors)

	// Connect to Redis (optional)
	var redisClient *redis.Client
	if redisURL != "" {
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			log.Printf("Warning: Invalid Redis URL: %v", err)
		} else {
			redisClient = redis.NewClient(opt)
			if err := redisClient.Ping(context.Background()).Err(); err != nil {
				log.Printf("Warning: Redis connection failed: %v", err)
				redisClient = nil
			} else {
				log.Printf("Connected to Redis: %s", redisURL)
			}
		}
	}

	// Connect to PostgreSQL (optional)
	var dbWriter *database.EventWriter
	if databaseURL != "" {
		var err error
		dbWriter, err = database.NewEventWriter(databaseURL)
		if err != nil {
			log.Printf("Warning: Database connection failed: %v", err)
		} else {
			dbWriter.Start()
			log.Printf("Database writer started")
		}
	}

	// Create ASN resolver (optional - multiple sources supported)
	var resolver database.CountryResolver = database.NewNullResolver()

	// Priority: CSV file > Database > Null
	if asnDataPath != "" {
		fileResolver, err := database.NewFileResolver(asnDataPath)
		if err != nil {
			log.Printf("Warning: Failed to load ASN data from %s: %v", asnDataPath, err)
		} else {
			resolver = fileResolver
			log.Printf("Using file-based ASN resolver: %s (%d ASNs)", asnDataPath, resolver.Count())
		}
	} else if databaseURL != "" {
		db, err := sql.Open("postgres", databaseURL)
		if err == nil {
			dbResolver := database.NewDatabaseResolver(db, "asn_countries")
			dbResolver.Start()
			resolver = dbResolver
			log.Printf("Using database ASN resolver")
		} else {
			log.Printf("Warning: ASN resolver database connection failed: %v", err)
		}
	} else {
		log.Printf("No ASN resolver configured - country codes will be 'XX'")
	}

	// Create channels
	events := make(chan models.BGPEvent, 10000)

	// Create multi-collector client
	client := rislive.NewMultiClient(collectors, *bufferSize)

	// Create detectors
	blackholeDetector := detector.NewBlackholeDetector(events)
	hijackDetector := detector.NewHijackDetector(events, redisClient)
	leakDetector := detector.NewLeakDetector(events)

	// Stats
	var updatesProcessed uint64
	var eventsDetected uint64

	// Start detector workers
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for update := range client.Updates() {
				atomic.AddUint64(&updatesProcessed, 1)

				// Run all detectors
				blackholeDetector.Process(update)
				hijackDetector.Process(update)
				leakDetector.Process(update)
			}
		}(i)
	}

	// Start event logger/writer
	go func() {
		for event := range events {
			atomic.AddUint64(&eventsDetected, 1)

			// Resolve country code from ASN if not set
			if event.CountryCode == "" {
				// Try affected ASN first
				if event.AffectedASN > 0 {
					event.CountryCode = resolver.Resolve(event.AffectedASN)
				}
				// If still empty, try AS path from details
				if event.CountryCode == "" {
					if asPath, ok := event.Details["as_path"].([]interface{}); ok {
						intPath := make([]int, 0, len(asPath))
						for _, v := range asPath {
							if f, ok := v.(float64); ok {
								intPath = append(intPath, int(f))
							} else if i, ok := v.(int); ok {
								intPath = append(intPath, i)
							}
						}
						event.CountryCode = resolver.ResolveFromPath(intPath)
					}
				}
			}

			// Use "XX" (unknown) as fallback - DO NOT use "GL" as that's Greenland!
			if event.CountryCode == "" {
				event.CountryCode = "XX"
			}

			// Write to database if connected
			if dbWriter != nil {
				dbWriter.Write(event)
			}

			// Log event as JSON
			eventJSON, _ := json.Marshal(map[string]interface{}{
				"type":            event.EventType,
				"severity":        event.Severity,
				"category":        event.EventCategory,
				"affected_asn":    event.AffectedASN,
				"affected_prefix": event.AffectedPrefix,
				"detected_at":     event.DetectedAt.Format(time.RFC3339),
				"details":         event.Details,
			})
			log.Printf("EVENT: %s", eventJSON)
		}
	}()

	// Start stats logger
	go func() {
		ticker := time.NewTicker(*statsInterval)
		defer ticker.Stop()
		lastUpdates := uint64(0)
		lastTime := time.Now()

		for range ticker.C {
			currentUpdates := atomic.LoadUint64(&updatesProcessed)
			currentEvents := atomic.LoadUint64(&eventsDetected)
			elapsed := time.Since(lastTime).Seconds()
			rate := float64(currentUpdates-lastUpdates) / elapsed

			clientStats := client.Stats()
			log.Printf("STATS: updates=%d (%.0f/s), events=%d, channel=%d/%d",
				currentUpdates, rate, currentEvents,
				clientStats["channel_len"], clientStats["channel_cap"])

			lastUpdates = currentUpdates
			lastTime = time.Now()
		}
	}()

	// Start client
	client.Start()

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Printf("Shutting down...")
	client.Stop()
	wg.Wait()
	close(events)

	// Stop database writer (flushes remaining events)
	if dbWriter != nil {
		dbWriter.Stop()
	}

	// Stop resolver
	resolver.Stop()

	log.Printf("Final stats: updates=%d, events=%d",
		atomic.LoadUint64(&updatesProcessed),
		atomic.LoadUint64(&eventsDetected))
}

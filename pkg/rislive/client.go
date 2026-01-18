// Package rislive provides a WebSocket client for RIPE RIS Live BGP stream.
package rislive

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hervehildenbrand/bgp-radar/pkg/models"
	"github.com/gorilla/websocket"
)

const (
	// RISLiveURL is the WebSocket endpoint for RIS Live.
	RISLiveURL = "wss://ris-live.ripe.net/v1/ws/"

	// Connection settings
	initialReconnectDelay = 5 * time.Second
	maxReconnectDelay     = 5 * time.Minute
	reconnectBackoff      = 2.0
	pingInterval          = 30 * time.Second
	connectionTimeout     = 60 * time.Second
	writeTimeout          = 10 * time.Second
)

// Client is a WebSocket client for RIS Live with automatic reconnection.
type Client struct {
	collector string
	updates   chan<- models.BGPUpdate
	done      chan struct{}
	wg        sync.WaitGroup

	// Stats
	messagesReceived uint64
	updatesParsed    uint64
	errors           uint64
	reconnects       uint64

	// State
	running   atomic.Bool
	connected atomic.Bool
}

// NewClient creates a new RIS Live client for a specific collector.
func NewClient(collector string, updates chan<- models.BGPUpdate) *Client {
	return &Client{
		collector: collector,
		updates:   updates,
		done:      make(chan struct{}),
	}
}

// Start begins the WebSocket connection in a goroutine.
func (c *Client) Start() {
	if c.running.Swap(true) {
		log.Printf("[%s] Client already running", c.collector)
		return
	}

	c.wg.Add(1)
	go c.runLoop()
	log.Printf("[%s] Client started", c.collector)
}

// Stop gracefully shuts down the client.
func (c *Client) Stop() {
	if !c.running.Swap(false) {
		return
	}
	close(c.done)
	c.wg.Wait()
	log.Printf("[%s] Client stopped", c.collector)
}

// Stats returns current statistics.
func (c *Client) Stats() map[string]interface{} {
	return map[string]interface{}{
		"collector":         c.collector,
		"connected":         c.connected.Load(),
		"messages_received": atomic.LoadUint64(&c.messagesReceived),
		"updates_parsed":    atomic.LoadUint64(&c.updatesParsed),
		"errors":            atomic.LoadUint64(&c.errors),
		"reconnects":        atomic.LoadUint64(&c.reconnects),
	}
}

func (c *Client) runLoop() {
	defer c.wg.Done()

	reconnectDelay := initialReconnectDelay

	for c.running.Load() {
		err := c.connectAndStream()
		if err != nil {
			atomic.AddUint64(&c.errors, 1)
			atomic.AddUint64(&c.reconnects, 1)
			log.Printf("[%s] Connection error: %v, reconnecting in %v", c.collector, err, reconnectDelay)
		}

		// Check if we should stop
		select {
		case <-c.done:
			return
		case <-time.After(reconnectDelay):
			// Exponential backoff
			reconnectDelay = time.Duration(float64(reconnectDelay) * reconnectBackoff)
			if reconnectDelay > maxReconnectDelay {
				reconnectDelay = maxReconnectDelay
			}
		}
	}
}

func (c *Client) connectAndStream() error {
	// Connect with timeout
	dialer := websocket.Dialer{
		HandshakeTimeout: connectionTimeout,
	}

	log.Printf("[%s] Connecting to RIS Live...", c.collector)
	conn, _, err := dialer.Dial(RISLiveURL, nil)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()

	// Send subscription message
	subscribeMsg := map[string]interface{}{
		"type": "ris_subscribe",
		"data": map[string]interface{}{
			"type": "UPDATE",
			"host": c.collector,
		},
	}

	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := conn.WriteJSON(subscribeMsg); err != nil {
		return fmt.Errorf("subscribe failed: %w", err)
	}

	c.connected.Store(true)
	log.Printf("[%s] Connected and subscribed", c.collector)

	// Set up ping handler
	conn.SetPongHandler(func(string) error {
		return nil
	})

	// Start ping goroutine
	pingDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				conn.SetWriteDeadline(time.Now().Add(writeTimeout))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-pingDone:
				return
			case <-c.done:
				// Close connection to unblock ReadMessage
				conn.Close()
				return
			}
		}
	}()
	defer close(pingDone)

	// Read messages
	for c.running.Load() {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			// Normal close - exit cleanly
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				c.connected.Store(false)
				return nil
			}
			// Any error means connection is broken - return to trigger reconnect
			c.connected.Store(false)
			return fmt.Errorf("read failed: %w", err)
		}

		// Only process text messages
		if messageType != websocket.TextMessage {
			continue
		}

		atomic.AddUint64(&c.messagesReceived, 1)

		// Log first few messages for debugging
		if atomic.LoadUint64(&c.messagesReceived) <= 3 {
			msgLen := len(message)
			if msgLen > 200 {
				msgLen = 200
			}
			log.Printf("[%s] Raw message: %s", c.collector, string(message[:msgLen]))
		}

		// Parse and send update
		update, err := ParseMessage(message, c.collector)
		if err != nil {
			// Not all messages are updates, this is fine
			if atomic.LoadUint64(&c.messagesReceived) <= 10 {
				log.Printf("[%s] Parse error: %v", c.collector, err)
			}
			continue
		}
		if update != nil {
			atomic.AddUint64(&c.updatesParsed, 1)
			// Non-blocking send to channel
			select {
			case c.updates <- *update:
			default:
				// Channel full, log occasionally
				if atomic.LoadUint64(&c.updatesParsed)%10000 == 0 {
					log.Printf("[%s] Update channel full, dropping update", c.collector)
				}
			}
		}
	}

	c.connected.Store(false)
	return nil
}

// MultiClient manages multiple RIS Live clients for global coverage.
type MultiClient struct {
	clients  []*Client
	updates  chan models.BGPUpdate
	running  atomic.Bool
	dedup    sync.Map // For deduplication
	dedupTTL time.Duration
}

// NewMultiClient creates a client that connects to multiple collectors.
func NewMultiClient(collectors []string, bufferSize int) *MultiClient {
	updates := make(chan models.BGPUpdate, bufferSize)
	clients := make([]*Client, len(collectors))

	for i, collector := range collectors {
		clients[i] = NewClient(collector, updates)
	}

	return &MultiClient{
		clients:  clients,
		updates:  updates,
		dedupTTL: 5 * time.Second,
	}
}

// Updates returns the channel of BGP updates.
func (mc *MultiClient) Updates() <-chan models.BGPUpdate {
	return mc.updates
}

// Start begins all collector clients.
func (mc *MultiClient) Start() {
	if mc.running.Swap(true) {
		return
	}
	for _, client := range mc.clients {
		client.Start()
	}
	log.Printf("MultiClient started with %d collectors", len(mc.clients))
}

// Stop gracefully shuts down all clients.
func (mc *MultiClient) Stop() {
	if !mc.running.Swap(false) {
		return
	}
	for _, client := range mc.clients {
		client.Stop()
	}
	close(mc.updates)
	log.Printf("MultiClient stopped")
}

// Stats returns aggregated statistics from all clients.
func (mc *MultiClient) Stats() map[string]interface{} {
	var totalMessages, totalUpdates, totalErrors, totalReconnects uint64
	clientStats := make([]map[string]interface{}, len(mc.clients))

	for i, client := range mc.clients {
		stats := client.Stats()
		clientStats[i] = stats
		totalMessages += stats["messages_received"].(uint64)
		totalUpdates += stats["updates_parsed"].(uint64)
		totalErrors += stats["errors"].(uint64)
		totalReconnects += stats["reconnects"].(uint64)
	}

	return map[string]interface{}{
		"running":          mc.running.Load(),
		"collectors":       clientStats,
		"total_messages":   totalMessages,
		"total_updates":    totalUpdates,
		"total_errors":     totalErrors,
		"total_reconnects": totalReconnects,
		"channel_len":      len(mc.updates),
		"channel_cap":      cap(mc.updates),
	}
}

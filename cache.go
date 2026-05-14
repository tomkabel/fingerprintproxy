package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	fhttp "github.com/saucesteals/fhttp"
	"github.com/saucesteals/mimic"
)

const defaultCacheTTL = 30 * time.Minute
const maxCacheEntries = 20

type MimicSpec struct {
	Brand    mimic.Brand
	Version  string
	Platform mimic.Platform
}

func (s MimicSpec) Key() string {
	return fmt.Sprintf("%s|%s|%s", s.Brand, s.Version, s.Platform)
}

type mimicEntry struct {
	transport *mimic.Transport
	created   time.Time
	lastUsed  time.Time
}

type MimicCache struct {
	transports map[string]*mimicEntry
	mu         sync.RWMutex
	ttl        time.Duration
	maxEntries int
}

func NewMimicCache(ttl time.Duration, maxEntries int) *MimicCache {
	return &MimicCache{
		transports: make(map[string]*mimicEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

func (mc *MimicCache) GetOrCreate(spec MimicSpec, insecureSkipVerify bool) (*mimic.Transport, error) {
	key := spec.Key()

	mc.mu.RLock()
	if entry, ok := mc.transports[key]; ok {
		if time.Since(entry.lastUsed) < mc.ttl {
			entry.lastUsed = time.Now()
			mc.mu.RUnlock()
			return entry.transport, nil
		}
	}
	mc.mu.RUnlock()

	mc.mu.Lock()
	defer mc.mu.Unlock()

	if entry, ok := mc.transports[key]; ok {
		if time.Since(entry.lastUsed) < mc.ttl {
			entry.lastUsed = time.Now()
			return entry.transport, nil
		}
		delete(mc.transports, key)
	}

	if len(mc.transports) >= mc.maxEntries {
		mc.evictOldest()
	}

	opts := mimic.TransportOptions{
		Version:  spec.Version,
		Brand:    spec.Brand,
		Platform: spec.Platform,
	}

	if insecureSkipVerify {
		baseTransport := &fhttp.Transport{
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &utls.Config{InsecureSkipVerify: true},
		}
		opts.Transport = baseTransport
	}

	transport, err := mimic.NewTransport(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create mimic transport for %s: %w", key, err)
	}

	now := time.Now()
	mc.transports[key] = &mimicEntry{
		transport: transport,
		created:   now,
		lastUsed:  now,
	}

	log.Printf("[MimicCache] Created transport for %s", key)
	return transport, nil
}

func (mc *MimicCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range mc.transports {
		if oldestKey == "" || entry.lastUsed.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.lastUsed
		}
	}

	if oldestKey != "" {
		delete(mc.transports, oldestKey)
		log.Printf("[MimicCache] Evicted transport: %s", oldestKey)
	}
}

func (mc *MimicCache) CloseIdleConnections() {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	for _, entry := range mc.transports {
		type closeIdler interface{ CloseIdleConnections() }
		if c, ok := entry.transport.Transport.(closeIdler); ok {
			c.CloseIdleConnections()
		}
	}
}

func (mc *MimicCache) Len() int {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return len(mc.transports)
}

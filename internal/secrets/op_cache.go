package secrets

import (
	"sync"
	"time"
)

// opCache is a bounded, in-process cache for the 1Password backend. Service
// accounts are rate-limited, so short-lived gog invocations should not hit op
// for the same item repeatedly. The cache keeps three maps in sync:
//
//   - uuid: resolves a keyring key (item title) to its 1Password item UUID.
//     Addressing items by UUID reduces op's fuzzy title lookup from 3 reads to
//     a single read (per-op item get semantics).
//   - value: the last-read credential bytes for a key, so Get within the TTL
//     performs no op subprocess call.
//   - list: the most recent op item list resolution of title→UUID.
//
// Writes invalidate/refresh the affected entries so refresh-token rotation is
// always observable immediately (no stale reads after a Set).
type opCache struct {
	mu     sync.Mutex
	max    int
	ttl    time.Duration
	uuids  map[string]opUUIDEntry
	values map[string]opValueEntry
	listed time.Time
	byKey  map[string]string // list resolution: key → UUID
}

type opUUIDEntry struct {
	uuid string
	at   time.Time
}

type opValueEntry struct {
	value string
	at    time.Time
}

// newOPCache returns an empty cache. A non-positive limit disables bounds
// enforcement; a non-positive ttl keeps entries until evicted.
func newOPCache(limit int, ttl time.Duration) *opCache {
	if limit <= 0 {
		limit = opCacheMaxEntries
	}

	return &opCache{
		max:    limit,
		ttl:    ttl,
		uuids:  make(map[string]opUUIDEntry),
		values: make(map[string]opValueEntry),
		byKey:  make(map[string]string),
	}
}

func (c *opCache) fresh(now time.Time, at time.Time) bool {
	if c.ttl <= 0 {
		return true
	}

	return now.Sub(at) < c.ttl
}

// uuid returns the cached UUID for key when fresh.
func (c *opCache) uuid(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.uuids[key]
	if !ok || !c.fresh(time.Now(), e.at) {
		return "", false
	}

	return e.uuid, true
}

// value returns the cached credential value for key when fresh.
func (c *opCache) value(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.values[key]
	if !ok || !c.fresh(time.Now(), e.at) {
		return "", false
	}

	return e.value, true
}

// list returns the cached title→UUID list resolution when fresh.
func (c *opCache) list() (map[string]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.byKey == nil || !c.fresh(time.Now(), c.listed) {
		return nil, false
	}

	out := make(map[string]string, len(c.byKey))
	for key, u := range c.byKey {
		out[key] = u
	}

	return out, true
}

// storeList records an op item list resolution and refreshes each key's UUID.
func (c *opCache) storeList(byTitle map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	c.byKey = make(map[string]string, len(byTitle))

	for title, u := range byTitle {
		c.byKey[title] = u
	}

	c.listed = now
	for title, u := range byTitle {
		c.uuids[title] = opUUIDEntry{uuid: u, at: now}
	}

	c.pruneLocked(now)
}

// store refreshes the value, UUID, and list entries for key after a read or
// write. Set passes the empty string for uuid on a create (its UUID is not
// known until the op response is parsed by createItem, which caches it).
func (c *opCache) store(key string, uuid string, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if uuid != "" {
		c.uuids[key] = opUUIDEntry{uuid: uuid, at: now}
		if c.byKey != nil {
			c.byKey[key] = uuid
		}
	}
	c.values[key] = opValueEntry{value: value, at: now}
	c.pruneLocked(now)
}

// delete removes every trace of key after a successful Remove.
func (c *opCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.uuids, key)
	delete(c.values, key)
	delete(c.byKey, key)
}

// pruneLocked drops expired entries first, then evicts arbitrary entries to
// stay within the bound. Callers must hold c.mu.
func (c *opCache) pruneLocked(now time.Time) {
	remaining := len(c.uuids) + len(c.values)
	if c.max > 0 && remaining <= c.max {
		return
	}

	for key, e := range c.uuids {
		if c.max > 0 && len(c.uuids)+len(c.values) <= c.max {
			break
		}

		if !c.fresh(now, e.at) {
			delete(c.uuids, key)
			delete(c.byKey, key)
		}
	}

	for key, e := range c.values {
		if c.max > 0 && len(c.uuids)+len(c.values) <= c.max {
			break
		}

		if !c.fresh(now, e.at) {
			delete(c.values, key)
		}
	}

	if c.max <= 0 {
		return
	}
	// If still over the bound after pruning, evict arbitrary entries.
	for key := range c.uuids {
		if len(c.uuids)+len(c.values) <= c.max {
			break
		}

		delete(c.uuids, key)
		delete(c.byKey, key)
	}

	for key := range c.values {
		if len(c.uuids)+len(c.values) <= c.max {
			break
		}

		delete(c.values, key)
	}
}

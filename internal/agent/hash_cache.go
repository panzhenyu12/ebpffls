package agent

import (
	"fmt"
	"os"
	"sync"
	"time"
)

type hashCache struct {
	mu      sync.Mutex
	entries map[string]hashCacheEntry
}

type hashCacheEntry struct {
	Size    int64
	ModTime time.Time
	Hash    string
	Info    os.FileInfo
}

const maxHashCacheEntries = 4096

func newHashCache() *hashCache {
	return &hashCache{entries: make(map[string]hashCacheEntry)}
}

func (c *hashCache) get(path string) (string, bool) {
	if c == nil {
		return "", false
	}
	stat, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[path]
	if !ok {
		return "", false
	}
	if entry.Size != stat.Size() || !entry.ModTime.Equal(stat.ModTime()) ||
		(entry.Info != nil && !os.SameFile(entry.Info, stat)) {
		delete(c.entries, path)
		return "", false
	}
	return entry.Hash, true
}

func (c *hashCache) compute(path string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("hash cache is nil")
	}
	if hash, ok := c.get(path); ok {
		return hash, nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		before, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		hash, err := fileSHA256(path)
		if err != nil {
			return "", err
		}
		after, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !os.SameFile(before, after) {
			continue
		}
		c.mu.Lock()
		if _, exists := c.entries[path]; !exists && len(c.entries) >= maxHashCacheEntries {
			for victim := range c.entries {
				delete(c.entries, victim)
				break
			}
		}
		c.entries[path] = hashCacheEntry{
			Size:    after.Size(),
			ModTime: after.ModTime(),
			Hash:    hash,
			Info:    after,
		}
		c.mu.Unlock()
		return hash, nil
	}
	return "", fmt.Errorf("file changed while hashing: %s", path)
}

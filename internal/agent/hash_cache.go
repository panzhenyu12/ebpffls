package agent

import (
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
}

func newHashCache() *hashCache {
	return &hashCache{entries: make(map[string]hashCacheEntry)}
}

func (c *hashCache) get(path string) (string, bool) {
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
	if entry.Size != stat.Size() || !entry.ModTime.Equal(stat.ModTime()) {
		delete(c.entries, path)
		return "", false
	}
	return entry.Hash, true
}

func (c *hashCache) compute(path string) (string, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if hash, ok := c.get(path); ok {
		return hash, nil
	}
	hash, err := fileSHA256(path)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.entries[path] = hashCacheEntry{
		Size:    stat.Size(),
		ModTime: stat.ModTime(),
		Hash:    hash,
	}
	c.mu.Unlock()
	return hash, nil
}

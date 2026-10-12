package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestHashCacheInvalidatesReplacedFileWithSameMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample")
	if err := os.WriteFile(path, []byte("first"), 0600); err != nil {
		t.Fatalf("write initial file: %v", err)
	}

	c := newHashCache()
	first, err := c.compute(path)
	if err != nil {
		t.Fatalf("compute initial hash: %v", err)
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat initial file: %v", err)
	}

	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("second"), 0600); err != nil {
		t.Fatalf("write replacement file: %v", err)
	}
	if err := os.Chtimes(replacement, stat.ModTime(), stat.ModTime()); err != nil {
		t.Fatalf("match replacement mtime: %v", err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatalf("replace file: %v", err)
	}

	second, err := c.compute(path)
	if err != nil {
		t.Fatalf("compute replacement hash: %v", err)
	}
	if first == second {
		t.Fatalf("hash cache returned stale hash %q after replacement", second)
	}
}

func TestHashCacheCapsEntries(t *testing.T) {
	dir := t.TempDir()
	c := newHashCache()
	for i := 0; i < maxHashCacheEntries+32; i++ {
		path := filepath.Join(dir, fmt.Sprintf("sample-%d", i))
		if err := os.WriteFile(path, []byte("same"), 0600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		if _, err := c.compute(path); err != nil {
			t.Fatalf("compute %s: %v", path, err)
		}
	}
	if got := len(c.entries); got != maxHashCacheEntries {
		t.Fatalf("entries len = %d, want cap %d", got, maxHashCacheEntries)
	}
}

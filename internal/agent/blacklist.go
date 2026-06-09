package agent

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/panzhenyu/ebpffls/internal/config"
)

type blacklist struct {
	mu         sync.RWMutex
	baseHashes []string
	hashes     map[string]struct{}
	files      []string
}

type procInfo struct {
	PID    uint32
	TGID   uint32
	UID    uint32
	Comm   string
	Exe    string
	Cgroup string
}

func newBlacklist(policy config.Policy) (*blacklist, error) {
	b := &blacklist{
		baseHashes: policy.BlacklistHashes,
		hashes:     make(map[string]struct{}),
		files:      policy.BlacklistHashFiles,
	}
	if err := b.reloadFiles(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *blacklist) reloadFiles() error {
	hashes := make(map[string]struct{})
	addHashTo(hashes, b.baseHashes...)
	for _, path := range b.files {
		if path == "" {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("open blacklist hash file %s: %w", path, err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			entry := strings.TrimSpace(scanner.Text())
			if entry == "" || strings.HasPrefix(entry, "#") {
				continue
			}
			fields := strings.Fields(entry)
			if len(fields) > 0 {
				addHashTo(hashes, fields[0])
			}
		}
		if err := scanner.Err(); err != nil {
			_ = file.Close()
			return fmt.Errorf("read blacklist hash file %s: %w", path, err)
		}
		_ = file.Close()
	}
	b.mu.Lock()
	b.hashes = hashes
	b.mu.Unlock()
	return nil
}

func (b *blacklist) matchHash(hash string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.hashes[strings.ToLower(hash)]
	return ok
}

func (b *blacklist) empty() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.hashes) == 0
}

func addHashTo(dst map[string]struct{}, hashes ...string) {
	for _, hash := range hashes {
		hash = strings.ToLower(strings.TrimSpace(hash))
		if len(hash) == sha256.Size*2 && isHex(hash) {
			dst[hash] = struct{}{}
		}
	}
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isHex(s string) bool {
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}

func readProc(pid uint32) (procInfo, error) {
	info := procInfo{PID: pid, TGID: pid}
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err == nil {
		info.Comm = strings.TrimSpace(string(comm))
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			switch fields[0] {
			case "Tgid:":
				if tgid, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
					info.TGID = uint32(tgid)
				}
			case "Uid:":
				if uid, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
					info.UID = uint32(uid)
				}
			}
		}
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err == nil {
		info.Exe = exe
	}
	cgroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err == nil {
		info.Cgroup = parseCgroupPath(string(cgroup))
	}
	if info.Comm == "" && info.Exe == "" {
		return info, fmt.Errorf("read proc %d: no comm or exe", pid)
	}
	return info, nil
}

func parseCgroupPath(data string) string {
	for _, line := range strings.Split(data, "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 {
			return strings.TrimSpace(parts[2])
		}
	}
	return ""
}

func listProcs() ([]procInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	procs := make([]procInfo, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		info, err := readProc(uint32(pid64))
		if err != nil {
			continue
		}
		procs = append(procs, info)
	}
	return procs, nil
}

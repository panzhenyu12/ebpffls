//go:build linux

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type openResult struct {
	Name  string `json:"name,omitempty"`
	PID   int    `json:"pid"`
	Errno int    `json:"errno"`
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "__open-helper" {
		if err := openHelper(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	binary := flag.String("binary", "", "frozen ebpffls executable")
	guard := flag.String("guard", "", "frozen test_lsm_chain.bpf.o")
	artifacts := flag.String("artifacts", "", "directory for policy and agent logs")
	timeout := flag.Duration("timeout", 60*time.Second, "overall test timeout")
	flag.Parse()
	if *binary == "" || *guard == "" || *artifacts == "" || *timeout <= 0 {
		flag.Usage()
		os.Exit(2)
	}
	active, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil || !contains(strings.Split(strings.TrimSpace(string(active)), ","), "bpf") {
		fmt.Println(`{"kind":"lsm_chain_result","status":"unsupported","reason":"BPF LSM is not active"}`)
		os.Exit(77)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	results, err := run(ctx, *binary, *guard, *artifacts)
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"kind": "lsm_chain_result", "status": "failed", "reason": err.Error(), "cases": results})
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"kind": "lsm_chain_result", "status": "passed", "file_open_attached": true, "cases": results})
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func openHelper(path string) error {
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(openResult{PID: os.Getpid()}); err != nil {
		return err
	}
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		return err
	}
	result := openResult{PID: os.Getpid()}
	file, err := os.Open(path)
	if err != nil {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			return err
		}
		result.Errno = int(errno)
	} else if err := file.Close(); err != nil {
		return err
	}
	return encoder.Encode(result)
}

func run(ctx context.Context, binary, guardPath, artifacts string) ([]openResult, error) {
	if err := os.MkdirAll(artifacts, 0755); err != nil {
		return nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpec(guardPath)
	if err != nil {
		return nil, fmt.Errorf("read guard object: %w", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load guard object: %w", err)
	}
	defer collection.Close()
	program := collection.Programs["chain_deny_file_open"]
	guardMap := collection.Maps["chain_guard_tgid"]
	if program == nil || guardMap == nil {
		return nil, fmt.Errorf("guard object lacks the chain program or target map")
	}
	guardLink, err := link.AttachLSM(link.LSMOptions{Program: program})
	if err != nil {
		return nil, fmt.Errorf("attach preceding LSM guard: %w", err)
	}
	defer guardLink.Close()

	workDir, err := os.MkdirTemp("", "ebpffls-lsm-chain-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(workDir)
	target := filepath.Join(workDir, "readable.data")
	if err := os.WriteFile(target, []byte("controlled LSM chain data\n"), 0644); err != nil {
		return nil, err
	}
	defer os.Remove(target)
	policy := filepath.Join(artifacts, "policy.yaml")
	data := fmt.Sprintf("name: lsm-chain-test\nwindow: 10s\nthreshold: 1000\naction: log\nprotected_dirs:\n  - %q\n", workDir)
	if err := os.WriteFile(policy, []byte(data), 0644); err != nil {
		return nil, err
	}
	logPath := filepath.Join(artifacts, "agent.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	defer logFile.Close()
	// App LSM links must be attached after the denying guard, or this is not a chain regression.
	agent := exec.CommandContext(ctx, binary, "monitor", "--config", policy)
	agent.Env = append(os.Environ(), "EBPFFLS_BPF_MODE=core")
	agent.Stdout, agent.Stderr = logFile, logFile
	if err := agent.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- agent.Wait(); close(done) }()
	defer func() {
		_ = agent.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = agent.Process.Kill()
			<-done
		}
	}()
	if err := waitReady(ctx, done, logPath); err != nil {
		return nil, err
	}
	var results []openResult
	for _, test := range []struct {
		name    string
		guarded bool
		errno   int
	}{
		{"guard_disabled_before", false, 0},
		{"prior_guard_denial_preserved", true, int(syscall.EACCES)},
		{"guard_disabled_after", false, 0},
	} {
		select {
		case err := <-done:
			return results, fmt.Errorf("app exited during LSM chain check: %v", err)
		default:
		}
		result, err := runOpen(ctx, guardMap, target, test.guarded)
		result.Name = test.name
		results = append(results, result)
		if err != nil {
			return results, fmt.Errorf("%s: %w", test.name, err)
		}
		if result.Errno != test.errno {
			return results, fmt.Errorf("%s returned errno=%d, expected=%d", test.name, result.Errno, test.errno)
		}
	}
	select {
	case err := <-done:
		return results, fmt.Errorf("app exited before LSM chain check completed: %v", err)
	default:
	}
	return results, nil
}

func waitReady(ctx context.Context, done <-chan error, logPath string) error {
	hooksPattern := regexp.MustCompile(`lsm_hooks="([^"]*)"`)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("app readiness: %w", ctx.Err())
		case err := <-done:
			return fmt.Errorf("app exited before LSM chain check: %v; see %s", err, logPath)
		case <-ticker.C:
			data, err := os.ReadFile(logPath)
			if err != nil {
				return err
			}
			text := string(data)
			if !strings.Contains(text, "started policy=lsm-chain-test") {
				continue
			}
			if !strings.Contains(text, "bpf_ready mode=core") {
				return fmt.Errorf("app silently changed runtime instead of starting core")
			}
			matches := hooksPattern.FindAllStringSubmatch(text, -1)
			for _, match := range matches {
				if contains(strings.Split(match[1], ","), "file_open") {
					return nil
				}
			}
			return fmt.Errorf("app started without an attached file_open LSM; guard alone cannot validate chaining")
		}
	}
}

func runOpen(ctx context.Context, guardMap *ebpf.Map, target string, guarded bool) (openResult, error) {
	self, err := os.Executable()
	if err != nil {
		return openResult{}, err
	}
	helper := exec.CommandContext(ctx, self, "__open-helper", target)
	stdout, err := helper.StdoutPipe()
	if err != nil {
		return openResult{}, err
	}
	stdin, err := helper.StdinPipe()
	if err != nil {
		return openResult{}, err
	}
	helper.Stderr = os.Stderr
	if err := helper.Start(); err != nil {
		return openResult{}, err
	}
	defer func() {
		_ = stdin.Close()
		if helper.ProcessState == nil {
			_ = helper.Process.Kill()
			_ = helper.Wait()
		}
	}()
	decoder := json.NewDecoder(stdout)
	var ready openResult
	if err := decoder.Decode(&ready); err != nil {
		return openResult{}, err
	}
	if ready.PID <= 0 || ready.PID != helper.Process.Pid {
		return ready, fmt.Errorf("helper process identity mismatch")
	}
	key, value := uint32(0), uint32(0)
	if guarded {
		value = uint32(ready.PID)
	}
	if err := guardMap.Put(key, value); err != nil {
		return ready, err
	}
	defer guardMap.Put(key, uint32(0))
	if _, err := stdin.Write([]byte("open\n")); err != nil {
		return ready, err
	}
	_ = stdin.Close()
	var result openResult
	if err := decoder.Decode(&result); err != nil {
		return result, err
	}
	if err := helper.Wait(); err != nil {
		return result, err
	}
	if result.PID != ready.PID {
		return result, fmt.Errorf("helper result changed process identity")
	}
	return result, nil
}

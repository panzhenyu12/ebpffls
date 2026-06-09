package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/panzhenyu/ebpffls/internal/agent"
	"github.com/panzhenyu/ebpffls/internal/config"
	"github.com/panzhenyu/ebpffls/internal/sensor"
	"github.com/spf13/pflag"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if err := run(os.Args[1:]); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "monitor":
		return monitor(args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func monitor(args []string) error {
	fs := pflag.NewFlagSet("monitor", pflag.ContinueOnError)
	configPath := fs.StringP("config", "c", "configs/ransomware.yaml", "policy config path")
	dryRun := fs.Bool("dry-run", true, "log detections without updating the kernel block map")
	debugEvents := fs.Bool("debug-events", false, "log raw eBPF events for troubleshooting")
	if err := fs.Parse(args); err != nil {
		return err
	}

	policy, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if policy.Action != "log" && policy.Action != "deny" && policy.Action != "kill" {
		return fmt.Errorf("unsupported action %q; use log, deny, or kill", policy.Action)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s, err := sensor.New(policy)
	if err != nil {
		return fmt.Errorf("%w; run as root and ensure BPF LSM is active in /sys/kernel/security/lsm", err)
	}
	defer s.Close()

	log.Printf("started policy=%s action=%s dry_run=%t window=%s threshold=%d", policy.Name, policy.Action, *dryRun, policy.Window, policy.Threshold)
	a := agent.New(policy, s, agent.Options{DryRun: *dryRun, DebugEvents: *debugEvents})
	return a.Run(ctx)
}

func usage() {
	fmt.Println(`ebpffls - eBPF anti-ransomware runtime guard

Usage:
  ebpffls monitor --config configs/ransomware.yaml [--dry-run=false]

Actions:
  log   detect and alert only
  deny  write TGID into the BPF LSM deny map
  kill  write TGID into the eBPF kill map and send SIGKILL on sensitive syscalls`)
}

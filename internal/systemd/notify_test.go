package systemd

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

func TestNewFromEnvDisabledWithoutNotifySocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	t.Setenv("WATCHDOG_USEC", "1000")
	if _, ok := NewFromEnv(); ok {
		t.Fatal("expected notifier to be disabled without NOTIFY_SOCKET")
	}
}

func TestReadyAndWatchdogNotifySocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ebpffls-systemd-test.")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)
	socket := dir + "/notify.sock"
	addr := &net.UnixAddr{Name: socket, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("listen notify socket: %v", err)
	}
	defer conn.Close()
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatalf("chmod notify socket: %v", err)
	}

	n := &Notifier{socket: socket, watchdog: 20 * time.Millisecond}
	if err := n.Ready(); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if got := readNotify(t, conn); got != "READY=1" {
		t.Fatalf("first notify = %q, want READY=1", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.StartWatchdog(ctx)
	if got := readNotify(t, conn); got != "WATCHDOG=1" {
		t.Fatalf("watchdog notify = %q, want WATCHDOG=1", got)
	}
}

func TestWatchdogInterval(t *testing.T) {
	n := &Notifier{watchdog: time.Second}
	if got := n.watchdogInterval(); got != 500*time.Millisecond {
		t.Fatalf("watchdog interval = %s, want 500ms", got)
	}
	n.watchdog = 0
	if got := n.watchdogInterval(); got != 0 {
		t.Fatalf("disabled interval = %s, want 0", got)
	}
}

func readNotify(t *testing.T, conn *net.UnixConn) string {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 128)
	n, _, err := conn.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("read notify socket: %v", err)
	}
	return string(buf[:n])
}

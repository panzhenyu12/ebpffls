package systemd

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Notifier struct {
	socket   string
	watchdog time.Duration
}

func NewFromEnv() (*Notifier, bool) {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil, false
	}
	return &Notifier{
		socket:   socket,
		watchdog: parseWatchdogUsec(os.Getenv("WATCHDOG_USEC")),
	}, true
}

func parseWatchdogUsec(raw string) time.Duration {
	if raw == "" {
		return 0
	}
	usec, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || usec <= 0 {
		return 0
	}
	return time.Duration(usec) * time.Microsecond
}

func (n *Notifier) Ready() error {
	return n.notify("READY=1")
}

func (n *Notifier) StartWatchdog(ctx context.Context) {
	interval := n.watchdogInterval()
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = n.notify("WATCHDOG=1")
		}
	}
}

func (n *Notifier) watchdogInterval() time.Duration {
	if n.watchdog <= 0 {
		return 0
	}
	interval := n.watchdog / 2
	if interval <= 0 {
		return time.Millisecond
	}
	return interval
}

func (n *Notifier) notify(state string) error {
	addr := notifyAddr(n.socket)
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

func notifyAddr(socket string) string {
	if strings.HasPrefix(socket, "@") {
		return "\x00" + strings.TrimPrefix(socket, "@")
	}
	return socket
}

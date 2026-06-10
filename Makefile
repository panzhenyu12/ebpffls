BINARY ?= ebpffls
GO ?= go

.PHONY: all generate build test integration-test clean bpftool

all: build

bpftool:
	@test -x "$$(command -v bpftool)" || (echo "bpftool is required" >&2; exit 1)

bpf/vmlinux.h: bpftool
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

generate:
	@test -f bpf/vmlinux.h || (echo "bpf/vmlinux.h is required for core CO-RE generation; use a checked-in minimal header or run 'make bpf/vmlinux.h' on a BTF-capable build host" >&2; exit 1)
	$(GO) generate ./...

build:
	$(GO) build -o bin/$(BINARY) ./cmd/ebpffls

test: generate
	$(GO) test ./...
	bash tests/systemd_unit.sh

integration-test: build test
	bash tests/integration.sh

clean:
	rm -rf bin
	rm -f bpf/vmlinux.h
	rm -f internal/sensor/*_bpfel.go internal/sensor/*_bpfeb.go
	rm -f internal/sensor/*.o

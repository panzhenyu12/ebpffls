BINARY ?= ebpffls
GO ?= go

.PHONY: all generate build clean bpftool

all: build

bpftool:
	@test -x "$$(command -v bpftool)" || (echo "bpftool is required" >&2; exit 1)

bpf/vmlinux.h: bpftool
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

generate: bpf/vmlinux.h
	$(GO) generate ./...

build: generate
	$(GO) build -o bin/$(BINARY) ./cmd/ebpffls

clean:
	rm -rf bin
	rm -f bpf/vmlinux.h
	rm -f internal/sensor/*_bpfel.go internal/sensor/*_bpfeb.go
	rm -f internal/sensor/*.o

FROM golang:1.24-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bpftool clang llvm libbpf-dev python3 rsync \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

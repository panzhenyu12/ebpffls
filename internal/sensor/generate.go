package sensor

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I../../bpf" ransomware ../../bpf/ransomware.bpf.c -- -I../../bpf

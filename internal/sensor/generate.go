package sensor

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I../../bpf" ransomware ../../bpf/ransomware.bpf.c -- -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -mcpu=v1 -I../../bpf" ransomwareLegacy ../../bpf/ransomware_legacy.bpf.c -- -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -mcpu=v1 -I../../bpf" ransomwareUltraLegacy ../../bpf/ransomware_ultra_legacy.bpf.c -- -I../../bpf

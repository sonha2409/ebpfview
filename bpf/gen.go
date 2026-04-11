package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang hello c/hello.c -- -Ic -Wall -Werror

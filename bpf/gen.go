package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang hello c/hello.c -- -Ic -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang flows c/flows.c -- -Ic -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang syscalllat c/syscall_lat.c -- -Ic -Wall -Werror
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang cpusample c/cpu_sample.c -- -Ic -Wall -Werror

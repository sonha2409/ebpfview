.PHONY: generate build test test-bpf lint clean

# Build output directory
BUILD_DIR := build
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -ldflags "-X main.version=$(VERSION)"

# BPF toolchain
CLANG     ?= clang
CFLAGS    := -O2 -g -Wall -Werror -target bpf

generate:
	go generate ./bpf/...

build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/ebpfview ./cmd/ebpfview/
	go build $(LDFLAGS) -o $(BUILD_DIR)/ebpfviewd ./cmd/ebpfviewd/

test:
	go test -count=1 ./...

test-bpf:
	go test -count=1 -tags integration -v ./...

lint:
	golangci-lint run ./...
	@if ls bpf/c/*.c 1>/dev/null 2>&1; then \
		echo "Running clang-tidy on BPF C files..."; \
		clang-tidy bpf/c/*.c -- $(CFLAGS); \
	fi

clean:
	rm -rf $(BUILD_DIR)
	rm -f bpf/*_bpfel.go bpf/*_bpfeb.go bpf/*_bpfel.o bpf/*_bpfeb.o

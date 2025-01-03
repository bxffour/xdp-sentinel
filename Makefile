all: build

.PHONY: build
build:
	cargo libbpf make

HEADERS="src/bpf"

.PHONY: vmlinux
vmlinux:
	mkdir -p $(HEADERS)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(HEADERS)/vmlinux.h

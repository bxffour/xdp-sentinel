all: build

.PHONY: build
build:
	cargo libbpf make

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h

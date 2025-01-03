all: build

.PHONY: build
build:
	cargo libbpf make

HEADERS="src/common/bpf/$(shell uname -i)"

.PHONY: vmlinux
vmlinux:
	mkdir -p $(HEADERS)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(HEADERS)/vmlinux.h

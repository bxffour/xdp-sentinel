#include "vmlinux.h"
#include "xdp_blocker_defs.h"

SEC("xdp")
__u32 xdp_test(struct xdp_md *xdp) {
  bpf_printk("hello from the other side");

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

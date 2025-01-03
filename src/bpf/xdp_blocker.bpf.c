#include "vmlinux.h"
#include "xdp_blocker_defs.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

void* lookup_elem(__u32 ipaddr)  {
  struct ipv4_lpm_key key = {
    .prefixlen = 32,
    .data = ipaddr
  };

  return bpf_map_lookup_elem(&block_list, &key);
}

SEC("xdp")
__u32 xdp_test(struct xdp_md *xdp) {
  void *data = (void*)(long)xdp->data;
  void *data_end = (void*)(long)xdp->data_end;

  struct ethhdr* eth = data;
  struct iphdr* iph;

  __u16 eth_proto;
  __u64 off;
  __be32* val;
  __u32 action = XDP_PASS;

  off = sizeof(struct ethhdr);
  if (data + off > data_end) {
    action = XDP_ABORTED;
    goto out;
  }

  eth_proto = eth->h_proto;
  if (eth_proto != BE_ETH_P_IP) {
    action = XDP_PASS;
    goto out;
  }

  iph = data + off;
  if (iph + 1 > data_end) {
    action = XDP_ABORTED;
    goto out;
  }

  val = lookup_elem(iph->saddr);
  if (val) {
    bpf_printk("xdp_blocker: found %pI4 in the block list, dropping packet", val);
    action = XDP_DROP;
    goto out;
  }

  out:
    return xdp_stats_record_action(xdp, action);
}

char _license[] SEC("license") = "GPL";

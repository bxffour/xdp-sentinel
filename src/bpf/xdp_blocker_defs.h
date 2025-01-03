#ifndef XDP_BLOCKER_DEFS_H
#define XDP_BLOCKER_DEFS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <sys/cdefs.h>

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710
// HELPER MACROS
#undef bpf_printk
#define bpf_printk(fmt, ...)                                                   \
  ({                                                                           \
    static const char ____fmt[] = fmt;                                         \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })

// STRUCTS
struct ipv4_lpm_key {
  __u32 prefixlen;
  __u32 data;
};

struct datarec {
  __u64 rx_packets;
  __u64 rx_bytes;
};

// MAPS
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct ipv4_lpm_key);
  __type(value, __u32);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 255);
} block_list SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(struct datarec));
  __uint(max_entries, XDP_ACTION_MAX);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_stats_map SEC(".maps");

// Functions
static __always_inline __u32 xdp_stats_record_action(struct xdp_md *xdp,
                                                     __u32 action) {
  if (action >= XDP_ACTION_MAX) {
    return XDP_ABORTED;
  }

  struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
  if (!rec) {
    return XDP_ABORTED;
  }

  rec->rx_packets += 1;
  rec->rx_bytes += (xdp->data_end - xdp->data);

  return action;
}
#endif

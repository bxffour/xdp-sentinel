#ifndef XDP_BLOCKER_DEFS_H
#define XDP_BLOCKER_DEFS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
// #include <linux/types.h>

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

// MAPS
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct ipv4_lpm_key);
  __type(value, __u32);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 255);
} block_list SEC(".maps");

#endif

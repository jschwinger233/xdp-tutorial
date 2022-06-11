import bcc

tc_stats_map = bcc.BPF(
    text=r"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>

struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

BPF_TABLE_PINNED("percpu_hash", __u32, struct datarec, tc_stats_map, TC_ACT_VALUE_MAX+1, "/sys/fs/bpf/tc_stats_map");
"""
).get_table("tc_stats_map")
for key, val in tc_stats_map.items():
    print(f"{key.value}: {val[0].rx_packets} {val[0].rx_bytes}")
    for v in val[1:]:
        print(f'{" "*3}{v.rx_packets} {v.rx_bytes}')

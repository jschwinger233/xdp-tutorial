#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>

struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

BPF_TABLE_PINNED("percpu_hash", __u32, struct datarec, tc_stats_map, TC_ACT_VALUE_MAX+1, "/sys/fs/bpf/tc_stats_map");

int tc_stats(struct __sk_buff *skb) {
    __u32 key = TC_ACT_OK;
    struct datarec *rec = tc_stats_map.lookup_or_try_init(&key, &(struct datarec){});
    if (!rec)
        return TC_ACT_SHOT;

    rec->rx_packets++;
    rec->rx_bytes += (long)skb->data_end - (long)skb->data;

    bpf_trace_printk("aaa\n");
    return TC_ACT_OK;
}

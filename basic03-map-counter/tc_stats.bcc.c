#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>

struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

BPF_PERCPU_HASH(tc_stats_map, __u32, struct datarec, TC_ACT_VALUE_MAX+1);

int tc_stats(struct __sk_buff *skb) {
    __u32 key = TC_ACT_OK;
    struct datarec *rec = tc_stats_map.lookup_or_try_init(&key, &(struct datarec){});
    if (!rec)
        return TC_ACT_SHOT;

    rec->rx_packets++;
    rec->rx_bytes += (long)skb->data_end - (long)skb->data;

    return TC_ACT_OK;
}

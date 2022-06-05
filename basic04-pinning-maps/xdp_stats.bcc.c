#include <uapi/linux/bpf.h>

#define XDP_ACTION_MAX (XDP_REDIRECT + 1)

struct datarec {
    u64 rx_packets;
    u64 rx_bytes;
};

BPF_TABLE_PINNED("percpu_hash", u32, struct datarec, xdp_stats_map, XDP_ACTION_MAX, "/sys/fs/bpf/xdp_stats_map");


int xdp_stats(struct xdp_md *ctx) {
    u32 key = XDP_PASS;
    struct datarec *rec = xdp_stats_map.lookup_or_try_init(
            &key, &(struct datarec){});
    if (rec == NULL) {
        return XDP_ABORTED;
    }

    rec->rx_packets++;
    rec->rx_bytes += ctx->data_end - ctx->data;
    return XDP_PASS;
}


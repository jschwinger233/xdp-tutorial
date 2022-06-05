#include <uapi/linux/bpf.h>

#define XDP_ACTION_MAX (XDP_REDIRECT + 1)

struct datarec {
    u64 rx_packets;
    u64 rx_bytes;
};

BPF_PERCPU_HASH(xdp_stats_map, u32, struct datarec, XDP_ACTION_MAX);

int xdp_stats(struct xdp_md *ctx) {
    u32 key = XDP_PASS;
    struct datarec *rec = xdp_stats_map.lookup_or_try_init(
            &key, &(struct datarec){});
    if (rec == NULL) {
        return XDP_ABORTED;
    }

    //__sync_fetch_and_add(&rec->rx_packets, 1);
    //__sync_fetch_and_add(&rec->rx_bytes, (u64)(ctx->data_end - ctx->data));
    rec->rx_packets++;
    rec->rx_bytes += ctx->data_end - ctx->data;
    return XDP_PASS;
}

#include <uapi/linux/bpf.h>

#define MAX_BUF_SIZE 450
#define min(a, b) (a) < (b) ? (a) : (b)

BPF_PERF_OUTPUT(buffer);

struct packet {
    u32 len;
};

int xdp_sample(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (data >= data_end) {
        return XDP_PASS;
    }
    struct packet pkt;
    __builtin_memset(&pkt, 0, sizeof(pkt));

    pkt.len = min(data_end - data, MAX_BUF_SIZE);
    buffer.perf_submit_skb(ctx, pkt.len, &pkt, sizeof(pkt));

    return XDP_PASS;
}

#include <uapi/linux/bpf.h>

#define MAX_BUF_SIZE 450

BPF_RINGBUF_OUTPUT(buffer, 1<<4);

struct packet {
    u8 content[MAX_BUF_SIZE];
    u16 len;
    bool truncate;
};

int xdp_sample(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (data >= data_end) {
        return XDP_PASS;
    }
    struct packet pkt;
    __builtin_memset(&pkt, 0, sizeof(pkt));

    pkt.len = data_end - data;
    if (pkt.len < 0) {
        pkt.len = 0;
    }
    if (pkt.len > MAX_BUF_SIZE) {
        pkt.len = MAX_BUF_SIZE;
        pkt.truncate = true;
    }

    if (pkt.len <= MAX_BUF_SIZE && pkt.len > 0 && data + pkt.len <= data_end) {
        bpf_probe_read_kernel(&pkt.content, pkt.len, data);
        if (buffer.ringbuf_output(&pkt, sizeof(pkt), BPF_RB_FORCE_WAKEUP) < 0) {
            bpf_trace_printk("failed to output ringbuf\n");
        }
    }

    return XDP_PASS;
}

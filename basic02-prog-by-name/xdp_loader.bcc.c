#include <uapi/linux/bpf.h>

int xdp_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}

int xdp_drop(struct xdp_md *ctx) {
    return XDP_DROP;
}

int xdp_abort(struct xdp_md *ctx) {
    return XDP_ABORTED;
}

#include <uapi/linux/bpf.h>

int xdp_abort(struct xdp_md *ctx) {
    return XDP_ABORTED;
}

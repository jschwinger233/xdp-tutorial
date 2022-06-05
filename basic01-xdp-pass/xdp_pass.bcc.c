#include <uapi/linux/bpf.h>

int xdp_prog_simple(struct xdp_md *ctx) {
    return XDP_PASS;
}

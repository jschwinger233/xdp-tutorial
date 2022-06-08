#include <uapi/linux/bpf.h>

BPF_PERCPU_HASH(xdp_stats_map, s32, u64, 50);

TRACEPOINT_PROBE(xdp, xdp_exception) {
    bpf_trace_printk("%ld\n", args->prog_id);
    if (args->act != XDP_ABORTED) {
        return 0;
    }

    s32 key = args->ifindex;
    u64 zero_val = 0;
    u64 *val = xdp_stats_map.lookup_or_try_init(&key, &zero_val);
    if (val == NULL) {
        return 0;
    }

    (*val)++;
    return 0;
}

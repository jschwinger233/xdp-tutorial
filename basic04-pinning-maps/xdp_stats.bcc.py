import os
import argparse

import bcc

parser = argparse.ArgumentParser(description="XDP loader")
parser.add_argument(
    "-d",
    "--dev",
    action="store",
    required=True,
)
parser.add_argument(
    "-p",
    "--progsec",
    action="store",
    required=True,
    help="load program in [section]",
)
parser.add_argument("-S", "--skb-mode", action="store_true")
parser.add_argument("-N", "--native-mode", action="store_true")
parser.add_argument("-O", "--offload-mode", action="store_true")
parser.add_argument("-F", "--force", action="store_true")
parser.add_argument("-U", "--unload", action="store_true")
parser.add_argument("-R", "--read-map", action="store_true")
parser.add_argument("filename", help="load program from [filename]")
args = parser.parse_args()

xdp_flags = bcc.BPF.XDP_FLAGS_UPDATE_IF_NOEXIST
if args.skb_mode:
    xdp_flags |= bcc.BPF.XDP_FLAGS_SKB_MODE
elif args.native_mode:
    xdp_flags |= bcc.BPF.XDP_FLAGS_HW_MODE
elif args.offload_mode:
    xdp_flags |= bcc.BPF.XDP_FLAGS_DRV_MODE
if args.force:
    xdp_flags &= ~bcc.BPF.XDP_FLAGS_UPDATE_IF_NOEXIST

if args.unload:
    bcc.BPF(text="").remove_xdp(args.dev)
    os._exit(0)

if args.read_map:
    xdp_stats_map = bcc.BPF(
        text=r"""
#include <uapi/linux/bpf.h>

#define XDP_ACTION_MAX (XDP_REDIRECT + 1)

struct datarec {
    u64 rx_packets;
    u64 rx_bytes;
};

BPF_TABLE_PINNED(
    "percpu_hash",
    u32,
    struct datarec,
    xdp_stats_map,
    XDP_ACTION_MAX,
    "/sys/fs/bpf/xdp_stats_map");
""").get_table("xdp_stats_map")
    for k, val in xdp_stats_map.items():
        print(f"{k.value}: {val[0].rx_packets} {val[0].rx_bytes}")
        for v in val[1:]:
            print(f'{" "*3}{v.rx_packets} {v.rx_bytes}')
    os._exit(0)

bpf = bcc.BPF(src_file=args.filename)
bpf.attach_xdp(
    args.dev,
    bpf.load_func(args.progsec, bcc.BPF.XDP),
    xdp_flags,
)

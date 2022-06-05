import os
import time
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

bpf = bcc.BPF(src_file=args.filename)

if args.unload:
    bpf.remove_xdp(args.dev)
    os._exit(0)

bpf.attach_xdp(
    args.dev,
    bpf.load_func(args.progsec, bcc.BPF.XDP),
    xdp_flags,
)
xdp_stats_map = bpf.get_table("xdp_stats_map")


while True:
    for k, val in xdp_stats_map.items():
        print(f'{k.value}: {val[0].rx_packets} {val[0].rx_bytes}')
        for v in val[1:]:
            print(f'{" "*3}{v.rx_packets} {v.rx_bytes}')
    time.sleep(1)

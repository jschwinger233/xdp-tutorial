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
    "--progsec",
    action="store",
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
else:
    bpf.attach_xdp(
        args.dev,
        bpf.load_func(args.progsec, bcc.BPF.XDP),
        xdp_flags,
    )

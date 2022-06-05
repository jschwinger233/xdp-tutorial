import argparse

import bcc

parser = argparse.ArgumentParser(description="Simple XDP prog doing XDP_PASS")
parser.add_argument(
    "-d",
    "--dev",
    action="store",
    required=True,
)
parser.add_argument("-S", "--skb-mode", action="store_true")
parser.add_argument("-N", "--native-mode", action="store_true")
parser.add_argument("-A", "--auto-mode", action="store_true")
parser.add_argument("-F", "--force", action="store_true")
parser.add_argument("-U", "--unload", action="store_true")
args = parser.parse_args()

xdp_flags = bcc.BPF.XDP_FLAGS_UPDATE_IF_NOEXIST
if args.skb_mode:
    xdp_flags |= bcc.BPF.XDP_FLAGS_SKB_MODE
elif args.native_mode:
    xdp_flags |= bcc.BPF.XDP_FLAGS_HW_MODE
if args.force:
    xdp_flags |= bcc.BPF.XDP_FLAGS_REPLACE
if args.force:
    xdp_flags &= ~bcc.BPF.XDP_FLAGS_UPDATE_IF_NOEXIST

src_file = f"{__file__[:-3]}.c"
bpf = bcc.BPF(src_file=src_file)

if args.unload:
    bpf.remove_xdp(args.dev)
else:
    bpf.attach_xdp(
        args.dev, bpf.load_func("xdp_prog_simple", bcc.BPF.XDP), xdp_flags
    )

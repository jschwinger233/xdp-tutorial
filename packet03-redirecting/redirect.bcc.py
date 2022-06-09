import os
import ctypes
import argparse

import bcc
import pyroute2

parser = argparse.ArgumentParser(description="XDP loader")
parser.add_argument(
    "--dev1",
    action="store",
    required=True,
)
parser.add_argument(
    "--dev2",
    action="store",
    required=True,
)
parser.add_argument(
    "--dev1-source-mac",
    action="store",
    required=True,
)
parser.add_argument(
    "--dev2-source-mac",
    action="store",
    required=True,
)
parser.add_argument("-U", "--unload", action="store_true")
args = parser.parse_args()

filename = __file__[:-2] + "c"
bpf = bcc.BPF(src_file=filename)

if args.unload:
    bpf.remove_xdp(args.dev1, 0)
    bpf.remove_xdp(args.dev2, 0)
    os._exit(0)

else:
    bpf.attach_xdp(
        args.dev1,
        bpf.load_func("xdp_redirect_map", bcc.BPF.XDP),
        0,
    )
    bpf.attach_xdp(
        args.dev2,
        bpf.load_func("xdp_redirect_map", bcc.BPF.XDP),
        0,
    )

    devmap = bpf.get_table("devmap")
    devmap[0] = ctypes.c_int(
        pyroute2.IPRoute().link_lookup(ifname=args.dev1)[0]
    )
    devmap[1] = ctypes.c_int(
        pyroute2.IPRoute().link_lookup(ifname=args.dev2)[0]
    )

    class RedirectKey(ctypes.Structure):
        _fields_ = [
            ("mac", ctypes.c_char * 6),
        ]

    class RedirectTarget(ctypes.Structure):
        _fields_ = [
            ("devindex", ctypes.c_int),
            ("mac", ctypes.c_char * 6),
        ]

    redirect_map = bpf.get_table("redirect_map")
    mac1 = bytes([int(x, 16) for x in args.dev1_source_mac.split(":")])
    mac2 = bytes([int(x, 16) for x in args.dev2_source_mac.split(":")])
    redirect_map[RedirectKey(mac2)] = RedirectTarget(0, mac1)
    redirect_map[RedirectKey(mac1)] = RedirectTarget(1, mac2)

    while True:
        bpf.trace_print()

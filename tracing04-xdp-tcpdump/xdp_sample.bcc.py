import os
import ctypes
import argparse

import bcc
from scapy.layers import l2
from scapy.all import wrpcap

parser = argparse.ArgumentParser(description="XDP loader")
parser.add_argument(
    "-d",
    "--dev",
    action="store",
    required=True,
)
parser.add_argument(
    "-o",
    "--output",
    action="store",
    required=True,
)
parser.add_argument("-U", "--unload", action="store_true")
args = parser.parse_args()

filename = __file__[:-2] + "c"
bpf = bcc.BPF(src_file=filename)

if args.unload:
    bpf.remove_xdp(args.dev, 0)
    os._exit(0)

else:
    bpf.attach_xdp(
        args.dev,
        bpf.load_func("xdp_sample", bcc.BPF.XDP),
        0,
    )

    class Packet(ctypes.Structure):
        _fields_ = [
            ("content", ctypes.c_uint8 * 450),
            ("len", ctypes.c_uint16),
            ("truncate", ctypes.c_bool),
        ]

    def callback(ctx, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Packet)).contents
        packet = l2.Ether(event.content[: event.len])
        wrpcap(args.output, packet, append=True)

    bpf["buffer"].open_ring_buffer(callback)

    while True:
        bpf.ring_buffer_poll()

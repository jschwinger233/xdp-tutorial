import os
import argparse
import subprocess
import contextlib

import bcc
import pyroute2

parser = argparse.ArgumentParser(description="TC loader")
parser.add_argument(
    "-i",
    "--iface",
    action="store",
    required=True,
)
parser.add_argument(
    "-s",
    "--section",
    action="store",
    required=True,
)
parser.add_argument(
    "-d",
    "--direction",
    choices=["ingress", "egress"],
    required=True,
)
parser.add_argument("-f", "--force", action="store_true")
parser.add_argument("-u", "--unload", action="store_true")
parser.add_argument("filename")
args = parser.parse_args()

bpf = bcc.BPF(src_file=args.filename)

ipr = pyroute2.IPRoute()
iface_idx = ipr.link_lookup(ifname=args.iface)[0]

parent = "ffff:fff2"  # ingress
if args.direction == "egress":
    parent = "ffff:fff3"

if args.unload or args.force:
    subprocess.call(f"tc filter del dev {args.iface} {args.direction}".split())

    if args.unload:
        os._exit(0)

func = bpf.load_func(args.section, bcc.BPF.SCHED_CLS)

with contextlib.suppress(pyroute2.netlink.exceptions.NetlinkError):
    ipr.tc("add", "clsact", iface_idx)

ipr.tc(
    "add-filter",
    "bpf",
    iface_idx,
    ":1",
    fd=func.fd,
    name=func.name,
    parent=parent,
    classid=1,
    direct_action=True,
)

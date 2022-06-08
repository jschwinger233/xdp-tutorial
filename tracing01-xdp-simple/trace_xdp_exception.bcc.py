import time

import bcc

bpf = bcc.BPF(src_file="./trace_xdp_exception.bcc.c")

xdp_stats_map = bpf.get_table("xdp_stats_map")
while True:
    for k, val in xdp_stats_map.items():
        print(f"devidx {k.value}: {val[0]}")
        for v in val[1:]:
            print(f'{" "*10}{v}')
    time.sleep(1)

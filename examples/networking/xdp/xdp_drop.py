#!/usr/bin/python3
#
# xdp_drop.py Count incoming packet and drop
#
# Copyright (c) 2021 Federico Parola
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import time
import sys
import ctypes as ct
import argparse

parser = argparse.ArgumentParser(description='Count incoming packet and drop.')
parser.add_argument('dev', type=str, help='input interface')
parser.add_argument('-t', dest='touch', action='store_true',
                    help='touch packet (mac addr swap)')
args = parser.parse_args()

flags = 0

# load BPF program
b = BPF(text = """
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>

BPF_PERCPU_ARRAY(rxcnt, long, 1);

static inline void swap_src_dst_mac(void *data)
{
    unsigned short *p = data;
    unsigned short dst[3];

    dst[0] = p[0];
    dst[1] = p[1];
    dst[2] = p[2];
    p[0] = p[3];
    p[1] = p[4];
    p[2] = p[5];
    p[3] = dst[0];
    p[4] = dst[1];
    p[5] = dst[2];
}

int xdp_drop(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    uint32_t key = 0;
    long *value;
    uint64_t nh_off;

    nh_off = sizeof(*eth);
    if (data + nh_off  > data_end)
        return XDP_DROP;

    value = rxcnt.lookup(&key);
    if (value)
        *value += 1;

#if SWAP
    swap_src_dst_mac(data);
#endif

    return XDP_DROP;
}
""", cflags=["-w", f"-DSWAP={int(args.touch)}"])

fn = b.load_func("xdp_drop", BPF.XDP)

b.attach_xdp(args.dev, fn, flags)

rxcnt = b.get_table("rxcnt")
prev = {}
cum = 0
print("Printing redirected packets, hit CTRL+C to stop")
while 1:
    try:
        val = rxcnt[0]
        tot = 0
        for i, v in enumerate(val):
            if not (i in prev):
                delta = v
            else:
                delta = v - prev[i]
            if delta > 0:
                print("Core %d: %d pkt/s" % (i, delta))
                prev[i] = v
                tot += delta
        cum += tot
        print("Total: %d pkt/s" % (tot))
        print("Cum: %d pkt\n" % (cum))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break;

b.remove_xdp(args.dev, flags)

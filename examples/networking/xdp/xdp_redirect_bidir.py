#!/usr/bin/python
#
# xdp_redirect_map.py Redirect the incoming packet to another interface
#                     with the helper: bpf_redirect_map()
#
# Copyright (c) 2018 Gary Lin
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2
import time
import sys
import ctypes as ct

XDP_FLAGS_SKB_MODE = 1 << 1
XDP_FLAGS_DRV_MODE = 1 << 2

def usage():
    print("Usage: {0} <ifdev1> <ifdev2>".format(sys.argv[0]))
    print("e.g.: {0} eth0 eth1\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 3:
    usage()

if1 = sys.argv[1]
if2 = sys.argv[2]

ip = pyroute2.IPRoute()
ifindex1 = ip.link_lookup(ifname=if1)[0]
ifindex2 = ip.link_lookup(ifname=if2)[0]

# load BPF program
b = BPF(text = """
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>

BPF_DEVMAP(tx_port, 1024);
BPF_PERCPU_ARRAY(rxcnt, long, 1);

int xdp_redirect_map(struct xdp_md *ctx) {
    uint32_t key = 0;
    long *value;

    value = rxcnt.lookup(&key);
    if (value)
        *value += 1;

    int ret = tx_port.redirect_map(ctx->ingress_ifindex, 0);
    bpf_trace_printk("Redirect from %d returned %d", ctx->ingress_ifindex,
                     ret);
    return ret;
}
""", cflags=["-w"])

tx_port = b.get_table("tx_port")
tx_port[ifindex1] = ct.c_int(ifindex2)
tx_port[ifindex2] = ct.c_int(ifindex1)

fn = b.load_func("xdp_redirect_map", BPF.XDP)

flags1 = XDP_FLAGS_DRV_MODE
flags2 = XDP_FLAGS_DRV_MODE
b.attach_xdp(if1, fn, flags1)
b.attach_xdp(if2, fn, flags2)

rxcnt = b.get_table("rxcnt")
prev = 0
print("Printing redirected packets, hit CTRL+C to stop")
while 1:
    try:
        val = rxcnt.sum(0).value
        if val:
            delta = val - prev
            prev = val
            print("{} pkt/s".format(delta))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break;

b.remove_xdp(if1, flags1)
b.remove_xdp(if2, flags2)

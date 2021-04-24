#!/usr/bin/python3

from bcc import BPF
import argparse
import pyroute2
import time
import ctypes as ct

parser = argparse.ArgumentParser()
parser.add_argument('input_if', help='Input interface')
parser.add_argument('output_if', help='Output interface')
parser.add_argument('iterations', help='Number of times the UDP checksum is recomputed')
args = parser.parse_args()

ip = pyroute2.IPRoute()
out_ifindex = ip.link_lookup(ifname=args.output_if)[0]

# Prepare program
b = BPF(src_file='checksummer.c',
        cflags=[f"-DOUTPUT_IFINDEX={out_ifindex}",
                f"-DITERATIONS={args.iterations}"])

# Attach program to interfaces
fn = b.load_func("checksummer", BPF.XDP)
b.attach_xdp(args.input_if, fn, 0)
dummy = b.load_func("dummy", BPF.XDP)
b.attach_xdp(args.output_if, dummy, 0)

print("Checksumming packets, hit CTRL+C to stop")
rxcnt = b.get_table("rxcnt")
prev = {}
cum = 0
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
        break

b.remove_xdp(args.input_if, 0)
b.remove_xdp(args.output_if, 0)
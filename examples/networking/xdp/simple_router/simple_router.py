#!/usr/bin/python3

from bcc import BPF
import argparse
import pyroute2
import time
import sys
import socket
import ctypes as ct

FIB_SIZE = 10000000
ARP_SIZE = 128

def str_to_ctype_mac(mac_str):
    bytes_ = mac_str.split(':')
    return (ct.c_ubyte * 6)(int(bytes_[0], 16), int(bytes_[1], 16),
                            int(bytes_[2], 16), int(bytes_[3], 16),
                            int(bytes_[4], 16), int(bytes_[5], 16))

parser = argparse.ArgumentParser()
parser.add_argument('interfaces', nargs='+', help='Interfaces to handle')
args = parser.parse_args()

ip = pyroute2.IPRoute()
ifindexes = []
for iface in args.interfaces:
    ifindexes.append(ip.link_lookup(ifname=iface)[0])

# Prepare program
b = BPF(src_file='simple_router.c',
        cflags=[f"-DFIB_SIZE={FIB_SIZE}", f"-DARP_SIZE={ARP_SIZE}"])

# Populate tables
arp_table = b.get_table("arp_table")
count = 0
with open('arp_entries.csv', 'r') as arp_entries:
    for line in arp_entries:
        daddr = socket.inet_aton(line.split(';')[0])
        dmac = str_to_ctype_mac(line.split(';')[1])
        smac = str_to_ctype_mac(line.split(';')[2])
        egress_ifindex = ip.link_lookup(ifname=line.split(';')[3].strip())[0]
        leaf = arp_table.Leaf(dmac, smac, egress_ifindex)
        arp_table[ct.c_uint(int.from_bytes(daddr, 'little'))] = leaf
        count += 1
print(f'Loaded {count} arp entries')

fib = b.get_table("fib")
count = 0
with open('routes.csv', 'r') as routes:
    for line in routes:
        daddr = socket.inet_aton(line.split(';')[0])
        next_hop = socket.inet_aton(line.split(';')[1])
        key = fib.Key(int.from_bytes(daddr, 'little'))
        leaf = fib.Leaf(int.from_bytes(next_hop, 'little'))
        fib[key] = leaf
        count += 1
        if count > 0 and count % 1000000 == 0:
            print(f'Loaded {count} routes')
print(f'Loaded {count} routes')

# Attach program to interfaces
fn = b.load_func("router", BPF.XDP)
for iface in args.interfaces:
    b.attach_xdp(iface, fn, 0)

print("Routing packets, hit CTRL+C to stop")
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

for iface in args.interfaces:
    b.remove_xdp(iface, 0)
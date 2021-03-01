#!/usr/bin/python3

from bcc import BPF
import argparse
import pyroute2
import socket
import time

BPF_SOURCE_FILE = 'traffic_monitoring.c'
ETHTYPE_2_PROTO = {
    socket.ntohs(0x0800): 'IPv4',
    socket.ntohs(0x0806): 'ARP',
    socket.ntohs(0x86dd): 'IPv6'
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser('Monitors traffic flowing through a network interface and prints various statistics')
    parser.add_argument('interface', help='Network interface to monitor',
                        type=str)
    args = parser.parse_args()

    ifname= args.interface

    ip = pyroute2.IPRoute()
    ifindex = ip.link_lookup(ifname=ifname)[0]

    b = BPF(src_file=BPF_SOURCE_FILE)

    l3protos_counter = b.get_table("l3protos_counter")
    fn = b.load_func("monitor", BPF.SCHED_CLS)

    ip.tc("add", "clsact", ifindex)

    try:
        ip.tc("add-filter", "bpf", ifindex, ":1", fd=fn.fd, name=fn.name,
            parent="ffff:fff2", classid=1, direct_action=True)
        ip.tc('add-filter', 'bpf', ifindex, ':1', fd=fn.fd, name=fn.name,
            parent='ffff:fff3', classid=1, direct_action=True)

        print("Monitoring traffic, hit CTRL+C to stop")
        while 1:
            try:
                time.sleep(5)

                print(time.strftime('\n%H.%M.%S:'))

                for value in l3protos_counter.values():
                    proto = ETHTYPE_2_PROTO.get(
                            value.ethtype,
                            f'Unknown (0x{socket.htons(value.ethtype):04x})')
                    print(f'{value.count} packets for protocol {proto}')

            except KeyboardInterrupt:
                print("Removing filter from device")
                break

    finally:
        ip.tc("del", "clsact", ifindex)
#!/usr/bin/python

from bcc import BPF
import pyroute2
import time
import sys
import ctypes as ct

bpf_txt = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/if_ether.h>

// #define DEBUG 1

BPF_ARRAY(tx_port, int, 1);
BPF_PERCPU_ARRAY(rxcnt, long, 1);
BPF_PROG_ARRAY(progs, 1024);

static void swap_src_dst_mac(void *data)
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

int tc_redirect_prog_0(struct __sk_buff *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int rc = TC_ACT_SHOT;
	int *ifindex, port = 0;
	long *value;
	u32 key = 0;
	u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	ifindex = tx_port.lookup(&port);
	if (!ifindex)
		return rc;

	value = rxcnt.lookup(&key);
	if (value)
		*value += 1;

	swap_src_dst_mac(data);
	return bpf_redirect(*ifindex, 0);
}

int tc_redirect_prog_1(struct __sk_buff *ctx)
{
#ifdef DEBUG
	bpf_trace_printk("Jumping to prog 0\\n");
#endif

	progs.call(ctx, 0);

	bpf_trace_printk("Tail call failed in prog 1\\n");

	return TC_ACT_SHOT;
}

int tc_redirect_prog_2(struct __sk_buff *ctx)
{
#ifdef DEBUG
	bpf_trace_printk("Jumping to prog 1\\n");
#endif

	progs.call(ctx, 1);

	bpf_trace_printk("Tail call failed in prog 2\\n");

	return TC_ACT_SHOT;
}

int tc_redirect_prog_3(struct __sk_buff *ctx)
{
#ifdef DEBUG
	bpf_trace_printk("Jumping to prog 2\\n");
#endif

	progs.call(ctx, 2);

	bpf_trace_printk("Tail call failed in prog 3\\n");

	return TC_ACT_SHOT;
}

int tc_redirect_prog_4(struct __sk_buff *ctx)
{
#ifdef DEBUG
	bpf_trace_printk("Jumping to prog 3\\n");
#endif

	progs.call(ctx, 3);

	bpf_trace_printk("Tail call failed in prog 4\\n");

	return TC_ACT_SHOT;
}

int tc_redirect_prog_5(struct __sk_buff *ctx)
{
#ifdef DEBUG
	bpf_trace_printk("Jumping to prog 4\\n");
#endif

	progs.call(ctx, 4);

	bpf_trace_printk("Tail call failed in prog 5\\n");

	return TC_ACT_SHOT;
}

int tc_redirect_prog_6(struct __sk_buff *ctx)
{
#ifdef DEBUG
	bpf_trace_printk("Jumping to prog 5\\n");
#endif

	progs.call(ctx, 5);

	bpf_trace_printk("Tail call failed in prog 6\\n");

	return TC_ACT_SHOT;
}

int tc_redirect_prog_7(struct __sk_buff *ctx)
{
#ifdef DEBUG
	bpf_trace_printk("Jumping to prog 6\\n");
#endif

	progs.call(ctx, 6);

	bpf_trace_printk("Tail call failed in prog 7\\n");

	return TC_ACT_SHOT;
}

int tc_redirect_prog_8(struct __sk_buff *ctx)
{
#ifdef DEBUG
	bpf_trace_printk("Jumping to prog 7\\n");
#endif

	progs.call(ctx, 7);

	bpf_trace_printk("Tail call failed in prog 8\\n");

	return TC_ACT_SHOT;
}

int tc_redirect_prog_9(struct __sk_buff *ctx)
{
#ifdef DEBUG
	bpf_trace_printk("Jumping to prog 8\\n");
#endif

	progs.call(ctx, 8);

	bpf_trace_printk("Tail call failed in prog 9\\n");

	return TC_ACT_SHOT;
}"""

flags = 0
def usage():
    print("Usage: {0} <in ifdev> <out ifdev> <chain size>".format(sys.argv[0]))
    print("e.g.: {0} eth0 eth1 5\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 4:
    usage()

in_if = sys.argv[1]
out_if = sys.argv[2]
chain_size = int(sys.argv[3])

ip = pyroute2.IPRoute()
in_idx = ip.link_lookup(ifname=in_if)[0]
out_idx = ip.link_lookup(ifname=out_if)[0]

b = BPF(text=bpf_txt)

tx_port = b.get_table("tx_port")
tx_port[0] = ct.c_int(out_idx)
progs = b.get_table("progs")
rxcnt = b.get_table("rxcnt")

programs = []
for i in range(chain_size):
    programs.append(b.load_func("tc_redirect_prog_%d" % (i), BPF.SCHED_CLS))
    progs[i] = ct.c_int(programs[i].fd)

ip.tc("add", "clsact", in_idx)

try:
    ip.tc("add-filter", "bpf", in_idx, ":1", fd=programs[-1].fd, name=programs[-1].name,
          parent="ffff:fff2", classid=1, direct_action=True)

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
            break

finally:
    ip.tc("del", "clsact", in_idx)
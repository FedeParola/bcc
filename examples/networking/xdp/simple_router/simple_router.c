#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct fib_key {
    __be32 daddr;
};

struct fib_value {
    __be32 next_hop;
};

BPF_HASH(fib, struct fib_key, struct fib_value, FIB_SIZE);

struct arp_value {
    unsigned char dmac[ETH_ALEN];
    unsigned char smac[ETH_ALEN];
    __u32 egress_ifindex;
};

BPF_HASH(arp_table, __be32, struct arp_value, ARP_SIZE);

BPF_PERCPU_ARRAY(rxcnt, __u64, 1);

// From include/net/ip.h
static __always_inline int ip_decrease_ttl(struct iphdr *iph) {
	__u32 check = iph->check;

	check += htons(0x0100);
	iph->check = (check + (check >= 0xFFFF));
	return --iph->ttl;
}

int router(struct xdp_md *ctx) {
    int zero = 0;
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    __u64 *count = rxcnt.lookup(&zero);
    if (!count) {
        return XDP_ABORTED;
    }
    (*count)++;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_ABORTED;
    }

    if (eth->h_proto != htons(ETH_P_IP)) {
        // Don't handle
        return XDP_DROP;
    }

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_ABORTED;
    }

    struct fib_key fib_key = { .daddr = iph->daddr };
    struct fib_value *fib_value = fib.lookup(&fib_key);
    if (!fib_value) {
        // Don't handle
        return XDP_DROP;
    }

    struct arp_value *arp_value = arp_table.lookup(&fib_value->next_hop);
    if (!arp_value) {
        // Don't handle
        return XDP_DROP;
    }

    if (iph->ttl <= 1) {
        // Don't handle
        return XDP_DROP;
    }
    ip_decrease_ttl(iph);

    memcpy(eth->h_dest, arp_value->dmac, ETH_ALEN);
    memcpy(eth->h_source, arp_value->smac, ETH_ALEN);

    return bpf_redirect(arp_value->egress_ifindex, 0);
}
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define MAX_UDP_LENGTH 1480

BPF_PERCPU_ARRAY(rxcnt, __u64, 1);

int checksummer(struct xdp_md *ctx) {
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

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_ABORTED;
    }

    if (ip->protocol != IPPROTO_UDP) {
        // Don't handle
        return XDP_DROP;
    }

    struct udphdr *udp = (void *)ip + (ip->ihl << 2);
    if ((void *)(udp + 1) > data_end) {
        return XDP_ABORTED;
    }

    u32 csum_buffer;
    u16 csum;
    u16 *buf;

    for (int i = 0; i < ITERATIONS; i++) {
        csum_buffer = 0;
        buf = (void *)udp;

        // Compute pseudo-header checksum
        csum_buffer += (u16)ip->saddr;
        csum_buffer += (u16)(ip->saddr >> 16);
        csum_buffer += (u16)ip->daddr;
        csum_buffer += (u16)(ip->daddr >> 16);
        csum_buffer += (u16)ip->protocol << 8;
        csum_buffer += udp->len;

        // Clean old checksum
        udp->check = 0;

        // Compute checksum on udp header + payload
        for (int j = 0; j < MAX_UDP_LENGTH; j += 2) {
            if ((void *)(buf + 1) > data_end) {
                break;
            }
            csum_buffer += *buf;
            buf++;
        }
        if ((void *)buf + 1 <= data_end) {
            // In case payload is not 2 bytes aligned
            csum_buffer += *(u8 *)buf;
        }

        csum = (u16)csum_buffer + (u16)(csum_buffer >> 16);
        csum = ~csum;
    }

    udp->check = csum;

    return bpf_redirect(OUTPUT_IFINDEX, 0);
}

int dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}
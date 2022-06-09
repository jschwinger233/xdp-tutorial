#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

u16 static _adjust_checksum2(u16 checksum, u16 from, u16 to) {
    checksum = ~checksum;
    u32 csum = checksum;
    csum -= from;
    csum += to;
    csum = (csum>>16) + (csum&0xffff);
    return ~(u16)csum;
}

u16 static fold_checksum(u32 csum) {
    u32 sum;
    sum = (csum>>16) + (csum&0xffff);
    sum += (sum>>16);
    return ~sum;

}

int xdp_icmp_echo_func(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) <= data_end && eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) <= data_end && ip->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmp = data + sizeof(*eth) + sizeof(*ip);
            if ((void*)icmp + sizeof(*icmp) <= data_end && icmp->type == ICMP_ECHO) {
                char h_source[ETH_ALEN];
                __builtin_memcpy(h_source, eth->h_source, ETH_ALEN);
                __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
                __builtin_memcpy(eth->h_dest, h_source, ETH_ALEN);
                u32 saddr = ip->saddr;
                ip->saddr = ip->daddr;
                ip->daddr = saddr;

                struct icmphdr icmp_old;
                __builtin_memcpy(&icmp_old, icmp, sizeof(*icmp));
                icmp->type = ICMP_ECHOREPLY;
                icmp->checksum = fold_checksum(
                        bpf_csum_diff(&icmp_old, sizeof(*icmp), icmp, sizeof(*icmp), ~icmp->checksum));
                //icmp->checksum = _adjust_checksum2(icmp->checksum, ICMP_ECHO, ICMP_ECHOREPLY);
                return XDP_TX;
            }
        }
    }
    return XDP_PASS;
}

int xdp_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}


static char mac1[ETH_ALEN] = "\xaa" "\x73" "\xaf" "\x5c" "\x0c" "\x70";
static u32 ifindex1 = 58;
static char mac2[ETH_ALEN] = "\x66" "\x35" "\x2a" "\xd8" "\xf0" "\x6b";
static u32 ifindex2 = 56;

int xdp_redirect_1to2(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) < data_end) {
        __builtin_memcpy(eth->h_dest, mac2, ETH_ALEN);
        return bpf_redirect(ifindex2, 0);
    }

    return XDP_PASS;
}

int xdp_redirect_2to1(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) < data_end) {
        __builtin_memcpy(eth->h_dest, mac1, ETH_ALEN);
        return bpf_redirect(ifindex1, 0);
    }

    return XDP_PASS;
}

struct redirect_key {
    char mac[ETH_ALEN];
};

struct redirect_target {
    int devindex;
    char mac[ETH_ALEN];
};

BPF_HASH(redirect_map, struct redirect_key, struct redirect_target);
BPF_DEVMAP(devmap, 2);

int xdp_redirect_map(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) < data_end) {
        struct redirect_key rk;
        __builtin_memcpy(rk.mac, eth->h_source, ETH_ALEN);
        struct redirect_target *rt = redirect_map.lookup(&rk);
        if (rt != NULL) {
            __builtin_memcpy(eth->h_dest, rt->mac, ETH_ALEN);
            return devmap.redirect_map(rt->devindex, 0);
        }
    }
    return XDP_PASS;
}

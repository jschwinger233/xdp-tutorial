#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct vlanhdr {
	u16	TCI;
	u16	h_proto;
};

int xdp_port_rewrite(struct xdp_md *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) <= data_end && eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) <= data_end && ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
            if ((void*)tcp + sizeof(*tcp) <= data_end) {
                bpf_trace_printk("mangle tcp sport: %d\n", ntohs(tcp->source));
                tcp->source  = htons(ntohs(tcp->source)-1);
            }
        }
    }
    return XDP_PASS;
}

int static _insert_vlan(struct xdp_md *ctx) {
    struct ethhdr *eth = (void*)(long)ctx->data;
    struct ethhdr eth_cp;
    memcpy(&eth_cp, eth, sizeof(*eth));

    if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlanhdr)) < 0) {
        bpf_trace_printk("failed to adjust xdp by -4\n");
        return XDP_PASS;
    };

    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    eth = data;
    if ((void*)eth + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    memcpy(eth, &eth_cp, sizeof(eth_cp));

    struct vlanhdr *vlan = data + sizeof(*eth);
    if ((void*)vlan + sizeof(*vlan) > data_end) {
        return XDP_PASS;
    }

    vlan->h_proto = eth->h_proto;
    vlan->TCI = htons(2);
    eth->h_proto = htons(ETH_P_8021Q);

    bpf_trace_printk("push vlan tag 2\n");
    return XDP_PASS;
}

int static _strip_vlan(struct xdp_md *ctx, u16 h_proto) {
    struct ethhdr *eth = (void*)(long)ctx->data;
    struct ethhdr eth_cp;
    memcpy(&eth_cp, eth, sizeof(*eth));

    if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct vlanhdr)) < 0) {
        bpf_trace_printk("failed to adjust xdp by +4\n");
        return XDP_PASS;
    };

    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    eth = data;
    if ((void*)eth + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    memcpy(eth, &eth_cp, sizeof(eth_cp));
    eth->h_proto = h_proto;
    return XDP_PASS;
}

int xdp_vlan_swap(struct xdp_md *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto == htons(ETH_P_8021Q)) {
        struct vlanhdr *vlan = data + sizeof(*eth);
        if ((void*)vlan + sizeof(*vlan) < data_end) {
            return _strip_vlan(ctx, vlan->h_proto);
        }
    } else {
        return _insert_vlan(ctx);
    }
    return XDP_PASS;
}

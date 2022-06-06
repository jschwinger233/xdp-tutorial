#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

struct vlanhdr {
	__be16	TCI;
	__be16	proto;
};

int static handle_ipv6(void *data_l3, void *data_end) {
    struct ipv6hdr *ipv6 = data_l3;
    if ((void*)ipv6 + sizeof(*ipv6) > data_end) {
        return XDP_PASS;
    }

    if (ipv6->nexthdr != IPPROTO_ICMPV6) {
        return XDP_PASS;
    }

    struct icmp6hdr *icmp6 = data_l3 + sizeof(*ipv6);
    if ((void*)icmp6 + sizeof(*icmp6) > data_end) {
        return XDP_PASS;
    }

    if (ntohs(icmp6->icmp6_dataun.u_echo.sequence) % 2 == 0) {
        bpf_trace_printk("drop icmp6 seq %ld\n", ntohs(icmp6->icmp6_dataun.u_echo.sequence));
        return XDP_DROP;
    }

    return XDP_PASS;
}

int static handle_ipv4(void *data_l3, void *data_end) {
    struct iphdr *ip = data_l3;
    if ((void*)ip + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_ICMP) {
        return XDP_PASS;
    }

    struct icmphdr *icmp = data_l3 + sizeof(*ip);
    if ((void*)icmp + sizeof(*icmp) > data_end) {
        return XDP_PASS;
    }

    if (ntohs(icmp->un.echo.sequence) % 2 == 0) {
        bpf_trace_printk("drop icmp4 seq %ld\n", ntohs(icmp->un.echo.sequence));
        return XDP_DROP;
    }

    return XDP_PASS;
}

int xdp_packet_parser(struct xdp_md *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    void *cursor = data + sizeof(*eth);
    u16 h_proto = eth->h_proto;

    for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
        if (h_proto != htons(ETH_P_8021Q)) {
            break;
        }
        struct vlanhdr *vlan = cursor;
        if ((void*)vlan + sizeof(*vlan) > data_end) {
            return XDP_PASS;
        }
        h_proto = vlan->proto;
        cursor += sizeof(*vlan);
    }

    switch (h_proto) {
        case htons(ETH_P_IP):
            return handle_ipv4(cursor, data_end);
        case htons(ETH_P_IPV6):
            return handle_ipv6(cursor, data_end);
    }
    return XDP_PASS;
}


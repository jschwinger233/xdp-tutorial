#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

int static _tc_parse_ipv4(void *data_l3, void *data_end) {
    struct iphdr *ip = data_l3;
    if ((void*)ip + sizeof(*ip) > data_end || ip->protocol != IPPROTO_ICMP)
        return TC_ACT_OK;

    struct icmphdr *icmp = data_l3 + sizeof(*ip);
    if ((void*)icmp + sizeof(*icmp) <= data_end &&
            bpf_ntohs(icmp->un.echo.sequence) % 2 == 0)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

int static _tc_parse_ipv6(void *data_l3, void *data_end) {
    struct ipv6hdr *ipv6 = data_l3;
    if ((void*)ipv6 + sizeof(*ipv6) > data_end || ipv6->nexthdr != IPPROTO_ICMPV6)
        return TC_ACT_OK;

    struct icmp6hdr *icmp6 = data_l3 + sizeof(*ipv6);
    if ((void*)icmp6 + sizeof(*icmp6) <= data_end &&
            bpf_ntohs(icmp6->icmp6_dataun.u_echo.sequence) % 2 == 0)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

struct vlanhdr {
    __be16 h_tci;
    __be16 h_proto;
};

int tc_parse(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    __be16 h_proto = eth->h_proto;
    void *cursor = data + sizeof(*eth);
    for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
        bpf_trace_printk("vlan!\n");
        if (h_proto != htons(ETH_P_8021Q))
            break;

        struct vlanhdr *vlan = cursor;
        if ((void*)vlan + sizeof(*vlan) > data_end)
            return TC_ACT_OK;
        h_proto = vlan->h_proto;
        cursor += sizeof(*vlan);
    }

    switch (h_proto) {
        case htons(ETH_P_IP):
            return _tc_parse_ipv4(cursor, data_end);
        case htons(ETH_P_IPV6):
            return _tc_parse_ipv6(cursor, data_end);
    }

    return TC_ACT_OK;
}

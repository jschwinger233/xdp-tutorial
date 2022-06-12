#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define TCP_SPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define TCP_DPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define IS_PSEUDO 0x10

int tc_port_rewrite_egress(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void*)data + sizeof(*eth) <= data_end && eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) <= data_end && ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
            if ((void*)tcp + sizeof(*tcp) <= data_end) {
                __be16 new_dest = htons(ntohs(tcp->dest) - 1);
                bpf_l4_csum_replace(skb, TCP_CSUM_OFF, tcp->dest, new_dest, IS_PSEUDO | sizeof(new_dest));
                bpf_skb_store_bytes(skb, TCP_DPORT_OFF, &new_dest, sizeof(new_dest), 0);
            }
        }
    }
    return TC_ACT_OK;
}

int tc_port_rewrite_ingress(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void*)data + sizeof(*eth) <= data_end && eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) <= data_end && ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
            if ((void*)tcp + sizeof(*tcp) <= data_end) {
                __be16 new_source = htons(ntohs(tcp->source) + 1);
                bpf_l4_csum_replace(skb, TCP_CSUM_OFF, tcp->source, new_source, IS_PSEUDO | sizeof(new_source));
                bpf_skb_store_bytes(skb, TCP_SPORT_OFF, &new_source, sizeof(new_source), 0);
            }
        }
    }
    return TC_ACT_OK;
}

struct vlanhdr {
    __be16 h_tci;
    __be16 h_proto;
};

int static _strip_vlan(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct ethhdr *eth = data;
    struct ethhdr eth_cp;
    if ((void*)eth + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    struct vlanhdr *vlan = data + sizeof(*eth);
    if ((void*)vlan + sizeof(*vlan) > data_end)
        return TC_ACT_OK;

    __builtin_memcpy(&eth_cp, eth, sizeof(*eth));
    eth_cp.h_proto = vlan->h_proto;

    __u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;
    bpf_skb_adjust_room(skb, -4, BPF_ADJ_ROOM_MAC, flags);

    bpf_skb_store_bytes(skb, 0, &eth_cp, sizeof(eth_cp), 0);
    return TC_ACT_OK;
}

int static _insert_vlan(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    struct ethhdr eth_cp;
    __builtin_memcpy(&eth_cp, eth, sizeof(*eth));
    struct vlanhdr vlan;
    __builtin_memset(&vlan, 0, sizeof(vlan));
    vlan.h_tci = htons(13);
    vlan.h_proto = eth_cp.h_proto;
    eth_cp.h_proto = htons(ETH_P_8021Q);

    bpf_skb_change_head(skb, sizeof(struct vlanhdr), 0);
    bpf_skb_store_bytes(skb, 0, &eth_cp, sizeof(eth_cp), 0);
    bpf_skb_store_bytes(skb, ETH_HLEN, &vlan, sizeof(vlan), 0);
    return TC_ACT_OK;
}

int tc_vlan_tunnel(struct __sk_buff *skb) {
    struct ethhdr eth;
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));

    if (eth.h_proto == htons(ETH_P_8021Q)) {
        return _insert_vlan(skb);
    } else {
        return _strip_vlan(skb);
    }
}

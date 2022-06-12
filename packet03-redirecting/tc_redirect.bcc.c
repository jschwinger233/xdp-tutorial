#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))

int tc_icmp_echo(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

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

                bpf_l4_csum_replace(skb, ICMP_CSUM_OFF, ICMP_ECHO, ICMP_ECHOREPLY, 2);
                __u16 new_type = ICMP_ECHOREPLY;
                bpf_skb_store_bytes(skb, ICMP_TYPE_OFF, &new_type, sizeof(new_type), 0);
                //return bpf_redirect(54, BPF_F_INGRESS); // v11-peer
                return bpf_redirect(55, 0); // v11
            }
        }
    }

    return TC_ACT_OK;
}

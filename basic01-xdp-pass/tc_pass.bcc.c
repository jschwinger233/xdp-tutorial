#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>

int  tc_pass(struct __sk_buff *skb)
{
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) < data_end && eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) < data_end && ip->protocol == IPPROTO_ICMP) {
            bpf_trace_printk("%ld -> %ld\n", ntohl(ip->saddr), ntohl(ip->daddr));
        }
    }
	return TC_ACT_OK;
}

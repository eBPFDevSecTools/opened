#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/swab.h>
#include <linux/pkt_cls.h>
#include <iproute2/bpf_elf.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

#ifndef __section
#define __section(NAME) \
    __attribute__((section(NAME), used))
#endif

#ifndef __inline
#define __inline \
    inline __attribute__((always_inline))
#endif

#ifndef lock_xadd
#define lock_xadd(ptr, val) \
    ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef BPF_FUNC
#define BPF_FUNC(NAME, ...) \
    (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

#define bpf_memcpy __builtin_memcpy

#define MAXELEM 2000

typedef struct cnt_pkt {
    uint32_t drop;
    uint32_t pass;
} pkt_count;

typedef struct iface_desc {
  __u8 mac[ETH_ALEN];
  __u32 ip;
} iface_desc;

#define IP_LEN 4

struct bpf_elf_map iface_map __section("maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(uint32_t),
    .size_value = ETH_ALEN,
    .pinning = PIN_GLOBAL_NS,
    .max_elem = MAXELEM,
};

struct bpf_elf_map iface_ip_map __section("maps") = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(uint32_t),
	.size_value     = sizeof(__be32),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = MAXELEM,
};

struct bpf_elf_map iface_stat_map __section("maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(pkt_count),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = MAXELEM,
};

static __inline int compare_mac(__u8 *mac1, __u8 *mac2) {
    if (mac1[0] == mac2[0] &&
        mac1[1] == mac2[1] &&
        mac1[2] == mac2[2] &&
        mac1[3] == mac2[3] &&
        mac1[4] == mac2[4] &&
        mac1[5] == mac2[5]) {
        return 1;
    }
    return 0;
}

static __inline int is_broadcast_mac(__u8 *m) {
    if (m[0] == (__u8)'0xff' &&
        m[1] == (__u8)'0xff' &&
        m[2] == (__u8)'0xff' &&
        m[3] == (__u8)'0xff' &&
        m[4] == (__u8)'0xff' &&
        m[5] == (__u8)'0xff') {
        return 1;
    }
    return 0;
}

#define ADD_DROP_STAT(idx, inf) do{ \
    if (idx < MAXELEM) {            \
        lock_xadd(&(inf->drop), 1); \
    }                               \
} while(0);

#define ADD_PASS_STAT(idx, inf) do{ \
    if (idx < MAXELEM) {            \
        lock_xadd(&(inf->pass), 1); \
    }                               \
} while(0);

/*
    This filter attaches on veth (interface in root namespace) and not
    vpeer (interface in the pod namespace) so INGRESS means data coming from pod
    EGRESS means data going towards the pod.
*/
static __inline int filter(struct __sk_buff *skb)
{
    char pkt_fmt[]       = "MAC_FILTER: pkt skb contain mac: %x%x\n";
    char src_fmt[]       = "MAC_FILTER: expected source mac: %x%x\n";
    char broadcast[]     = "MAC_FILTER: BROADCAST MESSAGE DETECTED\n";
    char mac_matched[]   = "MAC_FILTER: MAC MATCHED\n";
    char mac_unmatched[] = "MAC_FILTER: MAC DID NOT MATCH\n";
    char map_error[]     = "MAC_FILTER: Unable to get iface %s from map\n";
    char ip_matched[]    = "IP_FILTER: IP iface:%x == pkt:%x MATCHED\n";
    char ip_unmatched[]  = "IP_FILTER: IP iface:%x != pkt:%x DID NOT MATCH\n";
    char ipstr[]         = "ip";
    char macstr[]        = "mac";
    char statsstr[]      = "stats";

    uint32_t *bytes;
    pkt_count *inf;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    uint32_t idx = skb->ifindex;
    struct iphdr *ip;

    __u8 iface_mac[ETH_ALEN];
    __be32 iface_ip;

    __u64 l3_offset = sizeof(struct ethhdr);

    if (data_end < (void *)eth + l3_offset)
        return TC_ACT_SHOT;

    /* ETH_P_IP in Little Endian Format */
    if (eth->h_proto != 0x0008) {
        return TC_ACT_OK;
    }

    ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    inf = bpf_map_lookup_elem(&iface_stat_map, &(idx));
    if (!inf) {
        // haven't found the stat-entry, unexpected behavior, let packet go through.
        bpf_trace_printk(map_error, sizeof(map_error), statsstr);
        return TC_ACT_OK;
    }

    // Mac address lookup
    bytes = bpf_map_lookup_elem(&iface_map, &(idx));
    if (bytes == NULL) {
        /* Unable to get iface MAC. Let the packet through */
        bpf_trace_printk(map_error, sizeof(map_error), macstr);
        return TC_ACT_OK;
    }
    bpf_memcpy(iface_mac, bytes, ETH_ALEN);

    // IP addresss lookup
    bytes = bpf_map_lookup_elem(&iface_ip_map, &(idx));
    if (bytes == NULL) {
        /* Unable to get iface IP. Let the packet through */
        bpf_trace_printk(map_error, sizeof(map_error), ipstr);
        return TC_ACT_OK;
    }
    bpf_memcpy(&iface_ip, bytes, sizeof(__be32));

    // check broadcast messages
    // Broadcast address should be allowed
    if ((is_broadcast_mac(eth->h_source) == 1) ||
        (is_broadcast_mac(eth->h_dest) == 1)) {
        bpf_trace_printk(broadcast, sizeof(broadcast));
        return TC_ACT_OK;
    }

    /* check is packet is coming from pod or going towards pod. */
    if (compare_mac(eth->h_dest, iface_mac) == 1) {
        // Packet is going towards the pod. Let is pass
        return TC_ACT_OK;
    }

    // Packet has come from the pod. Check the mac address.
    __u8 *pkt_mac = (__u8 *)eth->h_source;
    __be32 pkt_ip = ip->saddr;

    if (compare_mac(pkt_mac, iface_mac) == 0) {
        bpf_trace_printk(mac_unmatched, sizeof(mac_unmatched));
        bpf_trace_printk(src_fmt, sizeof(src_fmt),
                         (iface_mac[0] << 16 | iface_mac[1] << 8 | iface_mac[2]),
                         (iface_mac[3] << 16 | iface_mac[4] << 8 | iface_mac[5]));
        bpf_trace_printk(pkt_fmt, sizeof(pkt_fmt),
                         (pkt_mac[0] << 16 | pkt_mac[1] << 8 | pkt_mac[2]),
                         (pkt_mac[3] << 16 | pkt_mac[4] << 8 | pkt_mac[5]));
        ADD_DROP_STAT(idx, inf);
        return TC_ACT_SHOT;
    }

    // MAC Address matches. Now check IP address
    bpf_trace_printk(mac_matched, sizeof(mac_matched));

    // If IP addresss do not match
    if (iface_ip != pkt_ip) {
        bpf_trace_printk(ip_unmatched, sizeof(ip_unmatched), iface_ip, pkt_ip);
        ADD_DROP_STAT(idx, inf);
        return TC_ACT_SHOT;
    }

    // IP address matches
    bpf_trace_printk(ip_matched, sizeof(ip_matched), iface_ip, pkt_ip);
    ADD_PASS_STAT(idx, inf);
    return TC_ACT_OK;
}

__section("classifier_bpf_filter") int bpf_filter(struct __sk_buff *skb)
{
    return filter(skb);
}

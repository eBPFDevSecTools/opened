/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause)
 *
 * Authors:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
*/

#ifndef __PKT_PARSE__
#define __PKT_PARSE__

#pragma once

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <kernel/lib/map-defs.h>
#include <kernel/lib/mptm-debug.h>
#include <kernel/lib/compiler.h>

/* Inspired from Katran.
 * ETH_P_IP and ETH_P_IPV6 in Big Endian format.
 * So we don't have to do htons on each packet
 */
#define BE_ETH_P_IP   0x0008
#define BE_ETH_P_IPV6 0xDD88
#define BE_ETH_P_ARP  0x0608

extern struct bpf_map_def mptm_tunnel_iface_map;

/* Parse eth, ip and udp headers of a packet.
 * If any header is passed as NULL then stop processing and return.
 */
static __ALWAYS_INLINE__ int parse_pkt_headers(void *data, void *data_end,
                                             struct ethhdr **ethhdr,
                                             struct iphdr **iphdr,
                                             struct udphdr **udphdr)
{
    struct hdr_cursor nh;
    int nh_type;
    nh.pos = data;

    if (ethhdr == NULL)
        return 0;

    struct ethhdr *eth;
    nh_type = parse_ethhdr(&nh, data_end, &eth);
    if (nh_type == -1)
      goto out_fail;
    if (eth->h_proto == BE_ETH_P_ARP)
      goto out_fail;
    if (eth->h_proto != BE_ETH_P_IP)
        // We don't support ipv6 for now.
        goto out_fail;

    /* set the header */
    *ethhdr = eth;

    if (iphdr == NULL)
        return 0;

    struct iphdr *ip;
    nh_type = parse_iphdr(&nh, data_end, &ip);
    if (nh_type == -1)
      goto out_fail;

    /* set the header */
    *iphdr = ip;

    if (udphdr == NULL)
        return 0;

    struct udphdr *udp;
    /* Check the protocol. If TCP we return else for udp we process further */
    if (nh_type == IPPROTO_TCP)
        goto out_fail;

    /* Parse udp header */
    nh_type = parse_udphdr(&nh, data_end, &udp);
    if (nh_type == -1)
        goto out_fail;

    /* set the header */
    *udphdr = udp;

    return 0;

    out_fail:
        return 1;
}

#endif /*  __PKT_PARSE__ */

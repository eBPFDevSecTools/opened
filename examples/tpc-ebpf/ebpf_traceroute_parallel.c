/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF TRACEROUTE"
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include "bpf_endian.h"
#include "kernel.h"

#define DEBUG 1 // Always prints
#include "ebpf_traceroute.h"

#define BASE_OP 50 // This value with the increment_hops cannot exceed 255: the maximum opcode to start the eBPF program

static int connection_number = 0;


static int traceroute(struct bpf_sock_ops *skops, int increment_hops)
{
    int rv = 0;
    // Get current Hop Limit
    int old_hops = 0;
    rv = bpf_getsockopt(skops, SOL_IPV6, IPV6_UNICAST_HOPS, &old_hops, sizeof(int));
    if (rv) {
        bpf_debug("Cannot get Hop Limit: %d\n", rv);
        return rv;
    }

    // Change Hop Limit for probe
    rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_UNICAST_HOPS, &increment_hops, sizeof(int));
    if (rv) {
        bpf_debug("Cannot set Hop Limit to %d: %d\n", increment_hops, rv);
        return rv;
    }

    // Send ack probe that should trigger 
    rv = bpf_send_ack(skops);
    if (rv) {
        bpf_debug("Cannot send ack probe: %d\n", rv);
        return rv;
    }

    // Reset Hop Limit
    rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_UNICAST_HOPS, &old_hops, sizeof(int));
    if (rv)
        bpf_debug("Cannot reset Hop Limit to %d: %d\n", old_hops, rv);

    // Start timer
    rv = bpf_start_timer(skops, 10, BASE_OP + increment_hops);
    if (rv)
        bpf_debug("Failed to start timer with error: %d\n", rv);

    return !!rv;
}

SEC("sockops")
int handle_sockop(struct bpf_sock_ops *skops)
{
	int op;
	int rv = 0;
	__u64 cur_time;
    struct ipv6hdr *ip6;
    struct icmp6hdr *icmp;
	struct flow_tuple flow_id;
	struct flow_infos *flow_info;

	cur_time = bpf_ktime_get_ns();
	op = (int) skops->op;

	/* Only execute the prog for scp */
	if (skops->family != AF_INET6) {
		skops->reply = -1;
		return 0;
	}
	get_flow_id_from_sock(&flow_id, skops);
	flow_info = (void *)bpf_map_lookup_elem(&conn_map, &flow_id);
    if (flow_id.remote_port != 5201)
        return 0; // IPerf client to server connection only

    if (flow_info && op == BASE_OP + flow_info->increment_hops - 1) {
        // We did not receive an answer yet !
        bpf_debug("Traceroute stopped\n");
        return 0;
    } /* else if (op > BASE_OP) {
        bpf_debug("Timeout debug: %d\n", op);
    }*/

	switch (op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            if (!flow_info) {  // TODO Problem if listening connections => no destination defined !!!
                connection_number++;
                if (connection_number != 2)
                    return 0; // Ignore iperf metadata connection
                struct flow_infos new_flow;
                int rv = 0;
                new_flow.increment_hops = 1;
                bpf_map_update_elem(&conn_map, &flow_id, &new_flow, BPF_ANY);
                flow_info = (void *) bpf_map_lookup_elem(&conn_map, &flow_id);
                if (!flow_info) {
                    return 1;
                }
            }
            // Start traceroute
            bpf_debug("Triggering traceroute\n");
            for (int i = 0; i < 15; i++) {
                rv = traceroute(skops, flow_info->increment_hops);
                flow_info->increment_hops++;
            }
            bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
            break;
        case BPF_SOCK_OPS_PARSE_ICMP_CB:
            // An ICMP is received
            if (!flow_info)
                return 1;
            ip6 = skops->skb_data;
            if ((void *) (ip6 + 1) <= skops->skb_data_end) {
                icmp = (struct icmp6hdr *) (ip6 + 1);
                if ((void *) (icmp + 1) <= skops->skb_data_end) {
                    if (icmp->icmp6_type == ICMPV6_TIME_EXCEEDED) {
                        // Get the last Hop Limit tried
                        bpf_debug("Hop %d is %pI6c\n", flow_info->increment_hops - 1, &ip6->saddr);

                        // Continue traceroute
                        for (int i = 0; i < 15; i++) {
                            rv = traceroute(skops, flow_info->increment_hops);
                            flow_info->increment_hops++;
                        }
                        bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
                    } else {
                        bpf_debug("ICMP of type %u and code %u\n", icmp->icmp6_type, icmp->icmp6_code);
                    }
                } else {
                    bpf_debug("Not enough skb to read the ICMPv6 header\n");
                }
            } else {
                bpf_debug("Not enough skb to read the IPv6 header\n");
            }
            break;
	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";

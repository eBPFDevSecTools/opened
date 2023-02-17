/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF SHORT FLOWS"
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "kernel.h"
#include "ebpf_exp3_lowest_completion.h"


static __inline int move_path(struct dst_infos *dst_infos, __u32 key, struct bpf_sock_ops *skops)
{
	int rv = 1;
	char cc[20];
	struct ip6_srh_t *srh = NULL;
	// Check needed to avoid verifier complaining about unbounded access
	// The check needs to be placed very near the actual line
	if (key >= 0 && key < MAX_SRH_BY_DEST) {
		srh = &(dst_infos->srhs[key].srh);
		rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR, srh, sizeof(*srh));
		bpf_debug("bpf_setsockopt !!!!! %d\n", rv);
	}
	return !!rv;
}

static int create_new_flow_infos(struct bpf_elf_map *dt_map, struct bpf_elf_map *c_map, struct flow_tuple *flow_id, __u64 cur_time, struct bpf_sock_ops *skops) {
	struct flow_infos *flow_info;
	struct flow_infos new_flow;
	int rv = 0;
	memset(&new_flow, 0, sizeof(struct flow_infos));

	//bpf_debug("flow not found, adding it\n");
	new_flow.exp3_last_number_actions = 1;
	new_flow.exp3_start_snd_nxt = skops->snd_nxt;
	struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem(dt_map, flow_id->remote_addr);
	if (!dst_infos)
		return 1; // Listening connections

	// Inititialize to 1 EXP3 weight and probabilities
	new_flow.exp3_last_probability.mantissa = LARGEST_BIT;
	new_flow.exp3_last_probability.exponent = BIAS;

	//bpf_debug("HHHHHHHHH FLOW src port %u - dst port %u\n", flow_id->local_port, flow_id->remote_port);

	// Insert flow to map
	return bpf_map_update_elem(c_map, flow_id, &new_flow, BPF_ANY);
}

SEC("sockops")
int handle_sockop(struct bpf_sock_ops *skops)
{
	struct dst_infos *dst_infos;
	struct flow_infos *flow_info;
	struct flow_tuple flow_id;

	int op;
	int rv = 0;
	__u64 cur_time;

	cur_time = bpf_ktime_get_ns();
	op = (int) skops->op;

	/* Only execute the prog for scp */
	if (skops->family != AF_INET6) {
		skops->reply = -1;
		return 0;
	}
	get_flow_id_from_sock(&flow_id, skops);
	flow_info = (void *)bpf_map_lookup_elem(&short_conn_map, &flow_id);
	//bpf_debug("HERE operation %d\n", op);
	if (!flow_info) {  // TODO Problem if listening connections => no destination defined !!!
		//bpf_debug("HERE flow creation\n");
		if (create_new_flow_infos(&short_dest_map, &short_conn_map, &flow_id, cur_time, skops)) {
			return 1;
		}
		flow_info = (void *) bpf_map_lookup_elem(&short_conn_map, &flow_id);
		if (flow_info) {
			dst_infos = (void *) bpf_map_lookup_elem(&short_dest_map, flow_id.remote_addr);
			if (dst_infos) {
				bpf_sock_ops_cb_flags_set(skops, (BPF_SOCK_OPS_RETRANS_CB_FLAG|BPF_SOCK_OPS_RTO_CB_FLAG|BPF_SOCK_OPS_RTT_CB_FLAG|BPF_SOCK_OPS_STATE_CB_FLAG));
				skops->reply = rv;
				//bpf_debug("HERE flow created %d\n", BPF_SOCK_OPS_ALL_CB_FLAGS);
				return 0;
			}
		}
		return 1;
	}

	//bpf_debug("operation: %d\n", op);
	//bpf_debug("snd_una: %lu rate : %lu interval: %lu\n", skops->snd_una, skops->rate_delivered, skops->rate_interval_us);
	switch (op) {
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // Call EXP3 for servers (because setting the SRH for request socks does not work)
			bpf_debug("passive established\n");
			flow_info->srh_id = exp3_next_path(&short_dest_map, flow_info, flow_id.remote_addr);
			dst_infos = (void *)bpf_map_lookup_elem(&short_dest_map, flow_id.remote_addr);
			if (dst_infos) {
				move_path(dst_infos, flow_info->srh_id, skops);
				flow_info->exp3_start_snd_nxt = skops->snd_nxt;

				// Retrieve time for completion time (advantage: ignores SYN+ACK delay)
				flow_info->established_timestamp = cur_time;
				flow_info->rtt_timestamp = cur_time;

				if (flow_info->srh_id >= 0 && flow_info->srh_id <= MAX_SRH_BY_DEST - 1)
					flow_info->exp3_curr_reward = dst_infos->srhs[flow_info->srh_id].curr_bw;

				rv = bpf_map_update_elem(&short_conn_map, &flow_id, flow_info, BPF_ANY);
			}
			break;
		case BPF_SOCK_OPS_RTT_CB:
			flow_info->rtt_timestamp = cur_time;
			rv = bpf_map_update_elem(&short_conn_map, &flow_id, flow_info, BPF_ANY);
			break;
		case BPF_SOCK_OPS_STATE_CB: // Change in the state of the TCP CONNECTION
			// This flow is closed, cleanup the maps
			if (skops->args[1] == BPF_TCP_CLOSE) {
				bpf_debug("close: %d\n", skops->args[1]);
				//bpf_debug("close syn delay %llu\n", flow_info->established_timestamp);
				//bpf_debug("close rtt delay %llu\n", flow_info->rtt_timestamp);
				//bpf_debug("close delay %llu\n", flow_info->rtt_timestamp - flow_info->established_timestamp);
				dst_infos = (void *) bpf_map_lookup_elem(&short_dest_map, flow_id.remote_addr);
				if (dst_infos) {
					// Store experience if we use EXP3, otherwise, pure random
					if (USE_EXP3)
						exp3_reward_path(flow_info, dst_infos, skops);
					// Delete the flow from the flows map
					bpf_map_delete_elem(&short_conn_map, &flow_id);
					// Save updated weights
					rv = bpf_map_update_elem(&short_dest_map, flow_id.remote_addr, dst_infos, BPF_ANY);
					if (rv)
						return 1;
					// Save data
					take_snapshot(&short_stat_map, dst_infos, flow_info);
				}
			}
			break;
	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";

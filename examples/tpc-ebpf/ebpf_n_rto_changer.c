/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF LONG FLOWS"
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "kernel.h"
#include "ebpf_n_rto_changer.h"


static __u32 inner_loop(__u32 srh_id, struct dst_infos* dst_infos) {
	#pragma clang loop unroll(full)
	for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {
		if (!dst_infos)
			continue;
		struct srh_record_t *srh_record = &dst_infos->srhs[i];

		// Wrong SRH ID -> might be inconsistent state, so skip
		// Not a valid SRH for the destination
		// Same SRH
		if (!srh_record || !srh_record->srh.type) {  // 1
			//bpf_debug("Cannot find the SRH entry indexed at %d at a dest entry\n", i);
			continue;
		}

		if (!srh_record->is_valid) {  // 1
			//bpf_debug("SRH entry indexed at %d by the dest entry is invalid\n", i);
			continue; // Not a valid SRH for the destination
		}

		if (i > srh_id) {
			return i;
		}
	}
	return 0;
}

static int move_path(struct bpf_elf_map *dst_map, void *id, __u32 key, struct bpf_sock_ops *skops)
{
	int val = 1;
	int rv = 1;
	char cc[20];
	char tmp_cc[5] = "reno";
	struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem(dst_map, id);
	if (dst_infos) {
		struct ip6_srh_t *srh = NULL;
		// Check needed to avoid verifier complaining about unbounded access
		// The check needs to be placed very near the actual line
		if (key >= 0 && key < MAX_SRH_BY_DEST) {
			srh = &(dst_infos->srhs[key].srh);
			rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR, srh, sizeof(*srh));
		}

		if (!rv) {
			// Reset congestion control
			// TODO This removes the estimation of the RTT and puts a timeout of 1 seconds by default
			// It will do nothing if there is no actual change...
			// The problem is that it does not reset the retransmission timeout...
			//rv = bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cc, sizeof(cc));
			//if (!rv) { // TODO Handle case with reno as base congestion control
			//	rv = bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, tmp_cc, sizeof(tmp_cc));
			//	rv = bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, cc, sizeof(cc));
			//}
			if (!rv) {
				rv = bpf_setsockopt(skops, SOL_TCP, TCP_PATH_CHANGED, &val, sizeof(val));
				//bpf_debug("Set Path changed - returned %u\n", rv);
			}
		}
	}
	return !!rv;
}

static int create_new_flow_infos(struct bpf_elf_map *dt_map, struct bpf_elf_map *c_map, struct flow_tuple *flow_id, __u64 cur_time, struct bpf_sock_ops *skops) {
	struct flow_infos *flow_info;
	struct flow_infos new_flow;
	int rv = 0;
	memset(&new_flow, 0, sizeof(struct flow_infos));

	// Timers
	new_flow.last_move_time = cur_time;
	struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem(dt_map, flow_id->remote_addr);
	if (!dst_infos)
		return 1; // Listening connections

	// Insert flow to map
	return bpf_map_update_elem(c_map, flow_id, &new_flow, BPF_ANY);
}

SEC("sockops")
int handle_sockop(struct bpf_sock_ops *skops)
{
	struct flow_infos *flow_info;
	struct flow_tuple flow_id;

	int rv = 0;
	__u64 cur_time;

	cur_time = bpf_ktime_get_ns();

	/* Only execute the prog for scp */
	if (skops->family != AF_INET6) {
		skops->reply = -1;
		return 0;
	}
	get_flow_id_from_sock(&flow_id, skops);
	flow_info = (void *)bpf_map_lookup_elem(&conn_map, &flow_id);

	switch ((int) skops->op) {
		case BPF_SOCK_OPS_TCP_CONNECT_CB:
			//bpf_debug("active SYN sent from %u\n", skops->local_port);
			// XXX No break; here
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // Call EXP4 for servers (because setting the SRH for request socks does not work)
			if (!flow_info) {
				if (create_new_flow_infos(&dest_map, &conn_map, &flow_id, cur_time, skops)) {
					return 1;
				}
				flow_info = (void *) bpf_map_lookup_elem(&conn_map, &flow_id);
				if (!flow_info) {
					return 1;
				}
			}
			bpf_debug("INIT CONN snd_cwnd: %u\n", skops->snd_cwnd);

			flow_info->last_move_time = cur_time;
			flow_info->srh_id = 0;
			move_path(&dest_map, flow_id.remote_addr, flow_info->srh_id, skops);
			rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
			if (rv)
				return 1;

			take_snapshot(&stat_map, flow_info, &flow_id, skops->op);

			bpf_sock_ops_cb_flags_set(skops, (BPF_SOCK_OPS_RETRANS_CB_FLAG|BPF_SOCK_OPS_RTO_CB_FLAG|BPF_SOCK_OPS_RTT_CB_FLAG|BPF_SOCK_OPS_STATE_CB_FLAG));
			skops->reply = rv;

			//if (skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
			//	bpf_debug("passive established - timer %llu\n", flow_info->last_move_time);
			break;
		case BPF_SOCK_OPS_STATE_CB: // Change in the state of the TCP CONNECTION
			// This flow is closed, cleanup the maps
			if (skops->args[1] == BPF_TCP_CLOSE || skops->args[1] == BPF_TCP_CLOSE_WAIT || skops->args[1] == BPF_TCP_CLOSING || skops->args[1] == BPF_TCP_FIN_WAIT1 || skops->args[1] == BPF_TCP_FIN_WAIT2) {
				//bpf_debug("Close\n");
				if (!flow_info) {
					return 0;
				}
				// Delete the flow from the flows map
				// take_snapshot(&stat_map, flow_info, &flow_id);
				bpf_map_delete_elem(&conn_map, &flow_id);
			}
			break;
		case BPF_SOCK_OPS_DUPACK:
			if (!flow_info) {
				return 1;
			}
			flow_info->retrans_count += 1;
			//bpf_debug("Duplicated ack: nbr %llu for %llu\n", flow_info->retrans_count, skops->rcv_nxt);

			if (flow_info->last_rcv_nxt != skops->rcv_nxt) { // Data was acked so issue was solved
				flow_info->last_rcv_nxt = skops->rcv_nxt;
				flow_info->retrans_count = 1;
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			}

			if (flow_info->retrans_count < 2) {
				// TODO This number needs to be strictly lower than the RTO trigger...
				// It can work with equal values if bytes were in flight at the failure but never greater values
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			}

			__u32 key_dup = 0; // This assumes that SRH 0 is always valid
			struct dst_infos *dst_infos_dup = (void *) bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
			key_dup = inner_loop(flow_info->srh_id, dst_infos_dup);
			//bpf_debug("DUP ACK - Change path to %u\n", key_dup);

			if (key_dup == flow_info->srh_id) {
				// This can't be helped
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			}

			// Move to the next path
			bpf_debug("DUP ACK - Change path to %u\n", key_dup);
			rv = move_path(&dest_map, flow_id.remote_addr, key_dup, skops);
			if (!rv) {
				// Update flow informations
				flow_info->srh_id = key_dup;
				flow_info->last_move_time = cur_time;
				flow_info->retrans_count = 0;
				bpf_debug("DUP ACK - Path changed to %u\n", key_dup);
			}
			take_snapshot(&stat_map, flow_info, &flow_id, skops->op);
			break;
		case BPF_SOCK_OPS_RETRANS_CB: // TODO Retransmission
			if (!flow_info) {
				return 0;
			}
			bpf_debug("Retransmission: for %llu\n", skops->snd_una);
			take_snapshot(&stat_map, flow_info, &flow_id, skops->op); // TODO Remove ?
			break;
		case BPF_SOCK_OPS_RTO_CB: // TODO Retransmission timeout
			// TODO The problem is that the connection is cut from the server to the client as well...
			// TODO So the server also needs this program (or a single-side cut)...
			// TODO But it won't work if the server is only acking because no eBPF is made...
			if (!flow_info) {
				return 1;
			}
			flow_info->retrans_count += 1;
			bpf_debug("Retransmission timeout: nbr %llu for %llu\n", flow_info->retrans_count, skops->snd_una);
			//bpf_debug("Params: %u %u %u\n", skops->args[0], skops->args[1], skops->args[2]);
			bpf_debug("snd_cwnd: %u - packets_out %u\n", skops->snd_cwnd, skops->packets_out);

			if (flow_info->last_snd_una + 3000 < skops->snd_una) { // Data was acked so issue was solved TODO Try with a delta of two packets
				flow_info->last_snd_una = skops->snd_una;
				flow_info->retrans_count = 1;
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				take_snapshot(&stat_map, flow_info, &flow_id, skops->op);
				break;
			}

			if (flow_info->retrans_count < 3) { 
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				take_snapshot(&stat_map, flow_info, &flow_id, skops->op);
				break;
			}

			// After three duplicated acknowledgments for the same data, switch path

			__u32 key = 0; // This assumes that SRH 0 is always valid
			struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
			key = inner_loop(flow_info->srh_id, dst_infos);
			//bpf_debug("RTO - Change path to %u\n", key);

			if (key == flow_info->srh_id) {
				// This can't be helped
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			}

			// Move to the next path
			bpf_debug("RTO - Change path to %u\n", key);
			rv = move_path(&dest_map, flow_id.remote_addr, key, skops);
			if (!rv) {
				// Update flow informations
				flow_info->srh_id = key;
				flow_info->last_move_time = cur_time;
				flow_info->retrans_count = 0;
				bpf_debug("RTO - Path changed to %u\n", key);
			}
			take_snapshot(&stat_map, flow_info, &flow_id, skops->op);
			rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
			break;
	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";

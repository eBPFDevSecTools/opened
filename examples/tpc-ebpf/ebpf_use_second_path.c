/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF SECOND PATH"
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "kernel.h"
#include "ebpf_use_second_path.h"

static int move_path(struct bpf_elf_map *dst_map, void *id, __u32 key, struct bpf_sock_ops *skops)
{
    int rv = 1;
	struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem(dst_map, id);
	if (dst_infos) {
		struct ip6_srh_t *srh = NULL;
		// Check needed to avoid verifier complaining about unbounded access
		// The check needs to be placed very near the actual line
		if (key >= 0 && key < MAX_SRH_BY_DEST) {
			srh = &(dst_infos->srhs[key].srh);
			rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR, srh, sizeof(*srh));
		}
	}
	return !!rv;
}

SEC("sockops")
int handle_sockop(struct bpf_sock_ops *skops)
{
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

	switch ((int) skops->op) {
        case BPF_SOCK_OPS_TCP_CONNECT_CB:
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			rv = move_path(&dest_map, flow_id.remote_addr, 1, skops);
            bpf_debug("Move to path %d\n", rv);
            break;
	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";


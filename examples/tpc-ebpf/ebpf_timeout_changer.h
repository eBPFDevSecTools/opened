#ifndef EBPF_LONG_FLOWS_H
#define EBPF_LONG_FLOWS_H

#include "utils.h"

#define MIN_TIME_BEFORE_MOVING_NS 700000000UL // ns -> 700ms

struct flow_infos {
	__u32 srh_id;
	__u64 last_move_time; // == min(time of last RTT, time of last path change)
	__u64 rtt_count;
	__u32 retrans_count;
	__u64 last_rcv_nxt;
	__u64 last_snd_una;
} __attribute__((packed));

struct flow_snapshot {
	__u32 sequence; // 0 if never used -> we change the lowest sequence id
	__u64 time;
	struct flow_tuple flow_id;
	struct flow_infos flow;
	__u32 reason;
} __attribute__((packed));

struct dst_infos {
	struct ip6_addr_t dest;
	__u32 max_reward;
	struct srh_record_t srhs[MAX_SRH_BY_DEST];
} __attribute__((packed));

struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
} __attribute__((packed));

struct snapshot_arg {
	struct flow_snapshot *new_snapshot;
	__u64 oldest_seq;
	__u32 best_idx;
	__u32 max_seq;
	__u32 setup;
};

static void take_snapshot(struct bpf_elf_map *st_map, struct flow_infos *flow_info, struct flow_tuple *flow_id, __u32 op)
{
	struct flow_snapshot *curr_snapshot = NULL;
	struct snapshot_arg arg = {
		.new_snapshot = NULL,
		.oldest_seq = 0,
		.best_idx = 0,
		.max_seq = 0
	};

	curr_snapshot = (void *) bpf_map_lookup_elem(st_map, &arg.best_idx);
	if (curr_snapshot) {
		arg.new_snapshot = curr_snapshot;
		arg.oldest_seq = curr_snapshot->sequence;
		arg.max_seq = curr_snapshot->sequence;
	}

	//#pragma clang loop unroll(full)
	for (int i = 0; i <= MAX_SNAPSHOTS - 1; i++) {
		int xxx = i;
		curr_snapshot = (void *) bpf_map_lookup_elem(st_map, &xxx);
		if (curr_snapshot) {
			if (arg.max_seq < curr_snapshot->sequence) {
				arg.max_seq = curr_snapshot->sequence;
			}
			if (arg.oldest_seq > curr_snapshot->sequence) {
				arg.oldest_seq = curr_snapshot->sequence;
				arg.new_snapshot = curr_snapshot;
				arg.best_idx = xxx;
			}
		}
	}
	if (arg.new_snapshot) {
		memcpy(&arg.new_snapshot->flow, flow_info, sizeof(struct flow_infos));
		memcpy(&arg.new_snapshot->flow_id, flow_id, sizeof(struct flow_tuple));
		arg.new_snapshot->sequence = arg.max_seq + 1;
		arg.new_snapshot->time = bpf_ktime_get_ns();
		arg.new_snapshot->reason = op;
		bpf_map_update_elem(st_map, &arg.best_idx, arg.new_snapshot, BPF_ANY);
	}
}

struct bpf_elf_map SEC("maps") conn_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct flow_tuple),
	.size_value	= sizeof(struct flow_infos),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_FLOWS,
};

struct bpf_elf_map SEC("maps") dest_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(unsigned long long),  // XXX Only looks at the most significant 64 bits of the address
	.size_value	= sizeof(struct dst_infos),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_FLOWS,
};

struct bpf_elf_map SEC("maps") stat_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct flow_snapshot),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_SNAPSHOTS,
};

#endif

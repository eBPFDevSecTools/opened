#ifndef EBPF_LONG_FLOWS_H
#define EBPF_LONG_FLOWS_H

#include "utils.h"

struct flow_infos {
	__u32 srh_id;
	__u64 rtt_count; // Count the number of RTT in the connection, this is useful to know if congestion signals are consecutive or not
	__u32 ecn_count; // Count the number of consecutive CWR sent (either from ECN or other causes)
	__u64 last_ecn_rtt; // The index of the last RTT were we sent an CWR
	__u32 exp3_last_number_actions;
	__u32 exp3_curr_reward;
	__u32 exp3_start_snd_nxt; // The reward is computed with the number of bytes exchanged during an amount of time
	floating exp3_last_probability;
	__u8 negative_reward; // boolean
} __attribute__((packed));

struct dst_infos {
	struct ip6_addr_t dest;
	__u32 max_reward;
	struct srh_record_t srhs[MAX_SRH_BY_DEST];
	floating exp3_weight[MAX_SRH_BY_DEST];
	u32 last_srtt[MAX_SRH_BY_DEST];
} __attribute__((packed));

struct flow_snapshot {
	__u32 sequence; // 0 if never used -> we change the lowest sequence id
	__u64 time;
	__u32 srh_id;
	__u32 reward;
	struct ip6_addr_t dest;
	floating exp3_weight[MAX_SRH_BY_DEST];
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

static void take_snapshot(struct bpf_elf_map *st_map, struct dst_infos *dst_info, struct flow_infos *flow_info)
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
		memcpy(&arg.new_snapshot->dest, &dst_info->dest, sizeof(struct ip6_addr_t));
		memcpy(arg.new_snapshot->exp3_weight, dst_info->exp3_weight, sizeof(floating) * MAX_SRH_BY_DEST);
		arg.new_snapshot->sequence = arg.max_seq + 1;
		arg.new_snapshot->time = bpf_ktime_get_ns();
		arg.new_snapshot->srh_id = flow_info->srh_id;
		arg.new_snapshot->reward = flow_info->exp3_curr_reward;
		bpf_map_update_elem(st_map, &arg.best_idx, arg.new_snapshot, BPF_ANY);
	} else {
		bpf_debug("HERE STAT FAIL\n");
	}
}

static void exp3_reward_path(struct flow_infos *flow_info, struct dst_infos *dst_infos, struct bpf_sock_ops *skops)
{
	/*
	theReward = reward(choice, t)
	weights[choice] *= math.exp(theReward / (probabilityDistribution[choice] * gamma_rev * numActions)) # important that we use estimated reward here!
	*/
	floating gamma_rev;
	floating reward;
	floating exponent_den_factor;
	floating exponent_den;
	floating nbr_actions;
	floating exponent;
	floating weight_factor;
	floating float_tmp, float_tmp2;
	floating operands[2];
	__u32 decimal[2];
	__u32 srtt;

	floating max_reward;

	// Compute max reward (in ms)
	bpf_to_floating(MAX_REWARD_FACTOR, 0, 1, &max_reward, sizeof(floating)); // TODO Hardcoded factor

	GAMMA_REV(gamma_rev);

	// Compute new reward (in ms)
	srtt = (skops->srtt_us >> 3) / 1000;
	if (srtt <= 23) { // TODO Hardcoded mean delay (should be a moving average)
		flow_info->exp3_curr_reward = 23 - srtt; // TODO Hardcoded mean delay (should be a moving average)
		flow_info->negative_reward = 0;
	} else {
		flow_info->exp3_curr_reward = srtt - 23; // TODO Hardcoded mean delay (should be a moving average)
		flow_info->negative_reward = 1;
	}

	bpf_debug("HERE reward %u for path %u - negative ? %d\n", flow_info->exp3_curr_reward, flow_info->srh_id, flow_info->negative_reward); // TODO Remove
	bpf_to_floating(flow_info->exp3_curr_reward, 0, 1, &reward, sizeof(floating));
	bpf_to_floating(flow_info->exp3_last_number_actions, 1, 0, &nbr_actions, sizeof(floating));

	set_floating(operands[0], reward);
	set_floating(operands[1], max_reward);
	bpf_floating_divide(operands, sizeof(floating) * 2, &reward, sizeof(floating)); // reward should be in [0, 1]
	bpf_floating_to_u32s(&reward, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-norm-reward %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

	// Compute new weight
	set_floating(operands[0], flow_info->exp3_last_probability);
	bpf_floating_to_u32s(&flow_info->exp3_last_probability, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-exponent_den_factor %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
	set_floating(operands[1], gamma_rev);
	bpf_floating_to_u32s(&gamma_rev, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-exponent_den_factor %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
	bpf_floating_multiply(operands, sizeof(floating) * 2, &exponent_den_factor, sizeof(floating));
	bpf_floating_to_u32s(&exponent_den_factor, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-exponent_den_factor %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

	set_floating(operands[0], exponent_den_factor);
	set_floating(operands[1], nbr_actions);
	bpf_floating_multiply(operands, sizeof(floating) * 2, &exponent_den, sizeof(floating));
	bpf_floating_to_u32s(&exponent_den, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-exponent_den %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

	set_floating(operands[0], reward);
	set_floating(operands[1], exponent_den);
	bpf_floating_divide(operands, sizeof(floating) * 2, &exponent, sizeof(floating));
	bpf_floating_to_u32s(&exponent, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-exponent %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

	bpf_floating_e_power_a(&exponent, sizeof(floating), &weight_factor, sizeof(floating));
	bpf_floating_to_u32s(&weight_factor, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-factor %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

	__u32 idx = flow_info->srh_id;
	if (idx >= 0 && idx <= MAX_SRH_BY_DEST - 1) { // Always true but this is for eBPF loader
		exp3_weight_get(dst_infos, idx, float_tmp);
		bpf_floating_to_u32s(&float_tmp, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		bpf_debug("HERE-old-weight %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
		set_floating(operands[0], float_tmp);
		set_floating(operands[1], weight_factor);
		// If negative reward, divide because of a negative exponent ^^
		if (flow_info->negative_reward) {
			bpf_floating_divide(operands, sizeof(floating) * 2, &float_tmp2, sizeof(floating));
		} else {
			bpf_floating_multiply(operands, sizeof(floating) * 2, &float_tmp2, sizeof(floating));
		}
		bpf_debug("HERE-new-weight %llu %u\n", float_tmp2.mantissa, float_tmp2.exponent); // TODO Remove
		bpf_floating_to_u32s(&float_tmp2, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		bpf_debug("HERE-new-weight %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
		exp3_weight_set(dst_infos, idx, float_tmp2);
	}

	// TODO Reset weights
	floating sum;
	bpf_to_floating(0, 0, 1, &sum, sizeof(floating));
	struct srh_record_t *srh_record = NULL;
	#pragma clang loop unroll(full)
	for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {
		int xxx = i; // Compiler cannot unroll otherwise
		srh_record = &dst_infos->srhs[i];

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

		set_floating(operands[0], sum);
		exp3_weight_get(dst_infos, xxx, operands[1]);
		// bpf_debug("HERE %llu %u\n", operands[1].mantissa, operands[1].exponent); // TODO Remove
		bpf_floating_to_u32s(&operands[1], sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		bpf_debug("BEFORE-1 %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

		bpf_floating_add(operands, sizeof(floating) * 2, &sum, sizeof(floating));
	}

	floating nbr_tokens;
	bpf_to_floating(NBR_TOKENS, 0, 1, &nbr_tokens, sizeof(floating));
	#pragma clang loop unroll(full)
	for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {
		int xxx = i; // Compiler cannot unroll otherwise
		srh_record = &dst_infos->srhs[i];

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
		exp3_weight_get(dst_infos, xxx, operands[0]);
		set_floating(operands[1], nbr_tokens);
		bpf_floating_multiply(operands, sizeof(floating) * 2, &float_tmp, sizeof(floating));
		set_floating(operands[0], float_tmp);
		set_floating(operands[1], sum);
		bpf_floating_divide(operands, sizeof(floating) * 2, &float_tmp, sizeof(floating));
		if (float_tmp.exponent >= BIAS) {
			exp3_weight_set(dst_infos, xxx, float_tmp);
		} else {
			exp3_weight_reset(dst_infos, xxx); // Minimum 1 for weights
		}

		exp3_weight_get(dst_infos, xxx, float_tmp);
		bpf_floating_to_u32s(&float_tmp, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		bpf_debug("AFTER-1 %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
	}
}

static __u32 exp3_next_path(struct bpf_elf_map *dt_map, struct flow_infos *flow_info, __u32 *dst_addr)
{
	/*
	def distr(weights, gamma=0.0):
		theSum = float(sum(weights))
		return tuple((1.0 - gamma) * (w / theSum) + (gamma / len(weights)) for w in weights)

	def exp3(numActions, reward, gamma):
		weights = [1.0] * numActions

		t = 0
		while True:
			probabilityDistribution = distr(weights, gamma)
			choice = draw(probabilityDistribution)
			theReward = reward(choice, t)

			estimatedReward = theReward / probabilityDistribution[choice]
			weights[choice] *= math.exp(estimatedReward * gamma / numActions) # important that we use estimated reward here!

			yield choice, theReward, estimatedReward, weights
			t = t + 1
	*/
	floating operands[2];
	floating gamma;
	GAMMA(gamma);

	__u32 decimal[2];
	decimal[0] = 0;
	decimal[1] = 0;

	__u32 chosen_id = 0, current_delay = 0;
	struct srh_record_t *srh_record = NULL;
	struct dst_infos *dst_infos = NULL;

	dst_infos = (void *) bpf_map_lookup_elem(dt_map, dst_addr);
	if (!dst_infos) {
		//bpf_debug("Cannot find the destination entry => Cannot find another SRH\n");
		return chosen_id;
	}

	// Compute the sum of weights
	floating sum;
	bpf_to_floating(0, 0, 1, &sum, sizeof(floating));
	__u32 nbr_valid_paths = 0;
	#pragma clang loop unroll(full)
	for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {
		int xxx = i; // Compiler cannot unroll otherwise
		srh_record = &dst_infos->srhs[i];

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

		set_floating(operands[0], sum);
		exp3_weight_get(dst_infos, xxx, operands[1]);
		//bpf_debug("HERE %llu %u\n", operands[1].mantissa, operands[1].exponent); // TODO Remove
		bpf_floating_to_u32s(&operands[1], sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		bpf_debug("HERE-2 %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
		bpf_floating_add(operands, sizeof(floating) * 2, &sum, sizeof(floating));
		nbr_valid_paths += 1;
	}

	bpf_floating_to_u32s(&sum, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-sum %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
	bpf_debug("HERE-nbr-valid-paths %u\n", nbr_valid_paths); // TODO Remove

	// Compute the probabilities
	floating probability;
	floating one_minus_gamma;
	ONE_MINUS_GAMMA(one_minus_gamma);
	floating weight_times_gama;
	floating term1;
	floating valid_paths;
	bpf_to_floating(nbr_valid_paths, 0, 1, &valid_paths, sizeof(floating));
	floating term2;

	set_floating(operands[0], gamma);
	set_floating(operands[1], valid_paths);
	bpf_floating_divide(operands, sizeof(floating) * 2, &term2, sizeof(floating));

	__u64 pick = ((__u64) bpf_get_prandom_u32()) % FLOAT_MULT; // No problem if FLOAT_MULT < UIN32T_MAX
	__u64 accumulator = 0;

	#pragma clang loop unroll(full)
	for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {
		int yyy = i; // Compiler cannot unroll otherwise
		srh_record = &dst_infos->srhs[i];

		// Wrong SRH ID -> might be inconsistent state, so skip
		// Not a valid SRH for the destination
		// Same SRH
		if (!srh_record || !srh_record->srh.type) {  // 2
			//bpf_debug("Cannot find the SRH entry indexed at %d at a dest entry\n", i);
			continue;
		}

		if (!srh_record->is_valid) {  // 2
			continue; // Not a valid SRH for the destination
		}

		// prob[i] = (1.0 - gamma) * (w[i] / theSum) + (gamma / len(weights))
		set_floating(operands[0], one_minus_gamma);
		exp3_weight_get(dst_infos, yyy, operands[1]);
		bpf_floating_multiply(operands, sizeof(floating) * 2, &weight_times_gama, sizeof(floating));

		//exp3_weight_get(dst_infos, yyy, operands[0]);
		set_floating(operands[0], weight_times_gama);
		set_floating(operands[1], sum);
		bpf_floating_divide(operands, sizeof(floating) * 2, &term1, sizeof(floating));

		set_floating(operands[0], term1);
		set_floating(operands[1], term2);
		bpf_floating_add(operands, sizeof(floating) * 2, &probability, sizeof(floating));

		bpf_floating_to_u32s(&probability, sizeof(floating), (__u64 *) decimal, sizeof(decimal));
		accumulator += decimal[1]; // No need to take the integer part since these are numbers in [0, 1[
		bpf_debug("HERE-probability %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
		if (pick < accumulator) {
			bpf_debug("Chosen %llu\n", accumulator); // TODO Remove
			// We found the chosen one
			chosen_id = i;
			set_floating(flow_info->exp3_last_probability, probability);
			break;
		}
	}

	flow_info->exp3_last_number_actions = nbr_valid_paths;
	return chosen_id;
}

struct bpf_elf_map SEC("maps") short_conn_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct flow_tuple),
	.size_value	= sizeof(struct flow_infos),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_FLOWS,
};

struct bpf_elf_map SEC("maps") short_dest_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(unsigned long long),  // XXX Only looks at the most significant 64 bits of the address
	.size_value	= sizeof(struct dst_infos),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_FLOWS,
};

struct bpf_elf_map SEC("maps") short_stat_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct flow_snapshot),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_SNAPSHOTS,
};

#endif

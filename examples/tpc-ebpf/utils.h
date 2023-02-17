#ifndef EBPF_UTILS_H
#define EBPF_UTILS_H

#include "bpf_helpers.h"
#include "floating_point.h"
#include "param.h"

/* Defining constant values */

#define IPPROTO_TCP 	6 /* TCP protocol in HDR */
#define AF_INET6 		10 /* IPv6 HDR */
#define SOL_IPV6 		41 /* IPv6 Sockopt */
#define SOL_SOCKET		1 /* Socket Sockopt */
#define SOL_TCP			6 /* TCP Sockopt */
#define SO_MAX_PACING_RATE	47 /* Max pacing rate for setsockopt */
#define IPV6_RTHDR 		57 /* SRv6 Option for sockopt */
#define ETH_HLEN 		14 /* Ethernet hdr length */
#define TCP_MAXSEG		2 /* Limit/Retrieve MSS */
#define TCP_CONGESTION  13 /* Change congestion control */
#define TCP_PATH_CHANGED 38 /* Notify TCP that kernel changed */
#define IPV6_RECVRTHDR	56	/* Trigger the save of the SRH */
#define NEXTHDR_ROUTING		43	/* Routing header. */
#define IPV6_UNICAST_HOPS	16	/* Hop limit */
#define ICMPV6_TIME_EXCEEDED	3 /* ICMPv6 Time Exceeded */
// #define DEBUG 			1
#define PIN_NONE		0
#define PIN_GLOBAL_NS	2
#define MAX_SRH			50
#define MAX_FLOWS		1024
#define MAX_SRH_BY_DEST 8
#define MAX_SEGS_NBR	10
#define MAX_EXPERTS MAX_SRH_BY_DEST + 2 // one expert telling 100% on a single path + one expert changing randomly + one random expert + one expert always stable

#define WAIT_BACKOFF 2 // Multiply by two the waiting time whenever a path change is made

// Stats
#define MAX_SNAPSHOTS 100 // TODO Fix - The max number fo snapshot to keep

/* eBPF definitions */

#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif

#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 *  * end-up in /sys/kernel/debug/tracing/trace_pipe
 *   */
#define bpf_debug(fmt, ...)						\
			({						\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
			##__VA_ARGS__);					\
			})
#else
#define bpf_debug(fmt, ...) { } while (0);
#endif

#define htonll(x) ((bpf_htonl(1)) == 1 ? (x) : ((uint64_t)bpf_htonl((x) & \
				0xFFFFFFFF) << 32) | bpf_htonl((x) >> 32))
#define ntohll(x) ((bpf_ntohl(1)) == 1 ? (x) : ((uint64_t)bpf_ntohl((x) & \
				0xFFFFFFFF) << 32) | bpf_ntohl((x) >> 32))

/* IPv6 address */
struct ip6_addr_t {
	unsigned long long hi;
	unsigned long long lo;
} __attribute__((packed));

/* SRH definition */
struct ip6_srh_t {
	unsigned char nexthdr;
	unsigned char hdrlen;
	unsigned char type;
	unsigned char segments_left;
	unsigned char first_segment;
	unsigned char flags;
	unsigned short tag;

	struct ip6_addr_t segments[MAX_SEGS_NBR];
} __attribute__((packed));

struct srh_record_t {
	__u32 srh_id;
	__u32 is_valid;
	__u64 curr_bw; // Mbps
	__u64 delay; // ms
	struct ip6_srh_t srh;
} __attribute__((packed));

struct flow_tuple {
	__u32 family;
	__u32 local_addr[4];
	__u32 remote_addr[4];
	__u32 local_port;
	__u32 remote_port;	
} __attribute__((packed));

#define exp3_weight_reset(flow_infos, idx) \
	if (idx >= 0 && idx <= MAX_SRH_BY_DEST - 1) {\
		(flow_infos)->exp3_weight[idx].mantissa = LARGEST_BIT; \
		(flow_infos)->exp3_weight[idx].exponent = BIAS; \
	}

#define exp3_weight_set(flow_infos, idx, value) \
	if (idx >= 0 && idx <= MAX_SRH_BY_DEST - 1) {\
		(flow_infos)->exp3_weight[idx].mantissa = (value).mantissa; \
		(flow_infos)->exp3_weight[idx].exponent = (value).exponent; \
	}

#define exp3_weight_get(flow_infos, idx, value) \
	if (idx >= 0 && idx <= MAX_SRH_BY_DEST - 1) { \
		(value).mantissa = (flow_infos)->exp3_weight[idx].mantissa; \
		(value).exponent = (flow_infos)->exp3_weight[idx].exponent; \
	}


#define exp4_weight_set(flow_infos, idx, value) \
	if (idx >= 0 && idx <= MAX_EXPERTS - 1) {\
		(flow_infos)->exp4_weight[idx].mantissa = (value).mantissa; \
		(flow_infos)->exp4_weight[idx].exponent = (value).exponent; \
	}

#define exp4_weight_get(flow_infos, idx, value) \
	if (idx >= 0 && idx <= MAX_EXPERTS - 1) { \
		(value).mantissa = (flow_infos)->exp4_weight[idx].mantissa; \
		(value).exponent = (flow_infos)->exp4_weight[idx].exponent; \
	}

static void get_flow_id_from_sock(struct flow_tuple *flow_id, struct bpf_sock_ops *skops)
{
	flow_id->family = skops->family;
	flow_id->local_addr[0] = skops->local_ip6[0];
	flow_id->local_addr[1] = skops->local_ip6[1];
	flow_id->local_addr[2] = skops->local_ip6[2];
	flow_id->local_addr[3] = skops->local_ip6[3];
	flow_id->remote_addr[0] = skops->remote_ip6[0];
	flow_id->remote_addr[1] = skops->remote_ip6[1];
	flow_id->remote_addr[2] = skops->remote_ip6[2];
	flow_id->remote_addr[3] = skops->remote_ip6[3];
	flow_id->local_port =  skops->local_port;
	flow_id->remote_port = bpf_ntohl(skops->remote_port);
}

#endif

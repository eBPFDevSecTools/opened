#ifndef __FLOW_H__
#define __FLOW_H__

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define IP_MAX_LEN 16

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef struct flow_metrics_t {
    u32 packets;
    u64 bytes;
    // Flow start and end times as monotomic timestamps in nanoseconds
    // as output from bpf_ktime_get_ns()
    u64 start_mono_time_ts;
    u64 end_mono_time_ts;
    // TCP Flags from https://www.ietf.org/rfc/rfc793.txt
    u16 flags;
    // The positive errno of a failed map insertion that caused a flow
    // to be sent via ringbuffer.
    // 0 otherwise
    // https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
    u8 errno;
} __attribute__((packed)) flow_metrics;

// Attributes that uniquely identify a flow
typedef struct flow_id_t {
    u16 eth_protocol;
    u8 direction;
    // L2 data link layer
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    // L3 network layer
    // IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
    // as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    // L4 transport layer
    u16 src_port;
    u16 dst_port;
    u8 transport_protocol;
    // OS interface index
    u32 if_index;
} __attribute__((packed)) flow_id;

// Flow record is a tuple containing both flow identifier and metrics. It is used to send
// a complete flow via ring buffer when only when the accounting hashmap is full.
// Contents in this struct must match byte-by-byte with Go's pkc/flow/Record struct
typedef struct flow_record_t {
    flow_id id;
    flow_metrics metrics;
} __attribute__((packed)) flow_record;
#endif

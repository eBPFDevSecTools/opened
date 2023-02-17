/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF REVERSE SRH"
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include "bpf_endian.h"
#include "kernel.h"
#include "ebpf_reverse_srh.h"


static int move_path(struct ip6_srh_t *srh, struct bpf_sock_ops *skops)
{
    srh->nexthdr = 0; // TODO Useful ?
	int rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR, srh, sizeof(*srh));
    //bpf_debug("bpf_setsockopt !!!!! %d\n", rv);
    if (rv) {
        bpf_debug("optval %p - optlen %llu\n", srh, sizeof(*srh));
        bpf_debug("optlen %llu - header_len %u\n", sizeof(*srh), (srh->hdrlen+1) << 3);
        bpf_debug("next extension %u - rt_type %u\n", srh->nexthdr, srh->type);
        bpf_debug("first segment %u - segments_left %u\n", srh->first_segment, srh->segments_left);
        bpf_debug("max_last_entry %u\n", (srh->hdrlen / 2) - 1);
    }
	return !!rv;
}

SEC("sockops")
int handle_sockop(struct bpf_sock_ops *skops)
{
	int op;
    int val = 0;
	int rv = 0;
	__u64 cur_time;
    struct ipv6hdr *ip6;
    struct ip6_srh_t reversed_srh;
    struct ip6_srh_t *skb_srh;
    struct ip6_addr_t tmp;

	cur_time = bpf_ktime_get_ns();
	op = (int) skops->op;

	/* Only execute the prog for scp */
	if (skops->family != AF_INET6) {
		skops->reply = -1;
		return 0;
	}

	switch (op) {
        case BPF_SOCK_OPS_TCP_CONNECT_CB:
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            val = 1;
            rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RECVRTHDR, &val, sizeof(int));
            break;
        case BPF_SOCK_OPS_PARSE_EXT_HDR_CB:
            // We cannot set a SRH on a request sock, only on a full sock
            if (skops->is_fullsock) {
                // TODO Print Received SRH
                ip6 = (struct ipv6hdr *) skops->skb_data;
	            if (ip6 + 1 <= skops->skb_data_end && ip6->nexthdr == NEXTHDR_ROUTING) {
                    //bpf_debug("IP version %d\n", ip6->version);
                    skb_srh = (struct ip6_srh_t *) (ip6 + 1);
                    if (((void *) (skb_srh + 1)) - sizeof(reversed_srh.segments) <= skops->skb_data_end && skb_srh->type == 4) {
                        // There is a routing extension header that is readable

                        int skb_srh_size = (skb_srh->hdrlen + 1) << 3;
                        if (((void *) skb_srh) + skb_srh_size > skops->skb_data_end) {
                            bpf_debug("SRH cut in the middle\n");
                            return 1;
                        }
                        if (skb_srh_size > sizeof(struct ip6_srh_t)) {
                            bpf_debug("A too big SRH for the reserved size\n");
                            return 1;
                        }
                        memset(&reversed_srh, 0, sizeof(reversed_srh));
                        memcpy(&reversed_srh, skb_srh, 8);
                        reversed_srh.segments_left = reversed_srh.first_segment;

                        // Copy each element in reverse, ignoring the segment at index 0 because it will be the destination
                        #pragma clang loop unroll(full)
                        for (int i = 0; i < MAX_SEGS_NBR - 1; i++) {
                            // TODO 
                            if (i < reversed_srh.first_segment) {
                                if (skb_srh->segments + i + 2 <= skops->skb_data_end) {
                                    tmp = skb_srh->segments[i + 1];
                                    int idx = reversed_srh.first_segment - i;
                                    if (idx >= 0 && idx < MAX_SEGS_NBR) { // Check for the verifier
                                        reversed_srh.segments[idx] = tmp;
                                    }
                                }
                            }
                        }
                        move_path(&reversed_srh, skops);
                    } else {
                        bpf_debug("Not enough space for IPv6 SRH\n");
                    }
                } else {
                    bpf_debug("No IPv6 SRH\n");
                }
            }
            break;
	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";

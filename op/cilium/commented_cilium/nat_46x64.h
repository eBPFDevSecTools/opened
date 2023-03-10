/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_NAT_46X64__
#define __LIB_NAT_46X64__

#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "lib/csum.h"

#include "common.h"
#include "ipv4.h"
#include "ipv6.h"
#include "eth.h"

#define TCP_CSUM_OFF (offsetof(struct tcphdr, check))
#define UDP_CSUM_OFF (offsetof(struct udphdr, check))


/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 22,
  "endLine": 35,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat_46x64.h",
  "funcName": "is_v4_in_v6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const union v6addr *daddr"
  ],
  "output": "static__always_inline__maybe_unusedbool",
  "helper": [],
  "compatibleHookpoints": [
    "socket_filter",
    "lwt_seg6local",
    "cgroup_device",
    "lwt_xmit",
    "cgroup_sock",
    "xdp",
    "sock_ops",
    "sched_act",
    "sk_reuseport",
    "lwt_in",
    "flow_dissector",
    "perf_event",
    "sk_msg",
    "sk_skb",
    "tracepoint",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "lwt_out",
    "kprobe",
    "sched_cls",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "cgroup_skb"
  ],
  "source": [
    "static __always_inline __maybe_unused bool is_v4_in_v6 (const union v6addr *daddr)\n",
    "{\n",
    "    union v6addr dprobe = {\n",
    "        .addr [10] = 0xff,\n",
    "        .addr [11] = 0xff,}\n",
    "    ;\n",
    "    union v6addr dmasked = {\n",
    "        .d1 = daddr->d1,}\n",
    "    ;\n",
    "    dmasked.p3 = daddr->p3;\n",
    "    return ipv6_addrcmp (&dprobe, &dmasked) == 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "ipv6_addrcmp"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    null
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused bool is_v4_in_v6(const union v6addr *daddr)
{
	/* Check for ::FFFF:<IPv4 address>. */
	union v6addr dprobe  = {
		.addr[10] = 0xff,
		.addr[11] = 0xff,
	};
	union v6addr dmasked = {
		.d1 = daddr->d1,
	};

	dmasked.p3 = daddr->p3;
	return ipv6_addrcmp(&dprobe, &dmasked) == 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 37,
  "endLine": 44,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat_46x64.h",
  "funcName": "build_v4_in_v6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "union v6addr *daddr",
    " __be32 v4"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "socket_filter",
    "lwt_seg6local",
    "cgroup_device",
    "lwt_xmit",
    "cgroup_sock",
    "xdp",
    "sock_ops",
    "sched_act",
    "sk_reuseport",
    "lwt_in",
    "flow_dissector",
    "perf_event",
    "sk_msg",
    "sk_skb",
    "tracepoint",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "lwt_out",
    "kprobe",
    "sched_cls",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "cgroup_skb"
  ],
  "source": [
    "static __always_inline __maybe_unused void build_v4_in_v6 (union v6addr *daddr, __be32 v4)\n",
    "{\n",
    "    memset (daddr, 0, sizeof (*daddr));\n",
    "    daddr->addr[10] = 0xff;\n",
    "    daddr->addr[11] = 0xff;\n",
    "    daddr->p4 = v4;\n",
    "}\n"
  ],
  "called_function_list": [
    "memset"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    null
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused
void build_v4_in_v6(union v6addr *daddr, __be32 v4)
{
	memset(daddr, 0, sizeof(*daddr));
	daddr->addr[10] = 0xff;
	daddr->addr[11] = 0xff;
	daddr->p4 = v4;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 46,
  "endLine": 50,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat_46x64.h",
  "funcName": "build_v4_from_v6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const union v6addr *v6",
    " __be32 *daddr"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "socket_filter",
    "lwt_seg6local",
    "cgroup_device",
    "lwt_xmit",
    "cgroup_sock",
    "xdp",
    "sock_ops",
    "sched_act",
    "sk_reuseport",
    "lwt_in",
    "flow_dissector",
    "perf_event",
    "sk_msg",
    "sk_skb",
    "tracepoint",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "lwt_out",
    "kprobe",
    "sched_cls",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "cgroup_skb"
  ],
  "source": [
    "static __always_inline __maybe_unused void build_v4_from_v6 (const union v6addr *v6, __be32 *daddr)\n",
    "{\n",
    "    *daddr = v6->p4;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
    null
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused
void build_v4_from_v6(const union v6addr *v6, __be32 *daddr)
{
	*daddr = v6->p4;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 52,
  "endLine": 74,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat_46x64.h",
  "funcName": "get_csum_offset",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u8 protocol"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "socket_filter",
    "lwt_seg6local",
    "cgroup_device",
    "lwt_xmit",
    "cgroup_sock",
    "xdp",
    "sock_ops",
    "sched_act",
    "sk_reuseport",
    "lwt_in",
    "flow_dissector",
    "perf_event",
    "sk_msg",
    "sk_skb",
    "tracepoint",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "lwt_out",
    "kprobe",
    "sched_cls",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "cgroup_skb"
  ],
  "source": [
    "static __always_inline int get_csum_offset (__u8 protocol)\n",
    "{\n",
    "    int csum_off;\n",
    "    switch (protocol) {\n",
    "    case IPPROTO_TCP :\n",
    "        csum_off = TCP_CSUM_OFF;\n",
    "        break;\n",
    "    case IPPROTO_UDP :\n",
    "        csum_off = UDP_CSUM_OFF;\n",
    "        break;\n",
    "    case IPPROTO_ICMP :\n",
    "        csum_off = (offsetof (struct icmphdr, checksum));\n",
    "        break;\n",
    "    case IPPROTO_ICMPV6 :\n",
    "        csum_off = (offsetof (struct icmp6hdr, icmp6_cksum));\n",
    "        break;\n",
    "    default :\n",
    "        return DROP_UNKNOWN_L4;\n",
    "    }\n",
    "    return csum_off;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    null
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
static __always_inline int get_csum_offset(__u8 protocol)
{
	int csum_off;

	switch (protocol) {
	case IPPROTO_TCP:
		csum_off = TCP_CSUM_OFF;
		break;
	case IPPROTO_UDP:
		csum_off = UDP_CSUM_OFF;
		break;
	case IPPROTO_ICMP:
		csum_off = (offsetof(struct icmphdr, checksum));
		break;
	case IPPROTO_ICMPV6:
		csum_off = (offsetof(struct icmp6hdr, icmp6_cksum));
		break;
	default:
		return DROP_UNKNOWN_L4;
	}

	return csum_off;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "cilium",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with l3_csum_replace() and l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 76,
  "endLine": 154,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat_46x64.h",
  "funcName": "icmp4_to_icmp6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int nh_off"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "xdp",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "sched_cls",
    "lwt_xmit",
    "lwt_out"
  ],
  "source": [
    "static __always_inline int icmp4_to_icmp6 (struct  __ctx_buff *ctx, int nh_off)\n",
    "{\n",
    "    struct icmphdr icmp4 __align_stack_8;\n",
    "    struct icmp6hdr icmp6 __align_stack_8 = {}\n",
    "    ;\n",
    "    if (ctx_load_bytes (ctx, nh_off, &icmp4, sizeof (icmp4)) < 0)\n",
    "        return DROP_INVALID;\n",
    "    icmp6.icmp6_cksum = icmp4.checksum;\n",
    "    switch (icmp4.type) {\n",
    "    case ICMP_ECHO :\n",
    "        icmp6.icmp6_type = ICMPV6_ECHO_REQUEST;\n",
    "        icmp6.icmp6_identifier = icmp4.un.echo.id;\n",
    "        icmp6.icmp6_sequence = icmp4.un.echo.sequence;\n",
    "        break;\n",
    "    case ICMP_ECHOREPLY :\n",
    "        icmp6.icmp6_type = ICMPV6_ECHO_REPLY;\n",
    "        icmp6.icmp6_identifier = icmp4.un.echo.id;\n",
    "        icmp6.icmp6_sequence = icmp4.un.echo.sequence;\n",
    "        break;\n",
    "    case ICMP_DEST_UNREACH :\n",
    "        icmp6.icmp6_type = ICMPV6_DEST_UNREACH;\n",
    "        switch (icmp4.code) {\n",
    "        case ICMP_NET_UNREACH :\n",
    "        case ICMP_HOST_UNREACH :\n",
    "            icmp6.icmp6_code = ICMPV6_NOROUTE;\n",
    "            break;\n",
    "        case ICMP_PROT_UNREACH :\n",
    "            icmp6.icmp6_type = ICMPV6_PARAMPROB;\n",
    "            icmp6.icmp6_code = ICMPV6_UNK_NEXTHDR;\n",
    "            icmp6.icmp6_pointer = 6;\n",
    "            break;\n",
    "        case ICMP_PORT_UNREACH :\n",
    "            icmp6.icmp6_code = ICMPV6_PORT_UNREACH;\n",
    "            break;\n",
    "        case ICMP_FRAG_NEEDED :\n",
    "            icmp6.icmp6_type = ICMPV6_PKT_TOOBIG;\n",
    "            icmp6.icmp6_code = 0;\n",
    "            if (icmp4.un.frag.mtu)\n",
    "                icmp6.icmp6_mtu = bpf_htonl (bpf_ntohs (icmp4.un.frag.mtu));\n",
    "            else\n",
    "                icmp6.icmp6_mtu = bpf_htonl (1500);\n",
    "            break;\n",
    "        case ICMP_SR_FAILED :\n",
    "            icmp6.icmp6_code = ICMPV6_NOROUTE;\n",
    "            break;\n",
    "        case ICMP_NET_UNKNOWN :\n",
    "        case ICMP_HOST_UNKNOWN :\n",
    "        case ICMP_HOST_ISOLATED :\n",
    "        case ICMP_NET_UNR_TOS :\n",
    "        case ICMP_HOST_UNR_TOS :\n",
    "            icmp6.icmp6_code = 0;\n",
    "            break;\n",
    "        case ICMP_NET_ANO :\n",
    "        case ICMP_HOST_ANO :\n",
    "        case ICMP_PKT_FILTERED :\n",
    "            icmp6.icmp6_code = ICMPV6_ADM_PROHIBITED;\n",
    "            break;\n",
    "        default :\n",
    "            return DROP_UNKNOWN_ICMP_CODE;\n",
    "        }\n",
    "        break;\n",
    "    case ICMP_TIME_EXCEEDED :\n",
    "        icmp6.icmp6_type = ICMPV6_TIME_EXCEED;\n",
    "        break;\n",
    "    case ICMP_PARAMETERPROB :\n",
    "        icmp6.icmp6_type = ICMPV6_PARAMPROB;\n",
    "        icmp6.icmp6_pointer = 6;\n",
    "        break;\n",
    "    default :\n",
    "        return DROP_UNKNOWN_ICMP_TYPE;\n",
    "    }\n",
    "    if (ctx_store_bytes (ctx, nh_off, &icmp6, sizeof (icmp6), 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    icmp4.checksum = 0;\n",
    "    icmp6.icmp6_cksum = 0;\n",
    "    return csum_diff (&icmp4, sizeof (icmp4), &icmp6, sizeof (icmp6), 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_bytes",
    "bpf_htonl",
    "ctx_load_bytes",
    "bpf_ntohs"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    null
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
static __always_inline int icmp4_to_icmp6(struct __ctx_buff *ctx, int nh_off)
{
	struct icmphdr icmp4 __align_stack_8;
	struct icmp6hdr icmp6 __align_stack_8 = {};

	if (ctx_load_bytes(ctx, nh_off, &icmp4, sizeof(icmp4)) < 0)
		return DROP_INVALID;
	icmp6.icmp6_cksum = icmp4.checksum;
	switch (icmp4.type) {
	case ICMP_ECHO:
		icmp6.icmp6_type = ICMPV6_ECHO_REQUEST;
		icmp6.icmp6_identifier = icmp4.un.echo.id;
		icmp6.icmp6_sequence = icmp4.un.echo.sequence;
		break;
	case ICMP_ECHOREPLY:
		icmp6.icmp6_type = ICMPV6_ECHO_REPLY;
		icmp6.icmp6_identifier = icmp4.un.echo.id;
		icmp6.icmp6_sequence = icmp4.un.echo.sequence;
		break;
	case ICMP_DEST_UNREACH:
		icmp6.icmp6_type = ICMPV6_DEST_UNREACH;
		switch (icmp4.code) {
		case ICMP_NET_UNREACH:
		case ICMP_HOST_UNREACH:
			icmp6.icmp6_code = ICMPV6_NOROUTE;
			break;
		case ICMP_PROT_UNREACH:
			icmp6.icmp6_type = ICMPV6_PARAMPROB;
			icmp6.icmp6_code = ICMPV6_UNK_NEXTHDR;
			icmp6.icmp6_pointer = 6;
			break;
		case ICMP_PORT_UNREACH:
			icmp6.icmp6_code = ICMPV6_PORT_UNREACH;
			break;
		case ICMP_FRAG_NEEDED:
			icmp6.icmp6_type = ICMPV6_PKT_TOOBIG;
			icmp6.icmp6_code = 0;
			/* FIXME */
			if (icmp4.un.frag.mtu)
				icmp6.icmp6_mtu = bpf_htonl(bpf_ntohs(icmp4.un.frag.mtu));
			else
				icmp6.icmp6_mtu = bpf_htonl(1500);
			break;
		case ICMP_SR_FAILED:
			icmp6.icmp6_code = ICMPV6_NOROUTE;
			break;
		case ICMP_NET_UNKNOWN:
		case ICMP_HOST_UNKNOWN:
		case ICMP_HOST_ISOLATED:
		case ICMP_NET_UNR_TOS:
		case ICMP_HOST_UNR_TOS:
			icmp6.icmp6_code = 0;
			break;
		case ICMP_NET_ANO:
		case ICMP_HOST_ANO:
		case ICMP_PKT_FILTERED:
			icmp6.icmp6_code = ICMPV6_ADM_PROHIBITED;
			break;
		default:
			return DROP_UNKNOWN_ICMP_CODE;
		}
		break;
	case ICMP_TIME_EXCEEDED:
		icmp6.icmp6_type = ICMPV6_TIME_EXCEED;
		break;
	case ICMP_PARAMETERPROB:
		icmp6.icmp6_type = ICMPV6_PARAMPROB;
		/* FIXME */
		icmp6.icmp6_pointer = 6;
		break;
	default:
		return DROP_UNKNOWN_ICMP_TYPE;
	}
	if (ctx_store_bytes(ctx, nh_off, &icmp6, sizeof(icmp6), 0) < 0)
		return DROP_WRITE_ERROR;
	icmp4.checksum = 0;
	icmp6.icmp6_cksum = 0;
	return csum_diff(&icmp4, sizeof(icmp4), &icmp6, sizeof(icmp6), 0);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "cilium",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with l3_csum_replace() and l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 156,
  "endLine": 231,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat_46x64.h",
  "funcName": "icmp6_to_icmp4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int nh_off"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "xdp",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "sched_cls",
    "lwt_xmit",
    "lwt_out"
  ],
  "source": [
    "static __always_inline int icmp6_to_icmp4 (struct  __ctx_buff *ctx, int nh_off)\n",
    "{\n",
    "    struct icmphdr icmp4 __align_stack_8 = {}\n",
    "    ;\n",
    "    struct icmp6hdr icmp6 __align_stack_8;\n",
    "    __u32 mtu;\n",
    "    if (ctx_load_bytes (ctx, nh_off, &icmp6, sizeof (icmp6)) < 0)\n",
    "        return DROP_INVALID;\n",
    "    icmp4.checksum = icmp6.icmp6_cksum;\n",
    "    switch (icmp6.icmp6_type) {\n",
    "    case ICMPV6_ECHO_REQUEST :\n",
    "        icmp4.type = ICMP_ECHO;\n",
    "        icmp4.un.echo.id = icmp6.icmp6_identifier;\n",
    "        icmp4.un.echo.sequence = icmp6.icmp6_sequence;\n",
    "        break;\n",
    "    case ICMPV6_ECHO_REPLY :\n",
    "        icmp4.type = ICMP_ECHOREPLY;\n",
    "        icmp4.un.echo.id = icmp6.icmp6_identifier;\n",
    "        icmp4.un.echo.sequence = icmp6.icmp6_sequence;\n",
    "        break;\n",
    "    case ICMPV6_DEST_UNREACH :\n",
    "        icmp4.type = ICMP_DEST_UNREACH;\n",
    "        switch (icmp6.icmp6_code) {\n",
    "        case ICMPV6_NOROUTE :\n",
    "        case ICMPV6_NOT_NEIGHBOUR :\n",
    "        case ICMPV6_ADDR_UNREACH :\n",
    "            icmp4.code = ICMP_HOST_UNREACH;\n",
    "            break;\n",
    "        case ICMPV6_ADM_PROHIBITED :\n",
    "            icmp4.code = ICMP_HOST_ANO;\n",
    "            break;\n",
    "        case ICMPV6_PORT_UNREACH :\n",
    "            icmp4.code = ICMP_PORT_UNREACH;\n",
    "            break;\n",
    "        default :\n",
    "            return DROP_UNKNOWN_ICMP6_CODE;\n",
    "        }\n",
    "        break;\n",
    "    case ICMPV6_PKT_TOOBIG :\n",
    "        icmp4.type = ICMP_DEST_UNREACH;\n",
    "        icmp4.code = ICMP_FRAG_NEEDED;\n",
    "        if (icmp6.icmp6_mtu) {\n",
    "            mtu = bpf_ntohl (icmp6.icmp6_mtu);\n",
    "            icmp4.un.frag.mtu = bpf_htons ((__u16) mtu);\n",
    "        }\n",
    "        else {\n",
    "            icmp4.un.frag.mtu = bpf_htons (1500);\n",
    "        }\n",
    "        break;\n",
    "    case ICMPV6_TIME_EXCEED :\n",
    "        icmp4.type = ICMP_TIME_EXCEEDED;\n",
    "        icmp4.code = icmp6.icmp6_code;\n",
    "        break;\n",
    "    case ICMPV6_PARAMPROB :\n",
    "        switch (icmp6.icmp6_code) {\n",
    "        case ICMPV6_HDR_FIELD :\n",
    "            icmp4.type = ICMP_PARAMETERPROB;\n",
    "            icmp4.code = 0;\n",
    "            break;\n",
    "        case ICMPV6_UNK_NEXTHDR :\n",
    "            icmp4.type = ICMP_DEST_UNREACH;\n",
    "            icmp4.code = ICMP_PROT_UNREACH;\n",
    "            break;\n",
    "        default :\n",
    "            return DROP_UNKNOWN_ICMP6_CODE;\n",
    "        }\n",
    "        break;\n",
    "    default :\n",
    "        return DROP_UNKNOWN_ICMP6_TYPE;\n",
    "    }\n",
    "    if (ctx_store_bytes (ctx, nh_off, &icmp4, sizeof (icmp4), 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    icmp4.checksum = 0;\n",
    "    icmp6.icmp6_cksum = 0;\n",
    "    return csum_diff (&icmp6, sizeof (icmp6), &icmp4, sizeof (icmp4), 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_ntohl",
    "ctx_store_bytes",
    "bpf_htons",
    "ctx_load_bytes"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    null
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
static __always_inline int icmp6_to_icmp4(struct __ctx_buff *ctx, int nh_off)
{
	struct icmphdr icmp4 __align_stack_8 = {};
	struct icmp6hdr icmp6 __align_stack_8;
	__u32 mtu;

	if (ctx_load_bytes(ctx, nh_off, &icmp6, sizeof(icmp6)) < 0)
		return DROP_INVALID;
	icmp4.checksum = icmp6.icmp6_cksum;
	switch (icmp6.icmp6_type) {
	case ICMPV6_ECHO_REQUEST:
		icmp4.type = ICMP_ECHO;
		icmp4.un.echo.id = icmp6.icmp6_identifier;
		icmp4.un.echo.sequence = icmp6.icmp6_sequence;
		break;
	case ICMPV6_ECHO_REPLY:
		icmp4.type = ICMP_ECHOREPLY;
		icmp4.un.echo.id = icmp6.icmp6_identifier;
		icmp4.un.echo.sequence = icmp6.icmp6_sequence;
		break;
	case ICMPV6_DEST_UNREACH:
		icmp4.type = ICMP_DEST_UNREACH;
		switch (icmp6.icmp6_code) {
		case ICMPV6_NOROUTE:
		case ICMPV6_NOT_NEIGHBOUR:
		case ICMPV6_ADDR_UNREACH:
			icmp4.code = ICMP_HOST_UNREACH;
			break;
		case ICMPV6_ADM_PROHIBITED:
			icmp4.code = ICMP_HOST_ANO;
			break;
		case ICMPV6_PORT_UNREACH:
			icmp4.code = ICMP_PORT_UNREACH;
			break;
		default:
			return DROP_UNKNOWN_ICMP6_CODE;
		}
		break;
	case ICMPV6_PKT_TOOBIG:
		icmp4.type = ICMP_DEST_UNREACH;
		icmp4.code = ICMP_FRAG_NEEDED;
		/* FIXME */
		if (icmp6.icmp6_mtu) {
			mtu = bpf_ntohl(icmp6.icmp6_mtu);
			icmp4.un.frag.mtu = bpf_htons((__u16)mtu);
		} else {
			icmp4.un.frag.mtu = bpf_htons(1500);
		}
		break;
	case ICMPV6_TIME_EXCEED:
		icmp4.type = ICMP_TIME_EXCEEDED;
		icmp4.code = icmp6.icmp6_code;
		break;
	case ICMPV6_PARAMPROB:
		switch (icmp6.icmp6_code) {
		case ICMPV6_HDR_FIELD:
			icmp4.type = ICMP_PARAMETERPROB;
			icmp4.code = 0;
			break;
		case ICMPV6_UNK_NEXTHDR:
			icmp4.type = ICMP_DEST_UNREACH;
			icmp4.code = ICMP_PROT_UNREACH;
			break;
		default:
			return DROP_UNKNOWN_ICMP6_CODE;
		}
		break;
	default:
		return DROP_UNKNOWN_ICMP6_TYPE;
	}
	if (ctx_store_bytes(ctx, nh_off, &icmp4, sizeof(icmp4), 0) < 0)
		return DROP_WRITE_ERROR;
	icmp4.checksum = 0;
	icmp6.icmp6_cksum = 0;
	return csum_diff(&icmp6, sizeof(icmp6), &icmp4, sizeof(icmp4), 0);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "cilium",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with l3_csum_replace() and l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    },
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Recompute the layer 4 (e. g. TCP , UDP or ICMP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored on the lowest four bits of flags. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and the four lowest bits of <[ flags ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. In addition <[ to ]>(IP: 3) the size of the field , <[ flags ]>(IP: 4) can be added (bitwise OR) actual flags. With BPF_F_MARK_MANGLED_0 , a null checksum is left untouched (unless BPF_F_MARK_ENFORCE is added as well) , and for updates resulting in a null checksum the value is set <[ to ]>(IP: 3) CSUM_MANGLED_0 instead. Flag BPF_F_PSEUDO_HDR indicates the checksum is <[ to ]>(IP: 3) be computed against a pseudo-header. This helper works in combination with csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "l4_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 233,
  "endLine": 288,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat_46x64.h",
  "funcName": "ipv4_to_ipv6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int nh_off",
    " const union v6addr *src6",
    " const union v6addr *dst6"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff",
    "l4_csum_replace"
  ],
  "compatibleHookpoints": [
    "sched_act",
    "lwt_xmit",
    "sched_cls"
  ],
  "source": [
    "static __always_inline int ipv4_to_ipv6 (struct  __ctx_buff *ctx, int nh_off, const union v6addr *src6, const union v6addr *dst6)\n",
    "{\n",
    "    __be16 protocol = bpf_htons (ETH_P_IPV6);\n",
    "    __u64 csum_flags = BPF_F_PSEUDO_HDR;\n",
    "    struct ipv6hdr v6 = {}\n",
    "    ;\n",
    "    struct iphdr v4;\n",
    "    int csum_off;\n",
    "    __be32 csum;\n",
    "    __be16 v4hdr_len;\n",
    "    if (ctx_load_bytes (ctx, nh_off, &v4, sizeof (v4)) < 0)\n",
    "        return DROP_INVALID;\n",
    "    if (ipv4_hdrlen (&v4) != sizeof (v4))\n",
    "        return DROP_INVALID_EXTHDR;\n",
    "    v6.version = 0x6;\n",
    "    v6.saddr.in6_u.u6_addr32[0] = src6->p1;\n",
    "    v6.saddr.in6_u.u6_addr32[1] = src6->p2;\n",
    "    v6.saddr.in6_u.u6_addr32[2] = src6->p3;\n",
    "    v6.saddr.in6_u.u6_addr32[3] = src6->p4;\n",
    "    v6.daddr.in6_u.u6_addr32[0] = dst6->p1;\n",
    "    v6.daddr.in6_u.u6_addr32[1] = dst6->p2;\n",
    "    v6.daddr.in6_u.u6_addr32[2] = dst6->p3;\n",
    "    v6.daddr.in6_u.u6_addr32[3] = dst6->p4;\n",
    "    if (v4.protocol == IPPROTO_ICMP)\n",
    "        v6.nexthdr = IPPROTO_ICMPV6;\n",
    "    else\n",
    "        v6.nexthdr = v4.protocol;\n",
    "    v6.hop_limit = v4.ttl;\n",
    "    v4hdr_len = (__be16) (v4.ihl << 2);\n",
    "    v6.payload_len = bpf_htons (bpf_ntohs (v4.tot_len) - v4hdr_len);\n",
    "    if (ctx_change_proto (ctx, bpf_htons (ETH_P_IPV6), 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (ctx_store_bytes (ctx, nh_off, &v6, sizeof (v6), 0) < 0 || ctx_store_bytes (ctx, nh_off - 2, &protocol, 2, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (v4.protocol == IPPROTO_ICMP) {\n",
    "        csum = icmp4_to_icmp6 (ctx, nh_off + sizeof (v6));\n",
    "        csum = ipv6_pseudohdr_checksum (& v6, IPPROTO_ICMPV6, bpf_ntohs (v6.payload_len), csum);\n",
    "    }\n",
    "    else {\n",
    "        csum = 0;\n",
    "        csum = csum_diff (& v4.saddr, 4, & v6.saddr, 16, csum);\n",
    "        csum = csum_diff (& v4.daddr, 4, & v6.daddr, 16, csum);\n",
    "        if (v4.protocol == IPPROTO_UDP)\n",
    "            csum_flags |= BPF_F_MARK_MANGLED_0;\n",
    "    }\n",
    "    csum_off = get_csum_offset (v6.nexthdr);\n",
    "    if (csum_off < 0)\n",
    "        return csum_off;\n",
    "    csum_off += sizeof (struct ipv6hdr);\n",
    "    if (l4_csum_replace (ctx, nh_off + csum_off, 0, csum, csum_flags) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "ipv6_pseudohdr_checksum",
    "ctx_store_bytes",
    "ipv4_hdrlen",
    "bpf_htons",
    "ctx_load_bytes",
    "ctx_change_proto",
    "bpf_ntohs",
    "icmp4_to_icmp6",
    "get_csum_offset"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    null
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
static __always_inline int ipv4_to_ipv6(struct __ctx_buff *ctx, int nh_off,
					const union v6addr *src6,
					const union v6addr *dst6)
{
	__be16 protocol = bpf_htons(ETH_P_IPV6);
	__u64 csum_flags = BPF_F_PSEUDO_HDR;
	struct ipv6hdr v6 = {};
	struct iphdr v4;
	int csum_off;
	__be32 csum;
	__be16 v4hdr_len;

	if (ctx_load_bytes(ctx, nh_off, &v4, sizeof(v4)) < 0)
		return DROP_INVALID;
	if (ipv4_hdrlen(&v4) != sizeof(v4))
		return DROP_INVALID_EXTHDR;
	v6.version = 0x6;
	v6.saddr.in6_u.u6_addr32[0] = src6->p1;
	v6.saddr.in6_u.u6_addr32[1] = src6->p2;
	v6.saddr.in6_u.u6_addr32[2] = src6->p3;
	v6.saddr.in6_u.u6_addr32[3] = src6->p4;
	v6.daddr.in6_u.u6_addr32[0] = dst6->p1;
	v6.daddr.in6_u.u6_addr32[1] = dst6->p2;
	v6.daddr.in6_u.u6_addr32[2] = dst6->p3;
	v6.daddr.in6_u.u6_addr32[3] = dst6->p4;
	if (v4.protocol == IPPROTO_ICMP)
		v6.nexthdr = IPPROTO_ICMPV6;
	else
		v6.nexthdr = v4.protocol;
	v6.hop_limit = v4.ttl;
	v4hdr_len = (__be16)(v4.ihl << 2);
	v6.payload_len = bpf_htons(bpf_ntohs(v4.tot_len) - v4hdr_len);
	if (ctx_change_proto(ctx, bpf_htons(ETH_P_IPV6), 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, nh_off, &v6, sizeof(v6), 0) < 0 ||
	    ctx_store_bytes(ctx, nh_off - 2, &protocol, 2, 0) < 0)
		return DROP_WRITE_ERROR;
	if (v4.protocol == IPPROTO_ICMP) {
		csum = icmp4_to_icmp6(ctx, nh_off + sizeof(v6));
		csum = ipv6_pseudohdr_checksum(&v6, IPPROTO_ICMPV6,
					       bpf_ntohs(v6.payload_len), csum);
	} else {
		csum = 0;
		csum = csum_diff(&v4.saddr, 4, &v6.saddr, 16, csum);
		csum = csum_diff(&v4.daddr, 4, &v6.daddr, 16, csum);
		if (v4.protocol == IPPROTO_UDP)
			csum_flags |= BPF_F_MARK_MANGLED_0;
	}
	csum_off = get_csum_offset(v6.nexthdr);
	if (csum_off < 0)
		return csum_off;
	csum_off += sizeof(struct ipv6hdr);
	if (l4_csum_replace(ctx, nh_off + csum_off, 0, csum, csum_flags) < 0)
		return DROP_CSUM_L4;
	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "cilium",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with l3_csum_replace() and l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    },
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Recompute the layer 4 (e. g. TCP , UDP or ICMP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored on the lowest four bits of flags. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and the four lowest bits of <[ flags ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. In addition <[ to ]>(IP: 3) the size of the field , <[ flags ]>(IP: 4) can be added (bitwise OR) actual flags. With BPF_F_MARK_MANGLED_0 , a null checksum is left untouched (unless BPF_F_MARK_ENFORCE is added as well) , and for updates resulting in a null checksum the value is set <[ to ]>(IP: 3) CSUM_MANGLED_0 instead. Flag BPF_F_PSEUDO_HDR indicates the checksum is <[ to ]>(IP: 3) be computed against a pseudo-header. This helper works in combination with csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "l4_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Recompute the layer 3 (e. g. IP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored in size. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and <[ size ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. This helper works in combination with csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "l3_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: size}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 290,
  "endLine": 345,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat_46x64.h",
  "funcName": "ipv6_to_ipv4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __be32 src4",
    " __be32 dst4"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff",
    "l4_csum_replace",
    "l3_csum_replace"
  ],
  "compatibleHookpoints": [
    "sched_act",
    "lwt_xmit",
    "sched_cls"
  ],
  "source": [
    "static __always_inline int ipv6_to_ipv4 (struct  __ctx_buff *ctx, __be32 src4, __be32 dst4)\n",
    "{\n",
    "    __be16 protocol = bpf_htons (ETH_P_IP);\n",
    "    __u64 csum_flags = BPF_F_PSEUDO_HDR;\n",
    "    int csum_off, nh_off = ETH_HLEN;\n",
    "    struct ipv6hdr v6;\n",
    "    struct iphdr v4 = {}\n",
    "    ;\n",
    "    __be32 csum = 0;\n",
    "    if (ctx_load_bytes (ctx, nh_off, &v6, sizeof (v6)) < 0)\n",
    "        return DROP_INVALID;\n",
    "    if (ipv6_hdrlen (ctx, &v6.nexthdr) != sizeof (v6))\n",
    "        return DROP_INVALID_EXTHDR;\n",
    "    v4.ihl = 0x5;\n",
    "    v4.version = 0x4;\n",
    "    v4.saddr = src4;\n",
    "    v4.daddr = dst4;\n",
    "    if (v6.nexthdr == IPPROTO_ICMPV6)\n",
    "        v4.protocol = IPPROTO_ICMP;\n",
    "    else\n",
    "        v4.protocol = v6.nexthdr;\n",
    "    v4.ttl = v6.hop_limit;\n",
    "    v4.tot_len = bpf_htons (bpf_ntohs (v6.payload_len) + sizeof (v4));\n",
    "    csum_off = offsetof (struct iphdr, check);\n",
    "    csum = csum_diff (NULL, 0, & v4, sizeof (v4), csum);\n",
    "    if (ctx_change_proto (ctx, bpf_htons (ETH_P_IP), 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (ctx_store_bytes (ctx, nh_off, &v4, sizeof (v4), 0) < 0 || ctx_store_bytes (ctx, nh_off - 2, &protocol, 2, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (l3_csum_replace (ctx, nh_off + csum_off, 0, csum, 0) < 0)\n",
    "        return DROP_CSUM_L3;\n",
    "    if (v6.nexthdr == IPPROTO_ICMPV6) {\n",
    "        __be32 csum1 = 0;\n",
    "        csum = icmp6_to_icmp4 (ctx, nh_off + sizeof (v4));\n",
    "        csum1 = ipv6_pseudohdr_checksum (& v6, IPPROTO_ICMPV6, bpf_ntohs (v6.payload_len), 0);\n",
    "        csum = csum_sub (csum, csum1);\n",
    "    }\n",
    "    else {\n",
    "        csum = 0;\n",
    "        csum = csum_diff (& v6.saddr, 16, & v4.saddr, 4, csum);\n",
    "        csum = csum_diff (& v6.daddr, 16, & v4.daddr, 4, csum);\n",
    "        if (v4.protocol == IPPROTO_UDP)\n",
    "            csum_flags |= BPF_F_MARK_MANGLED_0;\n",
    "    }\n",
    "    csum_off = get_csum_offset (v4.protocol);\n",
    "    if (csum_off < 0)\n",
    "        return csum_off;\n",
    "    csum_off += sizeof (struct iphdr);\n",
    "    if (l4_csum_replace (ctx, nh_off + csum_off, 0, csum, csum_flags) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "icmp6_to_icmp4",
    "ipv6_pseudohdr_checksum",
    "csum_sub",
    "ctx_store_bytes",
    "ipv6_hdrlen",
    "offsetof",
    "bpf_htons",
    "ctx_load_bytes",
    "ctx_change_proto",
    "bpf_ntohs",
    "get_csum_offset"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    null
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
static __always_inline int ipv6_to_ipv4(struct __ctx_buff *ctx,
					__be32 src4, __be32 dst4)
{
	__be16 protocol = bpf_htons(ETH_P_IP);
	__u64 csum_flags = BPF_F_PSEUDO_HDR;
	int csum_off, nh_off = ETH_HLEN;
	struct ipv6hdr v6;
	struct iphdr v4 = {};
	__be32 csum = 0;

	if (ctx_load_bytes(ctx, nh_off, &v6, sizeof(v6)) < 0)
		return DROP_INVALID;
	/* Drop frames which carry extensions headers */
	if (ipv6_hdrlen(ctx, &v6.nexthdr) != sizeof(v6))
		return DROP_INVALID_EXTHDR;
	v4.ihl = 0x5;
	v4.version = 0x4;
	v4.saddr = src4;
	v4.daddr = dst4;
	if (v6.nexthdr == IPPROTO_ICMPV6)
		v4.protocol = IPPROTO_ICMP;
	else
		v4.protocol = v6.nexthdr;
	v4.ttl = v6.hop_limit;
	v4.tot_len = bpf_htons(bpf_ntohs(v6.payload_len) + sizeof(v4));
	csum_off = offsetof(struct iphdr, check);
	csum = csum_diff(NULL, 0, &v4, sizeof(v4), csum);
	if (ctx_change_proto(ctx, bpf_htons(ETH_P_IP), 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, nh_off, &v4, sizeof(v4), 0) < 0 ||
	    ctx_store_bytes(ctx, nh_off - 2, &protocol, 2, 0) < 0)
		return DROP_WRITE_ERROR;
	if (l3_csum_replace(ctx, nh_off + csum_off, 0, csum, 0) < 0)
		return DROP_CSUM_L3;
	if (v6.nexthdr == IPPROTO_ICMPV6) {
		__be32 csum1 = 0;

		csum = icmp6_to_icmp4(ctx, nh_off + sizeof(v4));
		csum1 = ipv6_pseudohdr_checksum(&v6, IPPROTO_ICMPV6,
						bpf_ntohs(v6.payload_len), 0);
		csum = csum_sub(csum, csum1);
	} else {
		csum = 0;
		csum = csum_diff(&v6.saddr, 16, &v4.saddr, 4, csum);
		csum = csum_diff(&v6.daddr, 16, &v4.daddr, 4, csum);
		if (v4.protocol == IPPROTO_UDP)
			csum_flags |= BPF_F_MARK_MANGLED_0;
	}
	csum_off = get_csum_offset(v4.protocol);
	if (csum_off < 0)
		return csum_off;
	csum_off += sizeof(struct iphdr);
	if (l4_csum_replace(ctx, nh_off + csum_off, 0, csum, csum_flags) < 0)
		return DROP_CSUM_L4;
	return 0;
}

#endif /* __LIB_NAT_46X64__ */

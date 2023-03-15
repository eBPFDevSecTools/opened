// +build ignore
#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "common.h"
#include "ingress_node_firewall.h"
#include <inttypes.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sctp.h>

#define MAX_CPUS		256

// FIXME: Hack this structure defined in linux/sctp.h however I am getting incomplete type when I reference it
struct sctphdr {
    __be16 source;
    __be16 dest;
    __be32 vtag;
    __le32 checksum;
};

/*
 * ingress_node_firewall_events_map: is perf event array map type
 * key is the rule id, packet header is captured and used to generate events.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_CPUS);
} ingress_node_firewall_events_map SEC(".maps");

/*
 * ingress_node_firewall_statistics_map: is per cpu array map type
 * key is the rule id
 * user space collects statistics per CPU and aggregate them.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32); // ruleId
    __type(value, struct ruleStatistics_st);
    __uint(max_entries, MAX_TARGETS);
} ingress_node_firewall_statistics_map SEC(".maps");

/*
 * ingress_node_firewall_table_map: is LPM trie map type
 * key is the ingress interface index and the sourceCIDR.
 * lookup returns an array of rules with actions for the XDP program
 * to process.
 * Note: this map is pinned to specific path in bpffs.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_ip_key_st);
    __type(value, struct rulesVal_st);
    __uint(max_entries, MAX_TARGETS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_node_firewall_table_map SEC(".maps");

/*
 * ip_extract_l4info(): extracts L4 info for the supported protocols from
 * the incoming packet's headers.
 * Input:
 * void *dataStart : pointer to packet start in memory.
 * void *dataEnd: pointer to packet end in memory.
 * bool is_v4: true for ipv4 and false for ipv6.
 * Output:
 * __u8 *proto: L4 protocol type supported types are TCP/UDP/SCTP/ICMP/ICMPv6.
 * __u16 *dstPort: pointer to L4 destination port for TCP/UDP/SCTP protocols.
 * __u8 *icmpType: pointer to ICMP or ICMPv6's type value.
 * __u8 *icmpCode: pointer to ICMP or ICMPv6's code value.
 * Return:
 * 0 for Success.
 * -1 for Failure.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 84,
  "endLine": 160,
  "File": "/home/sayandes/opened_extraction/examples/ingress-node-firewall-master/bpf/ingress_node_firewall_kernel.c",
  "funcName": "ip_extract_l4info",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "// +build ignore"
    },
    {
      "start_line": 21,
      "end_line": 21,
      "text": "// FIXME: Hack this structure defined in linux/sctp.h however I am getting incomplete type when I reference it"
    },
    {
      "start_line": 29,
      "end_line": 32,
      "text": "/*\n * ingress_node_firewall_events_map: is perf event array map type\n * key is the rule id, packet header is captured and used to generate events.\n */"
    },
    {
      "start_line": 40,
      "end_line": 44,
      "text": "/*\n * ingress_node_firewall_statistics_map: is per cpu array map type\n * key is the rule id\n * user space collects statistics per CPU and aggregate them.\n */"
    },
    {
      "start_line": 47,
      "end_line": 47,
      "text": "// ruleId"
    },
    {
      "start_line": 52,
      "end_line": 58,
      "text": "/*\n * ingress_node_firewall_table_map: is LPM trie map type\n * key is the ingress interface index and the sourceCIDR.\n * lookup returns an array of rules with actions for the XDP program\n * to process.\n * Note: this map is pinned to specific path in bpffs.\n */"
    },
    {
      "start_line": 68,
      "end_line": 83,
      "text": "/*\n * ip_extract_l4info(): extracts L4 info for the supported protocols from\n * the incoming packet's headers.\n * Input:\n * void *dataStart : pointer to packet start in memory.\n * void *dataEnd: pointer to packet end in memory.\n * bool is_v4: true for ipv4 and false for ipv6.\n * Output:\n * __u8 *proto: L4 protocol type supported types are TCP/UDP/SCTP/ICMP/ICMPv6.\n * __u16 *dstPort: pointer to L4 destination port for TCP/UDP/SCTP protocols.\n * __u8 *icmpType: pointer to ICMP or ICMPv6's type value.\n * __u8 *icmpCode: pointer to ICMP or ICMPv6's code value.\n * Return:\n * 0 for Success.\n * -1 for Failure.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *dataStart",
    " void *dataEnd",
    " __u8 *proto",
    " __u16 *dstPort",
    " __u8 *icmpType",
    " __u8 *icmpCode",
    " __u8 is_v4"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "sched_act",
    "cgroup_sysctl",
    "sk_reuseport",
    "sk_skb",
    "cgroup_sock_addr",
    "sched_cls",
    "cgroup_sock",
    "lwt_xmit",
    "sk_msg",
    "flow_dissector",
    "perf_event",
    "xdp",
    "raw_tracepoint",
    "socket_filter",
    "lwt_out",
    "kprobe",
    "lwt_in",
    "lwt_seg6local",
    "cgroup_skb",
    "tracepoint",
    "raw_tracepoint_writable",
    "sock_ops"
  ],
  "source": [
    "static inline int ip_extract_l4info (void *dataStart, void *dataEnd, __u8 *proto, __u16 *dstPort, __u8 *icmpType, __u8 *icmpCode, __u8 is_v4)\n",
    "{\n",
    "    if (likely (is_v4)) {\n",
    "        struct iphdr *iph = dataStart;\n",
    "        dataStart += sizeof (struct iphdr);\n",
    "        if (unlikely (dataStart > dataEnd)) {\n",
    "            return -1;\n",
    "        }\n",
    "        *proto = iph->protocol;\n",
    "    }\n",
    "    else {\n",
    "        struct ipv6hdr *iph = dataStart;\n",
    "        dataStart += sizeof (struct ipv6hdr);\n",
    "        if (unlikely (dataStart > dataEnd)) {\n",
    "            return -1;\n",
    "        }\n",
    "        *proto = iph->nexthdr;\n",
    "    }\n",
    "    switch (*proto) {\n",
    "    case IPPROTO_TCP :\n",
    "        {\n",
    "            struct tcphdr *tcph = (struct tcphdr *) dataStart;\n",
    "            dataStart += sizeof (struct tcphdr);\n",
    "            if (unlikely (dataStart > dataEnd)) {\n",
    "                return -1;\n",
    "            }\n",
    "            *dstPort = tcph->dest;\n",
    "            break;\n",
    "        }\n",
    "    case IPPROTO_UDP :\n",
    "        {\n",
    "            struct udphdr *udph = (struct udphdr *) dataStart;\n",
    "            dataStart += sizeof (struct udphdr);\n",
    "            if (unlikely (dataStart > dataEnd)) {\n",
    "                return -1;\n",
    "            }\n",
    "            *dstPort = udph->dest;\n",
    "            break;\n",
    "        }\n",
    "    case IPPROTO_SCTP :\n",
    "        {\n",
    "            struct sctphdr *sctph = (struct sctphdr *) dataStart;\n",
    "            dataStart += sizeof (struct sctphdr);\n",
    "            if (unlikely (dataStart > dataEnd)) {\n",
    "                return -1;\n",
    "            }\n",
    "            *dstPort = sctph->dest;\n",
    "            break;\n",
    "        }\n",
    "    case IPPROTO_ICMP :\n",
    "        {\n",
    "            struct icmphdr *icmph = (struct icmphdr *) dataStart;\n",
    "            dataStart += sizeof (struct icmphdr);\n",
    "            if (unlikely (dataStart > dataEnd)) {\n",
    "                return -1;\n",
    "            }\n",
    "            *icmpType = icmph->type;\n",
    "            *icmpCode = icmph->code;\n",
    "            break;\n",
    "        }\n",
    "    case IPPROTO_ICMPV6 :\n",
    "        {\n",
    "            struct icmp6hdr *icmp6h = (struct icmp6hdr *) dataStart;\n",
    "            dataStart += sizeof (struct icmp6hdr);\n",
    "            if (unlikely (dataStart > dataEnd)) {\n",
    "                return -1;\n",
    "            }\n",
    "            *icmpType = icmp6h->icmp6_type;\n",
    "            *icmpCode = icmp6h->icmp6_code;\n",
    "            break;\n",
    "        }\n",
    "    default :\n",
    "        return -1;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "unlikely",
    "likely"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {}
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
__attribute__((__always_inline__)) static inline int
ip_extract_l4info(void *dataStart, void *dataEnd, __u8 *proto, __u16 *dstPort,
                  __u8 *icmpType, __u8 *icmpCode, __u8 is_v4) {

    if (likely(is_v4)) {
        struct iphdr *iph = dataStart;
        dataStart += sizeof(struct iphdr);
        if (unlikely(dataStart > dataEnd)) {
            return -1;
        }
        *proto = iph->protocol;
    } else {
        struct ipv6hdr *iph = dataStart;
        dataStart += sizeof(struct ipv6hdr);
        if (unlikely(dataStart > dataEnd)) {
            return -1;
        }
        *proto = iph->nexthdr;
    }
    switch (*proto) {
    case IPPROTO_TCP:
        {
            struct tcphdr *tcph = (struct tcphdr *)dataStart;
            dataStart += sizeof(struct tcphdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *dstPort = tcph->dest;
            break;
        }
    case IPPROTO_UDP:
        {
            struct udphdr *udph = (struct udphdr *)dataStart;
            dataStart += sizeof(struct udphdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *dstPort = udph->dest;
            break;
        }
    case IPPROTO_SCTP:
        {
            struct sctphdr *sctph = (struct sctphdr *)dataStart;
            dataStart += sizeof(struct sctphdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *dstPort = sctph->dest;
            break;
        }
    case IPPROTO_ICMP:
        {
            struct icmphdr *icmph = (struct icmphdr *)dataStart;
            dataStart += sizeof(struct icmphdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *icmpType = icmph->type;
            *icmpCode = icmph->code;
            break;
        }
    case IPPROTO_ICMPV6:
        {
            struct icmp6hdr *icmp6h = (struct icmp6hdr *)dataStart;
            dataStart += sizeof(struct icmp6hdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *icmpType = icmp6h->icmp6_type;
            *icmpCode = icmp6h->icmp6_code;
            break;
        }
    default:
        return -1;
    }
    return 0;
}

/*
 * ipv4_firewall_lookup(): matches ipv4 packet with LPM map's key,
 * match L4 headers with the result rules in order and return the action.
 * if there is no match it will return UNDEF action.
 * Input:
 * void *dataStart: pointer to packet start in memory.
 * void *dataEnd: pointer to packet end in memory.
 * __u32 ifID: ingress interface index where the packet is received from.
 * Output:
 * none.
 * Return:
 * __u32 action: returned action is the logical or of the rule id and action field
 * from the matching rule, in case of no match it returns UNDEF.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 176,
  "endLine": 242,
  "File": "/home/sayandes/opened_extraction/examples/ingress-node-firewall-master/bpf/ingress_node_firewall_kernel.c",
  "funcName": "ipv4_firewall_lookup",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 14,
      "text": "/*\n * ipv4_firewall_lookup(): matches ipv4 packet with LPM map's key,\n * match L4 headers with the result rules in order and return the action.\n * if there is no match it will return UNDEF action.\n * Input:\n * void *dataStart: pointer to packet start in memory.\n * void *dataEnd: pointer to packet end in memory.\n * __u32 ifID: ingress interface index where the packet is received from.\n * Output:\n * none.\n * Return:\n * __u32 action: returned action is the logical or of the rule id and action field\n * from the matching rule, in case of no match it returns UNDEF.\n */"
    },
    {
      "start_line": 29,
      "end_line": 29,
      "text": "// ipv4 address + ifId"
    },
    {
      "start_line": 73,
      "end_line": 73,
      "text": "// Protocol is not set so just apply the action"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " ingress_node_firewall_table_map"
  ],
  "input": [
    "void *dataStart",
    " void *dataEnd",
    " __u32 ifId"
  ],
  "output": "staticinline__u32",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "sched_act",
    "cgroup_sysctl",
    "sk_reuseport",
    "sk_skb",
    "cgroup_sock_addr",
    "sched_cls",
    "cgroup_sock",
    "lwt_xmit",
    "sk_msg",
    "flow_dissector",
    "perf_event",
    "xdp",
    "raw_tracepoint",
    "socket_filter",
    "lwt_out",
    "kprobe",
    "lwt_in",
    "lwt_seg6local",
    "cgroup_skb",
    "tracepoint",
    "raw_tracepoint_writable",
    "sock_ops"
  ],
  "source": [
    "static inline __u32 ipv4_firewall_lookup (void *dataStart, void *dataEnd, __u32 ifId)\n",
    "{\n",
    "    struct iphdr *iph = dataStart;\n",
    "    struct lpm_ip_key_st key;\n",
    "    __u32 srcAddr = iph->saddr;\n",
    "    __u16 dstPort = 0;\n",
    "    __u8 icmpCode = 0, icmpType = 0, proto = 0;\n",
    "    int i;\n",
    "    if (ip_extract_l4info (dataStart, dataEnd, &proto, &dstPort, &icmpType, &icmpCode, 1) < 0) {\n",
    "        bpf_printk (\"failed to extract l4 info\");\n",
    "        return SET_ACTION (UNDEF);\n",
    "    }\n",
    "    memset (&key, 0, sizeof (key));\n",
    "    key.prefixLen = 64;\n",
    "    key.ip_data[0] = srcAddr & 0xFF;\n",
    "    key.ip_data[1] = (srcAddr >> 8) & 0xFF;\n",
    "    key.ip_data[2] = (srcAddr >> 16) & 0xFF;\n",
    "    key.ip_data[3] = (srcAddr >> 24) & 0xFF;\n",
    "    key.ingress_ifindex = ifId;\n",
    "    struct rulesVal_st *rulesVal = (struct rulesVal_st *) bpf_map_lookup_elem (&ingress_node_firewall_table_map, &key);\n",
    "    if (likely (NULL != rulesVal)) {\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "        for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {\n",
    "            struct ruleType_st *rule = &rulesVal->rules[i];\n",
    "            if (rule->ruleId == INVALID_RULE_ID) {\n",
    "                continue;\n",
    "            }\n",
    "            if (likely ((rule->protocol != 0) && (rule->protocol == proto))) {\n",
    "                bpf_printk (\"ruleInfo (protocol %d, Id %d, action %d)\", rule->protocol, rule->ruleId, rule->action);\n",
    "                if ((rule->protocol == IPPROTO_TCP) || (rule->protocol == IPPROTO_UDP) || (rule->protocol == IPPROTO_SCTP)) {\n",
    "                    bpf_printk (\"TCP/UDP/SCTP packet rule_dstPortStart %d rule_dstPortEnd %d pkt_dstPort %d\", rule->dstPortStart, rule->dstPortEnd, bpf_ntohs (dstPort));\n",
    "                    if (rule->dstPortEnd == 0) {\n",
    "                        if (rule->dstPortStart == bpf_ntohs (dstPort)) {\n",
    "                            return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "                        }\n",
    "                    }\n",
    "                    else {\n",
    "                        if ((bpf_ntohs (dstPort) >= rule->dstPortStart) && (bpf_ntohs (dstPort) < rule->dstPortEnd)) {\n",
    "                            return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "                        }\n",
    "                    }\n",
    "                }\n",
    "                if (rule->protocol == IPPROTO_ICMP) {\n",
    "                    bpf_printk (\"ICMP packet rule(type:%d, code:%d) pkt(type:%d, code %d)\", rule->icmpType, rule->icmpCode, icmpType, icmpCode);\n",
    "                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {\n",
    "                        return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "                    }\n",
    "                }\n",
    "            }\n",
    "            if (rule->protocol == 0) {\n",
    "                return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "            }\n",
    "        }\n",
    "        bpf_printk (\"Packet didn't match any rule proto %d port %d\", proto, bpf_ntohs (dstPort));\n",
    "    }\n",
    "    return SET_ACTION (UNDEF);\n",
    "}\n"
  ],
  "called_function_list": [
    "SET_ACTION",
    "memset",
    "unroll",
    "bpf_ntohs",
    "bpf_printk",
    "likely",
    "ip_extract_l4info",
    "SET_ACTIONRULE_RESPONSE"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {}
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
__attribute__((__always_inline__)) static inline __u32
ipv4_firewall_lookup(void *dataStart, void *dataEnd, __u32 ifId) {
    struct iphdr *iph = dataStart;
    struct lpm_ip_key_st key;
    __u32 srcAddr = iph->saddr;
    __u16 dstPort = 0;
    __u8 icmpCode = 0, icmpType = 0, proto = 0;
    int i;

    if (ip_extract_l4info(dataStart, dataEnd, &proto, &dstPort, &icmpType, &icmpCode, 1) < 0) {
        bpf_printk("failed to extract l4 info");
        return SET_ACTION(UNDEF);
    }
    memset(&key, 0, sizeof(key));
    key.prefixLen = 64; // ipv4 address + ifId
    key.ip_data[0] = srcAddr & 0xFF;
    key.ip_data[1] = (srcAddr >> 8) & 0xFF;
    key.ip_data[2] = (srcAddr >> 16) & 0xFF;
    key.ip_data[3] = (srcAddr >> 24) & 0xFF;
    key.ingress_ifindex = ifId;

    struct rulesVal_st *rulesVal = (struct rulesVal_st *)bpf_map_lookup_elem(
        &ingress_node_firewall_table_map, &key);


    if (likely(NULL != rulesVal)) {
#pragma clang loop unroll(full)
        for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {
            struct ruleType_st *rule = &rulesVal->rules[i];
            if (rule->ruleId == INVALID_RULE_ID) {
                continue;
            }

            if (likely((rule->protocol != 0) && (rule->protocol == proto))) {
                bpf_printk("ruleInfo (protocol %d, Id %d, action %d)", rule->protocol, rule->ruleId, rule->action);
                if ((rule->protocol == IPPROTO_TCP) ||
                    (rule->protocol == IPPROTO_UDP) ||
                    (rule->protocol == IPPROTO_SCTP)) {
                    bpf_printk("TCP/UDP/SCTP packet rule_dstPortStart %d rule_dstPortEnd %d pkt_dstPort %d",
                    rule->dstPortStart, rule->dstPortEnd, bpf_ntohs(dstPort));
                    if (rule->dstPortEnd == 0 ) {
                        if (rule->dstPortStart == bpf_ntohs(dstPort)) {
                            return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                        }
                    } else {
                        if ((bpf_ntohs(dstPort) >= rule->dstPortStart) && (bpf_ntohs(dstPort) < rule->dstPortEnd)) {
                            return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                        }
                    }
                }

                if (rule->protocol == IPPROTO_ICMP) {
                    bpf_printk("ICMP packet rule(type:%d, code:%d) pkt(type:%d, code %d)", rule->icmpType, rule->icmpCode, icmpType, icmpCode);
                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                    }
                }
            }
            // Protocol is not set so just apply the action
            if (rule->protocol == 0) {
                return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
            }
        }
        bpf_printk("Packet didn't match any rule proto %d port %d", proto, bpf_ntohs(dstPort));
    }
    return SET_ACTION(UNDEF);
}

/*
 * ipv6_firewall_lookup(): matches ipv6 packet with LPM map's key,
 * match L4 headers with the result rules in order and return the action.
 * if there is no rule match it will return UNDEF action.
 * Input:
 * void *dataStart: pointer to packet start in memory.
 * void *dataEnd: pointer to packet end in memory.
 * __u32 ifID: ingress interface index where the packet is received from.
 * Output:
 * none.
 * Return:
 __u32 action: returned action is the logical or of the rule id and action field
 * from the matching rule, in case of no match it returns UNDEF.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 258,
  "endLine": 318,
  "File": "/home/sayandes/opened_extraction/examples/ingress-node-firewall-master/bpf/ingress_node_firewall_kernel.c",
  "funcName": "ipv6_firewall_lookup",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 14,
      "text": "/*\n * ipv6_firewall_lookup(): matches ipv6 packet with LPM map's key,\n * match L4 headers with the result rules in order and return the action.\n * if there is no rule match it will return UNDEF action.\n * Input:\n * void *dataStart: pointer to packet start in memory.\n * void *dataEnd: pointer to packet end in memory.\n * __u32 ifID: ingress interface index where the packet is received from.\n * Output:\n * none.\n * Return:\n __u32 action: returned action is the logical or of the rule id and action field\n * from the matching rule, in case of no match it returns UNDEF.\n */"
    },
    {
      "start_line": 28,
      "end_line": 28,
      "text": "// ipv6 address _ ifId"
    },
    {
      "start_line": 67,
      "end_line": 67,
      "text": "// Protocol is not set so just apply the action"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " ingress_node_firewall_table_map"
  ],
  "input": [
    "void *dataStart",
    " void *dataEnd",
    " __u32 ifId"
  ],
  "output": "staticinline__u32",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "sched_act",
    "cgroup_sysctl",
    "sk_reuseport",
    "sk_skb",
    "cgroup_sock_addr",
    "sched_cls",
    "cgroup_sock",
    "lwt_xmit",
    "sk_msg",
    "flow_dissector",
    "perf_event",
    "xdp",
    "raw_tracepoint",
    "socket_filter",
    "lwt_out",
    "kprobe",
    "lwt_in",
    "lwt_seg6local",
    "cgroup_skb",
    "tracepoint",
    "raw_tracepoint_writable",
    "sock_ops"
  ],
  "source": [
    "static inline __u32 ipv6_firewall_lookup (void *dataStart, void *dataEnd, __u32 ifId)\n",
    "{\n",
    "    struct ipv6hdr *iph = dataStart;\n",
    "    struct lpm_ip_key_st key;\n",
    "    __u8 *srcAddr = iph->saddr.in6_u.u6_addr8;\n",
    "    __u16 dstPort = 0;\n",
    "    __u8 icmpCode = 0, icmpType = 0, proto = 0;\n",
    "    int i;\n",
    "    if (ip_extract_l4info (dataStart, dataEnd, &proto, &dstPort, &icmpType, &icmpCode, 0) < 0) {\n",
    "        return SET_ACTION (UNDEF);\n",
    "    }\n",
    "    memset (&key, 0, sizeof (key));\n",
    "    key.prefixLen = 160;\n",
    "    memcpy (key.ip_data, srcAddr, 16);\n",
    "    key.ingress_ifindex = ifId;\n",
    "    struct rulesVal_st *rulesVal = (struct rulesVal_st *) bpf_map_lookup_elem (&ingress_node_firewall_table_map, &key);\n",
    "    if (NULL != rulesVal) {\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "        for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {\n",
    "            struct ruleType_st *rule = &rulesVal->rules[i];\n",
    "            if (rule->ruleId == INVALID_RULE_ID) {\n",
    "                continue;\n",
    "            }\n",
    "            if (likely ((rule->protocol != 0) && (rule->protocol == proto))) {\n",
    "                bpf_printk (\"ruleInfo (protocol %d, Id %d, action %d)\", rule->protocol, rule->ruleId, rule->action);\n",
    "                if ((rule->protocol == IPPROTO_TCP) || (rule->protocol == IPPROTO_UDP) || (rule->protocol == IPPROTO_SCTP)) {\n",
    "                    bpf_printk (\"TCP/UDP/SCTP packet rule_dstPortStart %d rule_dstPortEnd %d pkt_dstPort %d\", rule->dstPortStart, rule->dstPortEnd, bpf_ntohs (dstPort));\n",
    "                    if (rule->dstPortEnd == 0) {\n",
    "                        if (rule->dstPortStart == bpf_ntohs (dstPort)) {\n",
    "                            return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "                        }\n",
    "                    }\n",
    "                    else {\n",
    "                        if ((bpf_ntohs (dstPort) >= rule->dstPortStart) && (bpf_ntohs (dstPort) < rule->dstPortEnd)) {\n",
    "                            return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "                        }\n",
    "                    }\n",
    "                }\n",
    "                if (rule->protocol == IPPROTO_ICMPV6) {\n",
    "                    bpf_printk (\"ICMPV6 packet rule(type:%d, code:%d) pkt(type:%d, code %d)\", rule->icmpType, rule->icmpCode, icmpType, icmpCode);\n",
    "                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {\n",
    "                        return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "                    }\n",
    "                }\n",
    "            }\n",
    "            if (rule->protocol == 0) {\n",
    "                return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "            }\n",
    "        }\n",
    "        bpf_printk (\"Packet didn't match any rule proto %d port %d\", proto, bpf_ntohs (dstPort));\n",
    "    }\n",
    "    return SET_ACTION (UNDEF);\n",
    "}\n"
  ],
  "called_function_list": [
    "SET_ACTION",
    "memset",
    "unroll",
    "bpf_ntohs",
    "bpf_printk",
    "likely",
    "memcpy",
    "ip_extract_l4info",
    "SET_ACTIONRULE_RESPONSE"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {}
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
__attribute__((__always_inline__)) static inline __u32
ipv6_firewall_lookup(void *dataStart, void *dataEnd, __u32 ifId) {
    struct ipv6hdr *iph = dataStart;
    struct lpm_ip_key_st key;
    __u8 *srcAddr = iph->saddr.in6_u.u6_addr8;
    __u16 dstPort = 0;
    __u8 icmpCode = 0, icmpType = 0, proto = 0;
    int i;

    if (ip_extract_l4info(dataStart, dataEnd, &proto, &dstPort, &icmpType, &icmpCode, 0) < 0) {
        return SET_ACTION(UNDEF);
    }
    memset(&key, 0, sizeof(key));
    key.prefixLen = 160; // ipv6 address _ ifId
    memcpy(key.ip_data, srcAddr, 16);
    key.ingress_ifindex = ifId;

    struct rulesVal_st *rulesVal = (struct rulesVal_st *)bpf_map_lookup_elem(
        &ingress_node_firewall_table_map, &key);

    if (NULL != rulesVal) {
#pragma clang loop unroll(full)
        for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {
            struct ruleType_st *rule = &rulesVal->rules[i];
            if (rule->ruleId == INVALID_RULE_ID) {
                continue;
            }
            if (likely((rule->protocol != 0) && (rule->protocol == proto))) {
                bpf_printk("ruleInfo (protocol %d, Id %d, action %d)", rule->protocol, rule->ruleId, rule->action);
                if ((rule->protocol == IPPROTO_TCP) ||
                    (rule->protocol == IPPROTO_UDP) ||
                    (rule->protocol == IPPROTO_SCTP)) {
                    bpf_printk("TCP/UDP/SCTP packet rule_dstPortStart %d rule_dstPortEnd %d pkt_dstPort %d",
                        rule->dstPortStart, rule->dstPortEnd, bpf_ntohs(dstPort));
                    if (rule->dstPortEnd == 0) {
                        if (rule->dstPortStart == bpf_ntohs(dstPort)) {
                            return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                        }
                    } else {
                        if ((bpf_ntohs(dstPort) >= rule->dstPortStart) && (bpf_ntohs(dstPort) < rule->dstPortEnd)) {
                            return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                        }
                    }
                }

                if (rule->protocol == IPPROTO_ICMPV6) {
                    bpf_printk("ICMPV6 packet rule(type:%d, code:%d) pkt(type:%d, code %d)", rule->icmpType, rule->icmpCode, icmpType, icmpCode);
                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                    }
                }
            }
            // Protocol is not set so just apply the action
            if (rule->protocol == 0) {
                return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
            }
        }
        bpf_printk("Packet didn't match any rule proto %d port %d", proto, bpf_ntohs(dstPort));
    }
    return SET_ACTION(UNDEF);
}

/*
 * generate_event_and_update_statistics() : it will generate eBPF event including the packet header
 * and update statistics for the specificed rule id.
 * Input:
 * struct xdp_md *ctx: pointer to XDP context including input interface and packet pointer.
 * __u16 packet_len: packet length in bytes including layer2 header.
 * __u8 action: valid actions ALLOW/DENY/UNDEF.
 * __u16 ruleId: ruled id where the packet matches against (in case of match of course).
 * __u8 generateEvent: need to generate event for this packet or not.
 * __u32 ifID: input interface index where the packet is arrived from.
 * Output:
 * none.
 * Return:
 * none.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_update"
          ]
        }
      ]
    },
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "libbpf",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "bpf_map_lookup_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_read"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 335,
  "endLine": 374,
  "File": "/home/sayandes/opened_extraction/examples/ingress-node-firewall-master/bpf/ingress_node_firewall_kernel.c",
  "funcName": "generate_event_and_update_statistics",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 15,
      "text": "/*\n * generate_event_and_update_statistics() : it will generate eBPF event including the packet header\n * and update statistics for the specificed rule id.\n * Input:\n * struct xdp_md *ctx: pointer to XDP context including input interface and packet pointer.\n * __u16 packet_len: packet length in bytes including layer2 header.\n * __u8 action: valid actions ALLOW/DENY/UNDEF.\n * __u16 ruleId: ruled id where the packet matches against (in case of match of course).\n * __u8 generateEvent: need to generate event for this packet or not.\n * __u32 ifID: input interface index where the packet is arrived from.\n * Output:\n * none.\n * Return:\n * none.\n */"
    },
    {
      "start_line": 49,
      "end_line": 49,
      "text": "// enable the following flag to dump packet header"
    }
  ],
  "updateMaps": [
    " ingress_node_firewall_statistics_map"
  ],
  "readMaps": [
    "  ingress_node_firewall_statistics_map"
  ],
  "input": [
    "struct xdp_md *ctx",
    " __u16 packet_len",
    " __u8 action",
    " __u16 ruleId",
    " __u8 generateEvent",
    " __u32 ifId"
  ],
  "output": "staticinlinevoid",
  "helper": [
    "bpf_map_update_elem",
    "bpf_map_lookup_elem",
    "bpf_perf_event_output"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "lwt_xmit",
    "lwt_out",
    "sched_act",
    "kprobe",
    "lwt_in",
    "perf_event",
    "xdp",
    "sk_skb",
    "raw_tracepoint",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "raw_tracepoint_writable",
    "sock_ops",
    "socket_filter"
  ],
  "source": [
    "static inline void generate_event_and_update_statistics (struct xdp_md *ctx, __u16 packet_len, __u8 action, __u16 ruleId, __u8 generateEvent, __u32 ifId)\n",
    "{\n",
    "    struct ruleStatistics_st *statistics, initialStats;\n",
    "    struct event_hdr_st hdr;\n",
    "    __u64 flags = BPF_F_CURRENT_CPU;\n",
    "    __u16 headerSize;\n",
    "    __u32 key = ruleId;\n",
    "    memset (&hdr, 0, sizeof (hdr));\n",
    "    hdr.ruleId = ruleId;\n",
    "    hdr.action = action;\n",
    "    hdr.pktLength = (__u16) packet_len;\n",
    "    hdr.ifId = (__u16) ifId;\n",
    "    memset (&initialStats, 0, sizeof (initialStats));\n",
    "    statistics = bpf_map_lookup_elem (& ingress_node_firewall_statistics_map, & key);\n",
    "    if (likely (statistics)) {\n",
    "        switch (action) {\n",
    "        case ALLOW :\n",
    "            __sync_fetch_and_add (&statistics->allow_stats.packets, 1);\n",
    "            __sync_fetch_and_add (&statistics->allow_stats.bytes, packet_len);\n",
    "            break;\n",
    "        case DENY :\n",
    "            __sync_fetch_and_add (&statistics->deny_stats.packets, 1);\n",
    "            __sync_fetch_and_add (&statistics->deny_stats.bytes, packet_len);\n",
    "            break;\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        bpf_map_update_elem (&ingress_node_firewall_statistics_map, &key, &initialStats, BPF_ANY);\n",
    "    }\n",
    "    if (generateEvent) {\n",
    "        headerSize = packet_len < MAX_EVENT_DATA ? packet_len : MAX_EVENT_DATA;\n",
    "        flags |= (__u64) headerSize << 32;\n",
    "        (void) bpf_perf_event_output (ctx, &ingress_node_firewall_events_map, flags, &hdr, sizeof (hdr));\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "__sync_fetch_and_add",
    "memset",
    "likely"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {}
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
__attribute__((__always_inline__)) static inline void
generate_event_and_update_statistics(struct xdp_md *ctx, __u16 packet_len, __u8 action, __u16 ruleId, __u8 generateEvent, __u32 ifId) {
    struct ruleStatistics_st *statistics, initialStats;
    struct event_hdr_st hdr;
    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 headerSize;
    __u32 key = ruleId;

    memset(&hdr, 0, sizeof(hdr));
    hdr.ruleId = ruleId;
    hdr.action = action;
    hdr.pktLength = (__u16)packet_len;
    hdr.ifId = (__u16)ifId;

    memset(&initialStats, 0, sizeof(initialStats));
    statistics = bpf_map_lookup_elem(&ingress_node_firewall_statistics_map, &key);
    if (likely(statistics)) {
        switch (action) {
        case ALLOW:
            __sync_fetch_and_add(&statistics->allow_stats.packets, 1);
            __sync_fetch_and_add(&statistics->allow_stats.bytes, packet_len);
            break;
        case DENY:
            __sync_fetch_and_add(&statistics->deny_stats.packets, 1);
            __sync_fetch_and_add(&statistics->deny_stats.bytes, packet_len);
            break;
        }
    } else {
        bpf_map_update_elem(&ingress_node_firewall_statistics_map, &key, &initialStats, BPF_ANY);
    }

    if (generateEvent) {
        headerSize = packet_len < MAX_EVENT_DATA ? packet_len : MAX_EVENT_DATA;
        // enable the following flag to dump packet header
        flags |= (__u64)headerSize << 32;

        (void)bpf_perf_event_output(ctx, &ingress_node_firewall_events_map, flags,
                                    &hdr, sizeof(hdr));
    }
}

/*
 * ingress_node_firewall_main(): is the entry point for the XDP program to do
 * ingress node firewall.
 * Input:
 * struct xdp_md *ctx: pointer to XDP context which contains packet pointer and input interface index.
 * Output:
 * none.
 * Return:
 * int XDP action: valid values XDP_DROP and XDP_PASS.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    },
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 386,
  "endLine": 431,
  "File": "/home/sayandes/opened_extraction/examples/ingress-node-firewall-master/bpf/ingress_node_firewall_kernel.c",
  "funcName": "ingress_node_firewall_main",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 10,
      "text": "/*\n * ingress_node_firewall_main(): is the entry point for the XDP program to do\n * ingress node firewall.\n * Input:\n * struct xdp_md *ctx: pointer to XDP context which contains packet pointer and input interface index.\n * Output:\n * none.\n * Return:\n * int XDP action: valid values XDP_DROP and XDP_PASS.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "staticinlineint",
  "helper": [
    "XDP_DROP",
    "XDP_PASS"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static inline int ingress_node_firewall_main (struct xdp_md *ctx)\n",
    "{\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    void *dataEnd = (void *) (long) ctx->data_end;\n",
    "    struct ethhdr *eth = data;\n",
    "    void *dataStart = data + sizeof (struct ethhdr);\n",
    "    __u32 result = UNDEF;\n",
    "    __u32 ifId = ctx->ingress_ifindex;\n",
    "    bpf_printk (\"Ingress node firewall start processing a packet on %d\", ifId);\n",
    "    if (unlikely (dataStart > dataEnd)) {\n",
    "        bpf_printk (\"Ingress node firewall bad packet XDP_DROP\");\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    switch (eth->h_proto) {\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        bpf_printk (\"Ingress node firewall process IPv4 packet\");\n",
    "        result = ipv4_firewall_lookup (dataStart, dataEnd, ifId);\n",
    "        break;\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        bpf_printk (\"Ingress node firewall process IPv6 packet\");\n",
    "        result = ipv6_firewall_lookup (dataStart, dataEnd, ifId);\n",
    "        break;\n",
    "    default :\n",
    "        bpf_printk (\"Ingress node firewall unknown L3 protocol XDP_PASS\");\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "    __u16 ruleId = GET_RULE_ID (result);\n",
    "    __u8 action = GET_ACTION (result);\n",
    "    switch (action) {\n",
    "    case DENY :\n",
    "        generate_event_and_update_statistics (ctx, (__u16) (dataEnd - data), DENY, ruleId, 1, ifId);\n",
    "        bpf_printk (\"Ingress node firewall action DENY -> XDP_DROP\");\n",
    "        return XDP_DROP;\n",
    "    case ALLOW :\n",
    "        generate_event_and_update_statistics (ctx, (__u16) (dataEnd - data), ALLOW, ruleId, 0, ifId);\n",
    "        bpf_printk (\"Ingress node firewall action ALLOW -> XDP_PASS\");\n",
    "        return XDP_PASS;\n",
    "    default :\n",
    "        bpf_printk (\"Ingress node firewall action UNDEF\");\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "ipv4_firewall_lookup",
    "generate_event_and_update_statistics",
    "bpf_htons",
    "unlikely",
    "GET_ACTION",
    "bpf_printk",
    "GET_RULE_ID",
    "ipv6_firewall_lookup"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {}
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
__attribute__((__always_inline__)) static inline int
ingress_node_firewall_main(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *dataEnd = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    void *dataStart = data + sizeof(struct ethhdr);
    __u32 result = UNDEF;
    __u32 ifId = ctx->ingress_ifindex;

    bpf_printk("Ingress node firewall start processing a packet on %d", ifId);
    if (unlikely(dataStart > dataEnd)) {
        bpf_printk("Ingress node firewall bad packet XDP_DROP");
        return XDP_DROP;
    }

    switch (eth->h_proto) {
    case bpf_htons(ETH_P_IP):
        bpf_printk("Ingress node firewall process IPv4 packet");
        result = ipv4_firewall_lookup(dataStart, dataEnd, ifId);
        break;
    case bpf_htons(ETH_P_IPV6):
        bpf_printk("Ingress node firewall process IPv6 packet");
        result = ipv6_firewall_lookup(dataStart, dataEnd, ifId);
        break;
    default:
        bpf_printk("Ingress node firewall unknown L3 protocol XDP_PASS");
        return XDP_PASS;
    }

    __u16 ruleId = GET_RULE_ID(result);
    __u8 action = GET_ACTION(result);

    switch (action) {
    case DENY:
        generate_event_and_update_statistics(ctx, (__u16)(dataEnd - data), DENY, ruleId, 1, ifId);
        bpf_printk("Ingress node firewall action DENY -> XDP_DROP");
        return XDP_DROP;
    case ALLOW:
        generate_event_and_update_statistics(ctx, (__u16)(dataEnd - data), ALLOW, ruleId, 0, ifId);
        bpf_printk("Ingress node firewall action ALLOW -> XDP_PASS");
        return XDP_PASS;
    default:
        bpf_printk("Ingress node firewall action UNDEF");
        return XDP_PASS;
    }
}

SEC("xdp_ingress_node_firewall_process")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 434,
  "endLine": 436,
  "File": "/home/sayandes/opened_extraction/examples/ingress-node-firewall-master/bpf/ingress_node_firewall_kernel.c",
  "funcName": "ingress_node_firewall_process",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "sched_act",
    "cgroup_sysctl",
    "sk_reuseport",
    "sk_skb",
    "cgroup_sock_addr",
    "sched_cls",
    "cgroup_sock",
    "lwt_xmit",
    "sk_msg",
    "flow_dissector",
    "perf_event",
    "xdp",
    "raw_tracepoint",
    "socket_filter",
    "lwt_out",
    "kprobe",
    "lwt_in",
    "lwt_seg6local",
    "cgroup_skb",
    "tracepoint",
    "raw_tracepoint_writable",
    "sock_ops"
  ],
  "source": [
    "int ingress_node_firewall_process (struct xdp_md *ctx)\n",
    "{\n",
    "    return ingress_node_firewall_main (ctx);\n",
    "}\n"
  ],
  "called_function_list": [
    "ingress_node_firewall_main"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {}
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
int ingress_node_firewall_process(struct xdp_md *ctx) {
    return ingress_node_firewall_main(ctx);
}

char __license[] SEC("license") = "Dual BSD/GPL";

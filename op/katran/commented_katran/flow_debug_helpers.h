/* Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __FLOW_DEBUG_HELPERS_H
#define __FLOW_DEBUG_HELPERS_H

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "flow_debug_maps.h"

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 29,
  "endLine": 53,
  "File": "/home/sayandes/opened_extraction/examples/katran/flow_debug_helpers.h",
  "funcName": "get_next_ports",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 15,
      "text": "/* Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.\n *\n * This program is free software; you can redistribute it and/or modify\n * it under the terms of the GNU General Public License as published by\n * the Free Software Foundation; version 2 of the License.\n *\n * This program is distributed in the hope that it will be useful,\n * but WITHOUT ANY WARRANTY; without even the implied warranty of\n * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n * GNU General Public License for more details.\n *\n * You should have received a copy of the GNU General Public License along\n * with this program; if not, write to the Free Software Foundation, Inc.,\n * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *transport_hdr",
    " __u8 proto",
    " void *data_end"
  ],
  "output": "staticinline__u32",
  "helper": [],
  "compatibleHookpoints": [
    "kprobe",
    "cgroup_skb",
    "sk_skb",
    "cgroup_device",
    "tracepoint",
    "socket_filter",
    "xdp",
    "raw_tracepoint_writable",
    "flow_dissector",
    "lwt_seg6local",
    "sched_cls",
    "lwt_out",
    "sched_act",
    "cgroup_sysctl",
    "cgroup_sock_addr",
    "sk_reuseport",
    "lwt_xmit",
    "sock_ops",
    "perf_event",
    "raw_tracepoint",
    "sk_msg",
    "lwt_in",
    "cgroup_sock"
  ],
  "source": [
    "static inline __u32 get_next_ports (void *transport_hdr, __u8 proto, void *data_end)\n",
    "{\n",
    "    __u32 ports = 0;\n",
    "    struct udphdr *udph = 0;\n",
    "    struct tcphdr *tcph = 0;\n",
    "    switch (proto) {\n",
    "    case IPPROTO_UDP :\n",
    "        udph = transport_hdr;\n",
    "        if ((void *) udph + sizeof (struct udphdr) <= data_end) {\n",
    "            ports = (bpf_ntohs (udph->dest) << 16) | bpf_ntohs (udph->source);\n",
    "        }\n",
    "        break;\n",
    "    case IPPROTO_TCP :\n",
    "        tcph = transport_hdr;\n",
    "        if ((void *) tcph + sizeof (struct tcphdr) <= data_end) {\n",
    "            ports = (bpf_ntohs (tcph->dest) << 16) | bpf_ntohs (tcph->source);\n",
    "        }\n",
    "        break;\n",
    "    default :\n",
    "        break;\n",
    "    }\n",
    "    return ports;\n",
    "}\n"
  ],
  "called_function_list": [
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
__attribute__((__always_inline__)) static inline __u32
get_next_ports(void* transport_hdr, __u8 proto, void* data_end) {
  __u32 ports = 0;
  struct udphdr* udph = 0;
  struct tcphdr* tcph = 0;

  switch (proto) {
    case IPPROTO_UDP:
      udph = transport_hdr;
      if ((void*)udph + sizeof(struct udphdr) <= data_end) {
        ports = (bpf_ntohs(udph->dest) << 16) | bpf_ntohs(udph->source);
      }
      break;
    case IPPROTO_TCP:
      tcph = transport_hdr;
      if ((void*)tcph + sizeof(struct tcphdr) <= data_end) {
        ports = (bpf_ntohs(tcph->dest) << 16) | bpf_ntohs(tcph->source);
      }
      break;
    default:
      break;
  }

  return ports;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "libbpf",
          "Return Type": "u32",
          "Description": "Get the SMP (symmetric multiprocessing) processor id. Note that all programs run with preemption disabled , which means that the SMP processor id is stable during all the execution of the program. ",
          "Return": " The SMP id of the processor running the program.",
          "Function Name": "bpf_get_smp_processor_id",
          "Input Params": [
            "{Type: voi ,Var: void}"
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
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 55,
  "endLine": 128,
  "File": "/home/sayandes/opened_extraction/examples/katran/flow_debug_helpers.h",
  "funcName": "gue_record_route",
  "developer_inline_comments": [
    {
      "start_line": 15,
      "end_line": 20,
      "text": "/*XXX\nvoid* flow_debug_map = bpf_map_lookup_elem(&flow_debug_maps, &cpu_num);\n  if (!flow_debug_map) {\n    return;\n  }\n  */"
    },
    {
      "start_line": 70,
      "end_line": 72,
      "text": "/* XXX\n  bpf_map_update_elem(flow_debug_map, &flow, &debug_info, BPF_ANY);\n  */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ethhdr *outer_eth",
    " struct ethhdr *inner_eth",
    " void *data_end",
    " bool outer_v4",
    " bool inner_v4"
  ],
  "output": "staticinlinevoid",
  "helper": [
    "bpf_get_smp_processor_id"
  ],
  "compatibleHookpoints": [
    "kprobe",
    "cgroup_skb",
    "sk_skb",
    "tracepoint",
    "socket_filter",
    "xdp",
    "raw_tracepoint_writable",
    "flow_dissector",
    "lwt_seg6local",
    "sched_cls",
    "lwt_out",
    "sched_act",
    "cgroup_sock_addr",
    "sk_reuseport",
    "lwt_xmit",
    "sock_ops",
    "perf_event",
    "raw_tracepoint",
    "sk_msg",
    "lwt_in",
    "cgroup_sock"
  ],
  "source": [
    "static inline void gue_record_route (struct ethhdr *outer_eth, struct ethhdr *inner_eth, void *data_end, bool outer_v4, bool inner_v4)\n",
    "{\n",
    "    struct flow_key flow = {0}\n",
    "    ;\n",
    "    struct flow_debug_info debug_info = {0}\n",
    "    ;\n",
    "    struct ipv6hdr *ip6h = 0;\n",
    "    struct iphdr *ip4h = 0;\n",
    "    void *transport_header = 0;\n",
    "    __u32 cpu_num = bpf_get_smp_processor_id ();\n",
    "    if (outer_v4) {\n",
    "        if ((void *) outer_eth + sizeof (struct ethhdr) + sizeof (struct iphdr) > data_end) {\n",
    "            return;\n",
    "        }\n",
    "        ip4h = (void *) outer_eth + sizeof (struct ethhdr);\n",
    "        debug_info.l4_hop = ip4h->saddr;\n",
    "        debug_info.this_hop = ip4h->daddr;\n",
    "    }\n",
    "    else {\n",
    "        if ((void *) outer_eth + sizeof (struct ethhdr) + sizeof (struct ipv6hdr) > data_end) {\n",
    "            return;\n",
    "        }\n",
    "        ip6h = (void *) outer_eth + sizeof (struct ethhdr);\n",
    "        __builtin_memcpy (debug_info.l4_hopv6, ip6h->saddr.s6_addr32, sizeof (debug_info.l4_hopv6));\n",
    "        __builtin_memcpy (debug_info.this_hopv6, ip6h->daddr.s6_addr32, sizeof (debug_info.this_hopv6));\n",
    "    }\n",
    "    if (inner_v4) {\n",
    "        if ((void *) inner_eth + sizeof (struct ethhdr) + sizeof (struct iphdr) > data_end) {\n",
    "            return;\n",
    "        }\n",
    "        ip4h = (void *) inner_eth + sizeof (struct ethhdr);\n",
    "        transport_header = (void *) inner_eth + sizeof (struct ethhdr) + sizeof (struct iphdr);\n",
    "        flow.src = ip4h->saddr;\n",
    "        flow.dst = ip4h->daddr;\n",
    "        flow.proto = ip4h->protocol;\n",
    "        flow.ports = get_next_ports (transport_header, ip4h->protocol, data_end);\n",
    "    }\n",
    "    else {\n",
    "        if ((void *) inner_eth + sizeof (struct ethhdr) + sizeof (struct ipv6hdr) > data_end) {\n",
    "            return;\n",
    "        }\n",
    "        ip6h = (void *) inner_eth + sizeof (struct ethhdr);\n",
    "        transport_header = (void *) inner_eth + sizeof (struct ethhdr) + sizeof (struct ipv6hdr);\n",
    "        __builtin_memcpy (flow.srcv6, ip6h->saddr.s6_addr32, sizeof (flow.srcv6));\n",
    "        __builtin_memcpy (flow.dstv6, ip6h->daddr.s6_addr32, sizeof (flow.dstv6));\n",
    "        flow.proto = ip6h->nexthdr;\n",
    "        flow.ports = get_next_ports (transport_header, ip6h->nexthdr, data_end);\n",
    "    }\n",
    "    return;\n",
    "}\n"
  ],
  "called_function_list": [
    "__builtin_memcpy",
    "get_next_ports"
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
__attribute__((__always_inline__)) static inline void gue_record_route(
    struct ethhdr* outer_eth,
    struct ethhdr* inner_eth,
    void* data_end,
    bool outer_v4,
    bool inner_v4) {
  struct flow_key flow = {0};
  struct flow_debug_info debug_info = {0};
  struct ipv6hdr* ip6h = 0;
  struct iphdr* ip4h = 0;
  void* transport_header = 0;

  __u32 cpu_num = bpf_get_smp_processor_id();

  /*XXX
void* flow_debug_map = bpf_map_lookup_elem(&flow_debug_maps, &cpu_num);
  if (!flow_debug_map) {
    return;
  }
  */
  if (outer_v4) {
    if ((void*)outer_eth + sizeof(struct ethhdr) + sizeof(struct iphdr) >
        data_end) {
      return;
    }
    ip4h = (void*)outer_eth + sizeof(struct ethhdr);
    debug_info.l4_hop = ip4h->saddr;
    debug_info.this_hop = ip4h->daddr;
  } else {
    if ((void*)outer_eth + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) >
        data_end) {
      return;
    }
    ip6h = (void*)outer_eth + sizeof(struct ethhdr);
    __builtin_memcpy(
        debug_info.l4_hopv6,
        ip6h->saddr.s6_addr32,
        sizeof(debug_info.l4_hopv6));
    __builtin_memcpy(
        debug_info.this_hopv6,
        ip6h->daddr.s6_addr32,
        sizeof(debug_info.this_hopv6));
  }

  if (inner_v4) {
    if ((void*)inner_eth + sizeof(struct ethhdr) + sizeof(struct iphdr) >
        data_end) {
      return;
    }
    ip4h = (void*)inner_eth + sizeof(struct ethhdr);
    transport_header =
        (void*)inner_eth + sizeof(struct ethhdr) + sizeof(struct iphdr);
    flow.src = ip4h->saddr;
    flow.dst = ip4h->daddr;
    flow.proto = ip4h->protocol;
    flow.ports = get_next_ports(transport_header, ip4h->protocol, data_end);
  } else {
    if ((void*)inner_eth + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) >
        data_end) {
      return;
    }
    ip6h = (void*)inner_eth + sizeof(struct ethhdr);
    transport_header =
        (void*)inner_eth + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    __builtin_memcpy(flow.srcv6, ip6h->saddr.s6_addr32, sizeof(flow.srcv6));
    __builtin_memcpy(flow.dstv6, ip6h->daddr.s6_addr32, sizeof(flow.dstv6));
    flow.proto = ip6h->nexthdr;
    flow.ports = get_next_ports(transport_header, ip6h->nexthdr, data_end);
  }
  /* XXX
  bpf_map_update_elem(flow_debug_map, &flow, &debug_info, BPF_ANY);
  */
  return;
}

#endif // of __FLOW_DEBUG_HELPERS_H

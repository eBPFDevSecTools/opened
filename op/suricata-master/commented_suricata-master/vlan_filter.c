/* Copyright (C) 2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <stddef.h>
#include <linux/bpf.h>

#include "bpf_helpers.h"

#define LINUX_VERSION_CODE 263682

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 25,
  "endLine": 36,
  "File": "/home/sayandes/opened_extraction/examples/suricata-master/ebpf/vlan_filter.c",
  "funcName": "hashfilter",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "\\filter\\)",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "lwt_xmit",
    "perf_event",
    "socket_filter",
    "flow_dissector",
    "sched_act",
    "lwt_out",
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_seg6local",
    "sk_skb",
    "sk_reuseport",
    "sk_msg",
    "lwt_in",
    "sched_cls",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "cgroup_device",
    "kprobe",
    "tracepoint",
    "sock_ops",
    "xdp",
    "raw_tracepoint"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
int SEC("filter") hashfilter(struct __sk_buff *skb) {
    __u16 vlan_id = skb->vlan_tci & 0x0fff;
    /* accept VLAN 2 and 4 and drop the rest */
    switch (vlan_id) {
        case 2:
        case 4:
            return -1;
        default:
            return 0;
    }
    return 0;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;

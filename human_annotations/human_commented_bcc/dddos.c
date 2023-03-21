#include <linux/skbuff.h>
#include <uapi/linux/ip.h>

#define MAX_NB_PACKETS 1000
#define LEGAL_DIFF_TIMESTAMP_PACKETS 1000000

BPF_HASH(rcv_packets);

struct detectionPackets {
    u64 nb_ddos_packets;
};

BPF_PERF_OUTPUT(events);

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Return Type": "u64",
          "Description": "Return the time elapsed since system boot , in nanoseconds. ",
          "Return": " Current ktime.",
          "Function Name": "bpf_ktime_get_ns",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_ktime_get_ns": [
      {
        "opVar": "        rcv_packets_ts_inter ",
        "inpVar": [
          "  - *rcv_packets_ts_ptr"
        ]
      },
      {
        "opVar": "                rcv_packets_ts_inter ",
        "inpVar": [
          " "
        ]
      }
    ]
  },
  "startLine": 15,
  "endLine": 61,
  "File": "/root/examples/bcc/dddos.c",
  "funcName": "detect_ddos",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx",
    " void *skb"
  ],
  "output": "int",
  "helper": [
    "bpf_ktime_get_ns"
  ],
  "compatibleHookpoints": [
    "sock_ops",
    "sched_cls",
    "xdp",
    "lwt_seg6local",
    "cgroup_sock",
    "sk_reuseport",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "socket_filter",
    "raw_tracepoint",
    "sk_msg",
    "kprobe",
    "flow_dissector",
    "cgroup_skb",
    "sk_skb",
    "lwt_in",
    "tracepoint",
    "cgroup_sock_addr",
    "sched_act"
  ],
  "humanFuncDescription": [
    {
      "description": "detect_ddos() function checks if rate of incoming packets is greater than a user 
                      defined threshold. If the rate is greater the packet is dropped, if its lower the 
                      packet is passed to next module. It takes as input a structure pointer 
                      ctx of type pt_regs and a void pointer of type skb. It store two pointers - 
                      no of packets received and time stamp between two successive packets. If the 
                      number of packets received in less than legal time, then increase the count, else 
                      ignore. If number of packets exceeds the max number of packets then trigger an 
                      alert. Ends with updating the number of packets and time elapsed for each packet 
                      in the end. Function returns 0 on successful completion.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "01.02.2023"
    }
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
int detect_ddos(struct pt_regs *ctx, void *skb){
    struct detectionPackets detectionPacket = {};

    // Used to count number of received packets
    u64 rcv_packets_nb_index = 0, rcv_packets_nb_inter=1, *rcv_packets_nb_ptr;

    // Used to measure elapsed time between 2 successive received packets
    u64 rcv_packets_ts_index = 1, rcv_packets_ts_inter=0, *rcv_packets_ts_ptr;

    /* The algorithm analyses packets received by ip_rcv function
    * and measures the difference in reception time between each packet.
    * DDOS flooders send millions of packets such that difference of
    * timestamp between 2 successive packets is so small
    * (which is not like regular applications behaviour).
    * This script looks for this difference in time and if it sees
    * more than MAX_NB_PACKETS successive packets with a difference
    * of timestamp between each one of them less than
    * LEGAL_DIFF_TIMESTAMP_PACKETS ns,
    * ------------------ It Triggers an ALERT -----------------
    * Those settings must be adapted depending on regular network traffic
    * -------------------------------------------------------------------
    * Important: this is a rudimentary intrusion detection system, one can
    * test a real case attack using hping3. However; if regular network
    * traffic increases above predefined detection settings, a false
    * positive alert will be triggered (an example would be the
    * case of large file downloads).
    */
    rcv_packets_nb_ptr = rcv_packets.lookup(&rcv_packets_nb_index);
    rcv_packets_ts_ptr = rcv_packets.lookup(&rcv_packets_ts_index);
    if(rcv_packets_nb_ptr != 0 && rcv_packets_ts_ptr != 0){
        rcv_packets_nb_inter = *rcv_packets_nb_ptr;
        rcv_packets_ts_inter = bpf_ktime_get_ns() - *rcv_packets_ts_ptr;
        if(rcv_packets_ts_inter < LEGAL_DIFF_TIMESTAMP_PACKETS){
            rcv_packets_nb_inter++;
        } else {
            rcv_packets_nb_inter = 0;
        }
        if(rcv_packets_nb_inter > MAX_NB_PACKETS){
            detectionPacket.nb_ddos_packets = rcv_packets_nb_inter;
            events.perf_submit(ctx, &detectionPacket, sizeof(detectionPacket));
        }
    }
    rcv_packets_ts_inter = bpf_ktime_get_ns();
    rcv_packets.update(&rcv_packets_nb_index, &rcv_packets_nb_inter);
    rcv_packets.update(&rcv_packets_ts_index, &rcv_packets_ts_inter);
    return 0;
}

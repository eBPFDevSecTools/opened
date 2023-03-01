/*
 * vfsreadlat.c		VFS read latency distribution.
 *			For Linux, uses BCC, eBPF. See .py file.
 *
 * Copyright (c) 2013-2015 PLUMgrid, http://plumgrid.com
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * 15-Aug-2015	Brendan Gregg	Created this.
 */

#include <uapi/linux/ptrace.h>

BPF_HASH(start, u32);
BPF_HISTOGRAM(dist);

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
        },
        {
          "Return Type": "u64",
          "Return": " A 64-bit integer containing the current tgid and pid, and created  as  such:                     current_task->tgid << 32 | current_task->pid.",
          "Function Name": "bpf_get_current_pid_tgid",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ],
          "Description": "A 64-bit integer containing the current tgid and pid , and created as such: current_task->tgid << 32 | current_task->pid. "
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_get_current_pid_tgid": [
      {
        "opVar": "\tpid ",
        "inpVar": [
          " "
        ]
      }
    ],
    "bpf_ktime_get_ns": [
      {
        "opVar": "\tts ",
        "inpVar": [
          " "
        ]
      }
    ]
  },
  "startLine": 18,
  "endLine": 27,
  "File": "/root/examples/bcc/vfsreadlat.c",
  "funcName": "do_entry",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_ktime_get_ns",
    "bpf_get_current_pid_tgid"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "perf_event",
    "raw_tracepoint_writable",
    "kprobe",
    "tracepoint"
  ],
  "humanFuncDescription": [
    {
      "description": "Using BPF_HASH a hash (which is also a BPF map) named 'start' is created. 
                      The key feild of this map stores the pid of datatype u32 and the corresponding value field stores the timestamp of datatype u64.
                      When the function do_entry is invoked, the map 'start' saves the timestamp for the pid when it starts it's execution. 
                      This function is attached with 'vfs_read' entry event in the bpf loader program.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "18.01.2023"
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
int do_entry(struct pt_regs *ctx)
{
	u32 pid;
	u64 ts;

	pid = bpf_get_current_pid_tgid();
	ts = bpf_ktime_get_ns();
	start.update(&pid, &ts);
	return 0;
}

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
        },
        {
          "Return Type": "u64",
          "Return": " A 64-bit integer containing the current tgid and pid, and created  as  such:                     current_task->tgid << 32 | current_task->pid.",
          "Function Name": "bpf_get_current_pid_tgid",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ],
          "Description": "A 64-bit integer containing the current tgid and pid , and created as such: current_task->tgid << 32 | current_task->pid. "
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_get_current_pid_tgid": [
      {
        "opVar": "\tpid ",
        "inpVar": [
          " "
        ]
      }
    ],
    "bpf_ktime_get_ns": [
      {
        "opVar": "\t\tdelta ",
        "inpVar": [
          "  - *tsp"
        ]
      }
    ]
  },
  "startLine": 29,
  "endLine": 44,
  "File": "/root/examples/bcc/vfsreadlat.c",
  "funcName": "do_return",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_ktime_get_ns",
    "bpf_get_current_pid_tgid"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "perf_event",
    "raw_tracepoint_writable",
    "kprobe",
    "tracepoint"
  ],
  "humanFuncDescription": [
    {
      "description": "do_return function is attached at the exit point of vfs_read event.
                     This function calculate the toltal amount of time taken to execute the process
                     Using the bpf helper function, it first get the current pid and search the same pid in the 'start' bpf map to find it's start time and store it in 'tsp'
                    'delta' stores the time taken to execute the function by substrating the start time of of the function from current system time
                    'dist' is a histogram, which defaults to 64 buckets indexed by keys of type int and whose value gets increated by the log-2 value of delta/1000",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "18.01.2023"
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
int do_return(struct pt_regs *ctx)
{
	u32 pid;
	u64 *tsp, delta;

	pid = bpf_get_current_pid_tgid();
	tsp = start.lookup(&pid);

	if (tsp != 0) {
		delta = bpf_ktime_get_ns() - *tsp;
		dist.increment(bpf_log2l(delta / 1000));
		start.delete(&pid);
	}

	return 0;
}

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <sys/resource.h>

#define __non_bpf_context	1
#include "bpf/compiler.h"

struct cpu_jiffies {
	uint64_t *jiffies;
	uint32_t cpus;
};

static const uint64_t kernel_hz[] = { 100, 250, 300, 1000 };

#define abs(x)	({ x < 0 ? -x : x; })

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 30,
  "endLine": 38,
  "File": "/home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c",
  "funcName": "pin_to_cpu",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int cpu"
  ],
  "output": "staticint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "perf_event",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint",
    "lwt_xmit",
    "sched_act",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_device",
    "xdp",
    "sk_msg",
    "sock_ops",
    "lwt_seg6local",
    "kprobe",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "cgroup_sock_addr",
    "socket_filter",
    "sk_skb",
    "tracepoint"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
static int pin_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);

	return sched_setaffinity(0, sizeof(set), &set);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 40,
  "endLine": 47,
  "File": "/home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c",
  "funcName": "fix_priority",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "staticint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "perf_event",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint",
    "lwt_xmit",
    "sched_act",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_device",
    "xdp",
    "sk_msg",
    "sock_ops",
    "lwt_seg6local",
    "kprobe",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "cgroup_sock_addr",
    "socket_filter",
    "sk_skb",
    "tracepoint"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
static int fix_priority(void)
{
	struct sched_param sp = {
		.sched_priority = sched_get_priority_max(SCHED_FIFO),
	};

	return sched_setscheduler(0, SCHED_FIFO, &sp);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 49,
  "endLine": 52,
  "File": "/home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c",
  "funcName": "*timer_list_open",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "staticFILE",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "perf_event",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint",
    "lwt_xmit",
    "sched_act",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_device",
    "xdp",
    "sk_msg",
    "sock_ops",
    "lwt_seg6local",
    "kprobe",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "cgroup_sock_addr",
    "socket_filter",
    "sk_skb",
    "tracepoint"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
static FILE *timer_list_open(void)
{
	return fopen("/proc/timer_list", "r");
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 54,
  "endLine": 57,
  "File": "/home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c",
  "funcName": "timer_list_close",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "FILE *fp"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "perf_event",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint",
    "lwt_xmit",
    "sched_act",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_device",
    "xdp",
    "sk_msg",
    "sock_ops",
    "lwt_seg6local",
    "kprobe",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "cgroup_sock_addr",
    "socket_filter",
    "sk_skb",
    "tracepoint"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
static void timer_list_close(FILE *fp)
{
	fclose(fp);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 59,
  "endLine": 92,
  "File": "/home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c",
  "funcName": "prep_kern_jiffies",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct cpu_jiffies *before",
    " struct cpu_jiffies *after"
  ],
  "output": "staticint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "perf_event",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint",
    "lwt_xmit",
    "sched_act",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_device",
    "xdp",
    "sk_msg",
    "sock_ops",
    "lwt_seg6local",
    "kprobe",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "cgroup_sock_addr",
    "socket_filter",
    "sk_skb",
    "tracepoint"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
static int prep_kern_jiffies(struct cpu_jiffies *before,
			     struct cpu_jiffies *after)
{
	uint64_t jiffies = 0;
	char buff[512];
	int cpus = 0;
	FILE *fp;

	fp = timer_list_open();
	while (fp && fgets(buff, sizeof(buff), fp)) {
		if (sscanf(buff, "jiffies: %lu\n", &jiffies) == 1)
			cpus++;
	}
	timer_list_close(fp);

	if (!cpus) {
		fprintf(stderr, "No procfs support?\n");
		return -EIO;
	}

	before->cpus = after->cpus = cpus;
	before->jiffies = calloc(cpus, sizeof(*before->jiffies));
	after->jiffies  = calloc(cpus, sizeof(*before->jiffies));

	if (!before->jiffies || !after->jiffies) {
		free(before->jiffies);
		free(after->jiffies);
		fprintf(stderr, "Error allocating per CPU jiffies: %s\n",
			strerror(errno));
		return -EIO;
	}

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 94,
  "endLine": 113,
  "File": "/home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c",
  "funcName": "fetch_kern_jiffies",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct cpu_jiffies *curr"
  ],
  "output": "staticint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "perf_event",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint",
    "lwt_xmit",
    "sched_act",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_device",
    "xdp",
    "sk_msg",
    "sock_ops",
    "lwt_seg6local",
    "kprobe",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "cgroup_sock_addr",
    "socket_filter",
    "sk_skb",
    "tracepoint"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
static int fetch_kern_jiffies(const struct cpu_jiffies *curr)
{
	char buff[512];
	int cpus = 0;
	FILE *fp;

	fp = timer_list_open();
	while (fp && fgets(buff, sizeof(buff), fp) && cpus < curr->cpus) {
		if (sscanf(buff, "jiffies: %lu\n", &curr->jiffies[cpus]) == 1)
			cpus++;
	}
	timer_list_close(fp);

	if (cpus != curr->cpus) {
		fprintf(stderr, "CPU mismatch when fetching jiffies\n");
		return -EIO;
	}

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 115,
  "endLine": 150,
  "File": "/home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c",
  "funcName": "dump_kern_jiffies",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct cpu_jiffies *fixed",
    " const struct cpu_jiffies *result",
    " bool macro"
  ],
  "output": "staticint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "perf_event",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint",
    "lwt_xmit",
    "sched_act",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_device",
    "xdp",
    "sk_msg",
    "sock_ops",
    "lwt_seg6local",
    "kprobe",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "cgroup_sock_addr",
    "socket_filter",
    "sk_skb",
    "tracepoint"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
static int dump_kern_jiffies(const struct cpu_jiffies *fixed,
			     const struct cpu_jiffies *result,
			     bool macro)
{
	uint64_t delta, warp = 0;
	int i, j, ret = -1;
	int64_t x;

	for (i = 0; i < result->cpus; i++) {
		result->jiffies[i] -= fixed->jiffies[i];
		for (j = 0, delta = ~0; j < ARRAY_SIZE(kernel_hz); j++) {
			x = abs((int64_t)(kernel_hz[j] - result->jiffies[i]));
			if (x < delta) {
				delta = x;
				fixed->jiffies[i] = kernel_hz[j];
			}
		}
		if (delta > warp)
			warp = delta;
		if (fixed->jiffies[i] != fixed->jiffies[0]) {
			fprintf(stderr, "Probed jiffies mismatch: %lu vs %lu HZ\n",
				fixed->jiffies[i], fixed->jiffies[0]);
			goto out;
		}
	}

	if (macro)
		printf("#define KERNEL_HZ %lu\t/* warp: %lu jiffies */\n", fixed->jiffies[0], warp);
	else
		printf("%lu, %lu\n", fixed->jiffies[0], warp);
	ret = 0;
out:
	free(fixed->jiffies);
	free(result->jiffies);
	return ret;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 152,
  "endLine": 194,
  "File": "/home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c",
  "funcName": "main",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int argc",
    " char **argv"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "perf_event",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint",
    "lwt_xmit",
    "sched_act",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_device",
    "xdp",
    "sk_msg",
    "sock_ops",
    "lwt_seg6local",
    "kprobe",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "cgroup_sock_addr",
    "socket_filter",
    "sk_skb",
    "tracepoint"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
int main(int argc, char **argv)
{
	struct cpu_jiffies before, after;
	struct timespec tv = {
		.tv_sec  = 1,
		.tv_nsec = 0,
	};
	int opt, sig, ret, tries = 4;
	bool macro = false;

	while ((opt = getopt(argc, argv, "m")) != -1) {
		switch (opt) {
		case 'm':
			macro = true;
			break;
		default:
			return -1;
		}
	}

	if (pin_to_cpu(0)) {
		fprintf(stderr, "Cannot pin to CPU 0: %s\n", strerror(errno));
		return -1;
	}
	if (fix_priority()) {
		fprintf(stderr, "Cannot set priority: %s\n", strerror(errno));
		return -1;
	}
	if (prep_kern_jiffies(&before, &after)) {
		fprintf(stderr, "Cannot prep jiffies: %s\n", strerror(errno));
		return -1;
	}

	do {
		ret  = fetch_kern_jiffies(&before);
		sig  = nanosleep(&tv, NULL);
		ret += fetch_kern_jiffies(&after);
	} while (!ret && sig && errno == EINTR && --tries >= 0);

	if (!ret && !sig)
		ret = dump_kern_jiffies(&before, &after, macro);
	return ret;
}

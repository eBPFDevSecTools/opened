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
    "static int pin_to_cpu (int cpu)\n",
    "{\n",
    "    cpu_set_t set;\n",
    "    CPU_ZERO (&set);\n",
    "    CPU_SET (cpu, &set);\n",
    "    return sched_setaffinity (0, sizeof (set), &set);\n",
    "}\n"
  ],
  "called_function_list": [
    "sched_setaffinity",
    "CPU_SET",
    "CPU_ZERO"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " clear CPU and reset a specific CPU in the set, then sets the CPU affinity mask of the thread ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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
    "static int fix_priority (void)\n",
    "{\n",
    "    struct sched_param sp = {\n",
    "        .sched_priority = sched_get_priority_max (SCHED_FIFO),}\n",
    "    ;\n",
    "    return sched_setscheduler (0, SCHED_FIFO, &sp);\n",
    "}\n"
  ],
  "called_function_list": [
    "sched_get_priority_max",
    "sched_setscheduler"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " reset the maxmium for the scheduling policy specified by policy  ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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
  "funcName": "timer_list_open",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "staticFILE",
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
    "static FILE *timer_list_open (void)\n",
    "{\n",
    "    return fopen (\"/proc/timer_list\", \"r\");\n",
    "}\n"
  ],
  "called_function_list": [
    "fopen"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " read the timer_list file ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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
    "static void timer_list_close (FILE *fp)\n",
    "{\n",
    "    fclose (fp);\n",
    "}\n"
  ],
  "called_function_list": [
    "fclose"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " close file ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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
    "static int prep_kern_jiffies (struct cpu_jiffies *before, struct cpu_jiffies *after)\n",
    "{\n",
    "    uint64_t jiffies = 0;\n",
    "    char buff [512];\n",
    "    int cpus = 0;\n",
    "    FILE *fp;\n",
    "    fp = timer_list_open ();\n",
    "    while (fp && fgets (buff, sizeof (buff), fp)) {\n",
    "        if (sscanf (buff, \"jiffies: %lu\\n\", &jiffies) == 1)\n",
    "            cpus++;\n",
    "    }\n",
    "    timer_list_close (fp);\n",
    "    if (!cpus) {\n",
    "        fprintf (stderr, \"No procfs support?\\n\");\n",
    "        return -EIO;\n",
    "    }\n",
    "    before->cpus = after->cpus = cpus;\n",
    "    before->jiffies = calloc (cpus, sizeof (*before->jiffies));\n",
    "    after->jiffies = calloc (cpus, sizeof (*before->jiffies));\n",
    "    if (!before->jiffies || !after->jiffies) {\n",
    "        free (before->jiffies);\n",
    "        free (after->jiffies);\n",
    "        fprintf (stderr, \"Error allocating per CPU jiffies: %s\\n\", strerror (errno));\n",
    "        return -EIO;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "free",
    "fgets",
    "timer_list_open",
    "fprintf",
    "timer_list_close",
    "sscanf",
    "calloc",
    "strerror"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " allocate the CPU jiffies with error check (*) ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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
    "static int fetch_kern_jiffies (const struct cpu_jiffies *curr)\n",
    "{\n",
    "    char buff [512];\n",
    "    int cpus = 0;\n",
    "    FILE *fp;\n",
    "    fp = timer_list_open ();\n",
    "    while (fp && fgets (buff, sizeof (buff), fp) && cpus < curr->cpus) {\n",
    "        if (sscanf (buff, \"jiffies: %lu\\n\", &curr->jiffies[cpus]) == 1)\n",
    "            cpus++;\n",
    "    }\n",
    "    timer_list_close (fp);\n",
    "    if (cpus != curr->cpus) {\n",
    "        fprintf (stderr, \"CPU mismatch when fetching jiffies\\n\");\n",
    "        return -EIO;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "fgets",
    "timer_list_open",
    "fprintf",
    "timer_list_close",
    "sscanf"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " fetch the CPU jiffies to fit the cpus set in current cpu parameter ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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
    "static int dump_kern_jiffies (const struct cpu_jiffies *fixed, const struct cpu_jiffies *result, bool macro)\n",
    "{\n",
    "    uint64_t delta, warp = 0;\n",
    "    int i, j, ret = -1;\n",
    "    int64_t x;\n",
    "    for (i = 0; i < result->cpus; i++) {\n",
    "        result->jiffies[i] -= fixed->jiffies[i];\n",
    "        for (j = 0, delta = ~0; j < ARRAY_SIZE (kernel_hz); j++) {\n",
    "            x = abs ((int64_t) (kernel_hz [j] - result -> jiffies [i]));\n",
    "            if (x < delta) {\n",
    "                delta = x;\n",
    "                fixed->jiffies[i] = kernel_hz[j];\n",
    "            }\n",
    "        }\n",
    "        if (delta > warp)\n",
    "            warp = delta;\n",
    "        if (fixed->jiffies[i] != fixed->jiffies[0]) {\n",
    "            fprintf (stderr, \"Probed jiffies mismatch: %lu vs %lu HZ\\n\", fixed->jiffies[i], fixed->jiffies[0]);\n",
    "            goto out;\n",
    "        }\n",
    "    }\n",
    "    if (macro)\n",
    "        printf (\"#define KERNEL_HZ %lu\\t/* warp: %lu jiffies */\\n\", fixed->jiffies[0], warp);\n",
    "    else\n",
    "        printf (\"%lu, %lu\\n\", fixed->jiffies[0], warp);\n",
    "    ret = 0;\n",
    "out :\n",
    "    free (fixed->jiffies);\n",
    "    free (result->jiffies);\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "free",
    "abs",
    "ARRAY_SIZE",
    "fprintf",
    "printf"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " decrease the fixed jiffies from the result jiffies, reset fixed jiffies to the closest kernel_hz stop when any fixed_jiffies isn't constant with the first one. With a macro bool for debugging  ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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
    "int main (int argc, char **argv)\n",
    "{\n",
    "    struct cpu_jiffies before, after;\n",
    "    struct timespec tv = {\n",
    "        .tv_sec = 1,\n",
    "        .tv_nsec = 0,}\n",
    "    ;\n",
    "    int opt, sig, ret, tries = 4;\n",
    "    bool macro = false;\n",
    "    while ((opt = getopt (argc, argv, \"m\")) != -1) {\n",
    "        switch (opt) {\n",
    "        case 'm' :\n",
    "            macro = true;\n",
    "            break;\n",
    "        default :\n",
    "            return -1;\n",
    "        }\n",
    "    }\n",
    "    if (pin_to_cpu (0)) {\n",
    "        fprintf (stderr, \"Cannot pin to CPU 0: %s\\n\", strerror (errno));\n",
    "        return -1;\n",
    "    }\n",
    "    if (fix_priority ()) {\n",
    "        fprintf (stderr, \"Cannot set priority: %s\\n\", strerror (errno));\n",
    "        return -1;\n",
    "    }\n",
    "    if (prep_kern_jiffies (&before, &after)) {\n",
    "        fprintf (stderr, \"Cannot prep jiffies: %s\\n\", strerror (errno));\n",
    "        return -1;\n",
    "    }\n",
    "    do {\n",
    "        ret = fetch_kern_jiffies (& before);\n",
    "        sig = nanosleep (& tv, NULL);\n",
    "        ret += fetch_kern_jiffies (&after);\n",
    "    }\n",
    "    while (!ret && sig && errno == EINTR && --tries >= 0);\n",
    "    if (!ret && !sig)\n",
    "        ret = dump_kern_jiffies (&before, &after, macro);\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "pin_to_cpu",
    "fix_priority",
    "prep_kern_jiffies",
    "fetch_kern_jiffies",
    "fprintf",
    "dump_kern_jiffies",
    "getopt",
    "nanosleep",
    "strerror"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " Main function of above functions, initialize the cpu and deal with the  jiffies  accordingly  ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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

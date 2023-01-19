/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP monitor via tracepoints\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include <linux/err.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"
#include "bpf_util.h" /* bpf_num_possible_cpus */

#include <linux/perf_event.h>
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/ioctl.h>

enum {
	REDIR_SUCCESS = 0,
	REDIR_ERROR = 1,
};

#define XDP_UNKNOWN	XDP_REDIRECT + 1
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_UNKNOWN + 1)
#endif

#define REDIR_RES_MAX 2
static const char *redir_names[REDIR_RES_MAX] = {
	[REDIR_SUCCESS]	= "Success",
	[REDIR_ERROR]	= "Error",
};

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 53,
  "endLine": 58,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "*err2str",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int err"
  ],
  "output": "staticconstchar",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static const char *err2str(int err)
{
	if (err < REDIR_RES_MAX)
		return redir_names[err];
	return NULL;
}

/* Common stats data record shared with _kern.c */
struct datarec {
	__u64 processed;
	__u64 dropped;
	__u64 info;
	__u64 err;
};

#define MAX_CPUS 64

/* Userspace structs for collection of stats from maps */
struct record {
	__u64 timestamp;
	struct datarec total;
	struct datarec *cpu;
};

struct u64rec {
	__u64 processed;
};

struct record_u64 {
	/* record for _kern side __u64 values */
	__u64 timestamp;
	struct u64rec total;
	struct u64rec *cpu;
};

struct stats_record {
	struct record_u64 xdp_redirect[REDIR_RES_MAX];
	struct record_u64 xdp_exception[XDP_ACTION_MAX];
	struct record xdp_cpumap_kthread;
	struct record xdp_cpumap_enqueue[MAX_CPUS];
	struct record xdp_devmap_xmit;
};

static const char *default_filename = "trace_prog_kern.o";

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{0, 0, NULL,  0 }}
};

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 111,
  "endLine": 126,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "find_map_fd",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_object *bpf_obj",
    " const char *mapname"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	/* Lesson#3: bpf_object to bpf_map */
	map = bpf_object__find_map_by_name(bpf_obj, mapname);
        if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}

	map_fd = bpf_map__fd(map);
 out:
	return map_fd;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 128,
  "endLine": 171,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "__check_map_fd_info",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int map_fd",
    " struct bpf_map_info *info",
    " struct bpf_map_info *exp"
  ],
  "output": "staticint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static int __check_map_fd_info(int map_fd, struct bpf_map_info *info,
			       struct bpf_map_info *exp)
{
	__u32 info_len = sizeof(*info);
	int err;

	if (map_fd < 0)
		return EXIT_FAIL;

        /* BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: %s() can't get info - %s\n",
			__func__,  strerror(errno));
		return EXIT_FAIL_BPF;
	}

	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return EXIT_FAIL;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return EXIT_FAIL;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return EXIT_FAIL;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return EXIT_FAIL;
	}

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 173,
  "endLine": 178,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "__check_map",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int map_fd",
    " struct bpf_map_info *exp"
  ],
  "output": "staticint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static int __check_map(int map_fd, struct bpf_map_info *exp)
{
	struct bpf_map_info info;

	return __check_map_fd_info(map_fd, &info, exp);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 180,
  "endLine": 245,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "check_map",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const char *name",
    " const struct bpf_map_def *def",
    " int fd"
  ],
  "output": "staticint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static int check_map(const char *name, const struct bpf_map_def *def, int fd)
{
	struct {
		const char          *name;
		struct bpf_map_info  info;
	} maps[] = {
		{
			.name = "redirect_err_cnt",
			.info = {
				.type = BPF_MAP_TYPE_PERCPU_ARRAY,
				.key_size = sizeof(__u32),
				.value_size = sizeof(__u64),
				.max_entries = 2,
			}
		},
		{
			.name = "exception_cnt",
			.info = {
				.type = BPF_MAP_TYPE_PERCPU_ARRAY,
				.key_size = sizeof(__u32),
				.value_size = sizeof(__u64),
				.max_entries = XDP_UNKNOWN + 1,
			}
		},
		{
			.name = "cpumap_enqueue_cnt",
			.info = {
				.type = BPF_MAP_TYPE_PERCPU_ARRAY,
				.key_size = sizeof(__u32),
				.value_size = sizeof(struct datarec),
				.max_entries = MAX_CPUS,
			}
		},
		{
			.name = "cpumap_kthread_cnt",
			.info = {
				.type = BPF_MAP_TYPE_PERCPU_ARRAY,
				.key_size = sizeof(__u32),
				.value_size = sizeof(struct datarec),
				.max_entries = 1,
			}
		},
		{
			.name = "devmap_xmit_cnt",
			.info = {
				.type = BPF_MAP_TYPE_PERCPU_ARRAY,
				.key_size = sizeof(__u32),
				.value_size = sizeof(struct datarec),
				.max_entries = 1,
			}
		},
		{ }
	};
	int i = 0;

	fprintf(stdout, "checking map %s\n", name);

	while (maps[i].name) {
		if (!strcmp(maps[i].name, name))
			return __check_map(fd, &maps[i].info);
		i++;
	}

	fprintf(stdout, "ERR: map %s not found\n", name);
	return -1;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 247,
  "endLine": 265,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "check_maps",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_object *obj"
  ],
  "output": "staticint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static int check_maps(struct bpf_object *obj)
{
	struct bpf_map *map;

	bpf_object__for_each_map(map, obj) {
		const struct bpf_map_def *def;
		const char *name;
		int fd;

		name = bpf_map__name(map);
		def  = bpf_map__def(map);
		fd   = bpf_map__fd(map);

		if (check_map(name, def, fd))
			return -1;
	}

	return 0;
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 268,
  "endLine": 279,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "gettime",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "static__u64",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with clock_gettime! (%i)\n", res);
		exit(-1);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "bpf_map_lookup_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      {
        "opVar": "\tif ((bpf_map_lookup_elem(fd, &key, values)) !",
        "inpVar": [
          " 0 "
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tfprintfstderr",
          "\t\t\t\"ERR:  failed key:0x%X\\n\"",
          " key"
        ]
      }
    ]
  },
  "startLine": 281,
  "endLine": 316,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "map_collect_record",
  "updateMaps": [],
  "readMaps": [
    " fd",
    " failed key:0x%X\\n\""
  ],
  "input": [
    "int fd",
    " __u32 key",
    " struct record *rec"
  ],
  "output": "staticbool",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_skb",
    "socket_filter",
    "cgroup_sock_addr",
    "sk_msg",
    "sock_ops",
    "flow_dissector",
    "sched_act",
    "sk_reuseport",
    "lwt_seg6local",
    "raw_tracepoint",
    "xdp",
    "cgroup_device",
    "lwt_in",
    "sk_skb",
    "cgroup_sock",
    "raw_tracepoint_writable",
    "perf_event",
    "sched_cls",
    "tracepoint",
    "lwt_out",
    "lwt_xmit",
    "cgroup_sysctl",
    "kprobe"
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
static bool map_collect_record(int fd, __u32 key, struct record *rec)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct datarec values[nr_cpus];
	__u64 sum_processed = 0;
	__u64 sum_dropped = 0;
	__u64 sum_info = 0;
	__u64 sum_err = 0;
	int i;

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		return false;
	}
	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();

	/* Record and sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		rec->cpu[i].processed = values[i].processed;
		sum_processed        += values[i].processed;
		rec->cpu[i].dropped = values[i].dropped;
		sum_dropped        += values[i].dropped;
		rec->cpu[i].info = values[i].info;
		sum_info        += values[i].info;
		rec->cpu[i].err = values[i].err;
		sum_err        += values[i].err;
	}
	rec->total.processed = sum_processed;
	rec->total.dropped   = sum_dropped;
	rec->total.info      = sum_info;
	rec->total.err       = sum_err;
	return true;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "bpf_map_lookup_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      {
        "opVar": "\tif ((bpf_map_lookup_elem(fd, &key, values)) !",
        "inpVar": [
          " 0 "
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tfprintfstderr",
          "\t\t\t\"ERR:  failed key:0x%X\\n\"",
          " key"
        ]
      }
    ]
  },
  "startLine": 318,
  "endLine": 341,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "map_collect_record_u64",
  "updateMaps": [],
  "readMaps": [
    " fd",
    " failed key:0x%X\\n\""
  ],
  "input": [
    "int fd",
    " __u32 key",
    " struct record_u64 *rec"
  ],
  "output": "staticbool",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_skb",
    "socket_filter",
    "cgroup_sock_addr",
    "sk_msg",
    "sock_ops",
    "flow_dissector",
    "sched_act",
    "sk_reuseport",
    "lwt_seg6local",
    "raw_tracepoint",
    "xdp",
    "cgroup_device",
    "lwt_in",
    "sk_skb",
    "cgroup_sock",
    "raw_tracepoint_writable",
    "perf_event",
    "sched_cls",
    "tracepoint",
    "lwt_out",
    "lwt_xmit",
    "cgroup_sysctl",
    "kprobe"
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
static bool map_collect_record_u64(int fd, __u32 key, struct record_u64 *rec)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct u64rec values[nr_cpus];
	__u64 sum_total = 0;
	int i;

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		return false;
	}
	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();

	/* Record and sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		rec->cpu[i].processed = values[i].processed;
		sum_total            += values[i].processed;
	}
	rec->total.processed = sum_total;
	return true;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 343,
  "endLine": 353,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "calc_period",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct record *r",
    " struct record *p"
  ],
  "output": "staticdouble",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 355,
  "endLine": 365,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "calc_period_u64",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct record_u64 *r",
    " struct record_u64 *p"
  ],
  "output": "staticdouble",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static double calc_period_u64(struct record_u64 *r, struct record_u64 *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 367,
  "endLine": 377,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "calc_pps",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct datarec *r",
    " struct datarec *p",
    " double period"
  ],
  "output": "staticdouble",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static double calc_pps(struct datarec *r, struct datarec *p, double period)
{
	__u64 packets = 0;
	double pps = 0;

	if (period > 0) {
		packets = r->processed - p->processed;
		pps = packets / period;
	}
	return pps;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 379,
  "endLine": 389,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "calc_pps_u64",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct u64rec *r",
    " struct u64rec *p",
    " double period"
  ],
  "output": "staticdouble",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static double calc_pps_u64(struct u64rec *r, struct u64rec *p, double period)
{
	__u64 packets = 0;
	double pps = 0;

	if (period > 0) {
		packets = r->processed - p->processed;
		pps = packets / period;
	}
	return pps;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 391,
  "endLine": 401,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "calc_drop",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct datarec *r",
    " struct datarec *p",
    " double period"
  ],
  "output": "staticdouble",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static double calc_drop(struct datarec *r, struct datarec *p, double period)
{
	__u64 packets = 0;
	double pps = 0;

	if (period > 0) {
		packets = r->dropped - p->dropped;
		pps = packets / period;
	}
	return pps;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 403,
  "endLine": 413,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "calc_info",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct datarec *r",
    " struct datarec *p",
    " double period"
  ],
  "output": "staticdouble",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static double calc_info(struct datarec *r, struct datarec *p, double period)
{
	__u64 packets = 0;
	double pps = 0;

	if (period > 0) {
		packets = r->info - p->info;
		pps = packets / period;
	}
	return pps;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 415,
  "endLine": 425,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "calc_err",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct datarec *r",
    " struct datarec *p",
    " double period"
  ],
  "output": "staticdouble",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static double calc_err(struct datarec *r, struct datarec *p, double period)
{
	__u64 packets = 0;
	double pps = 0;

	if (period > 0) {
		packets = r->err - p->err;
		pps = packets / period;
	}
	return pps;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 427,
  "endLine": 608,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "stats_print",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct stats_record *stats_rec",
    " struct stats_record *stats_prev",
    " bool err_only"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev,
			bool err_only)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	int rec_i = 0, i, to_cpu;
	double t = 0, pps = 0;

	/* Header */
	printf("%-15s %-7s %-12s %-12s %-9s\n",
	       "XDP-event", "CPU:to", "pps", "drop-pps", "extra-info");

	/* tracepoint: xdp:xdp_redirect_* */
	if (err_only)
		rec_i = REDIR_ERROR;

	for (; rec_i < REDIR_RES_MAX; rec_i++) {
		struct record_u64 *rec, *prev;
		char *fmt1 = "%-15s %-7d %'-12.0f %'-12.0f %s\n";
		char *fmt2 = "%-15s %-7s %'-12.0f %'-12.0f %s\n";

		rec  =  &stats_rec->xdp_redirect[rec_i];
		prev = &stats_prev->xdp_redirect[rec_i];
		t = calc_period_u64(rec, prev);

		for (i = 0; i < nr_cpus; i++) {
			struct u64rec *r = &rec->cpu[i];
			struct u64rec *p = &prev->cpu[i];

			pps = calc_pps_u64(r, p, t);
			if (pps > 0)
				printf(fmt1, "XDP_REDIRECT", i,
				       rec_i ? 0.0: pps, rec_i ? pps : 0.0,
				       err2str(rec_i));
		}
		pps = calc_pps_u64(&rec->total, &prev->total, t);
		printf(fmt2, "XDP_REDIRECT", "total",
		       rec_i ? 0.0: pps, rec_i ? pps : 0.0, err2str(rec_i));
	}

	/* tracepoint: xdp:xdp_exception */
	for (rec_i = 0; rec_i < XDP_ACTION_MAX; rec_i++) {
		struct record_u64 *rec, *prev;
		char *fmt1 = "%-15s %-7d %'-12.0f %'-12.0f %s\n";
		char *fmt2 = "%-15s %-7s %'-12.0f %'-12.0f %s\n";

		rec  =  &stats_rec->xdp_exception[rec_i];
		prev = &stats_prev->xdp_exception[rec_i];
		t = calc_period_u64(rec, prev);

		for (i = 0; i < nr_cpus; i++) {
			struct u64rec *r = &rec->cpu[i];
			struct u64rec *p = &prev->cpu[i];

			pps = calc_pps_u64(r, p, t);
			if (pps > 0)
				printf(fmt1, "Exception", i,
				       0.0, pps, action2str(rec_i));
		}
		pps = calc_pps_u64(&rec->total, &prev->total, t);
		if (pps > 0)
			printf(fmt2, "Exception", "total",
			       0.0, pps, action2str(rec_i));
	}

	/* cpumap enqueue stats */
	for (to_cpu = 0; to_cpu < MAX_CPUS; to_cpu++) {
		char *fmt1 = "%-15s %3d:%-3d %'-12.0f %'-12.0f %'-10.2f %s\n";
		char *fmt2 = "%-15s %3s:%-3d %'-12.0f %'-12.0f %'-10.2f %s\n";
		struct record *rec, *prev;
		char *info_str = "";
		double drop, info;

		rec  =  &stats_rec->xdp_cpumap_enqueue[to_cpu];
		prev = &stats_prev->xdp_cpumap_enqueue[to_cpu];
		t = calc_period(rec, prev);
		for (i = 0; i < nr_cpus; i++) {
			struct datarec *r = &rec->cpu[i];
			struct datarec *p = &prev->cpu[i];

			pps  = calc_pps(r, p, t);
			drop = calc_drop(r, p, t);
			info = calc_info(r, p, t);
			if (info > 0) {
				info_str = "bulk-average";
				info = pps / info; /* calc average bulk size */
			}
			if (pps > 0)
				printf(fmt1, "cpumap-enqueue",
				       i, to_cpu, pps, drop, info, info_str);
		}
		pps = calc_pps(&rec->total, &prev->total, t);
		if (pps > 0) {
			drop = calc_drop(&rec->total, &prev->total, t);
			info = calc_info(&rec->total, &prev->total, t);
			if (info > 0) {
				info_str = "bulk-average";
				info = pps / info; /* calc average bulk size */
			}
			printf(fmt2, "cpumap-enqueue",
			       "sum", to_cpu, pps, drop, info, info_str);
		}
	}

	/* cpumap kthread stats */
	{
		char *fmt1 = "%-15s %-7d %'-12.0f %'-12.0f %'-10.0f %s\n";
		char *fmt2 = "%-15s %-7s %'-12.0f %'-12.0f %'-10.0f %s\n";
		struct record *rec, *prev;
		double drop, info;
		char *i_str = "";

		rec  =  &stats_rec->xdp_cpumap_kthread;
		prev = &stats_prev->xdp_cpumap_kthread;
		t = calc_period(rec, prev);
		for (i = 0; i < nr_cpus; i++) {
			struct datarec *r = &rec->cpu[i];
			struct datarec *p = &prev->cpu[i];

			pps  = calc_pps(r, p, t);
			drop = calc_drop(r, p, t);
			info = calc_info(r, p, t);
			if (info > 0)
				i_str = "sched";
			if (pps > 0 || drop > 0)
				printf(fmt1, "cpumap-kthread",
				       i, pps, drop, info, i_str);
		}
		pps = calc_pps(&rec->total, &prev->total, t);
		drop = calc_drop(&rec->total, &prev->total, t);
		info = calc_info(&rec->total, &prev->total, t);
		if (info > 0)
			i_str = "sched-sum";
		printf(fmt2, "cpumap-kthread", "total", pps, drop, info, i_str);
	}

	/* devmap ndo_xdp_xmit stats */
	{
		char *fmt1 = "%-15s %-7d %'-12.0f %'-12.0f %'-10.2f %s %s\n";
		char *fmt2 = "%-15s %-7s %'-12.0f %'-12.0f %'-10.2f %s %s\n";
		struct record *rec, *prev;
		double drop, info, err;
		char *i_str = "";
		char *err_str = "";

		rec  =  &stats_rec->xdp_devmap_xmit;
		prev = &stats_prev->xdp_devmap_xmit;
		t = calc_period(rec, prev);
		for (i = 0; i < nr_cpus; i++) {
			struct datarec *r = &rec->cpu[i];
			struct datarec *p = &prev->cpu[i];

			pps  = calc_pps(r, p, t);
			drop = calc_drop(r, p, t);
			info = calc_info(r, p, t);
			err  = calc_err(r, p, t);
			if (info > 0) {
				i_str = "bulk-average";
				info = (pps+drop) / info; /* calc avg bulk */
			}
			if (err > 0)
				err_str = "drv-err";
			if (pps > 0 || drop > 0)
				printf(fmt1, "devmap-xmit",
				       i, pps, drop, info, i_str, err_str);
		}
		pps = calc_pps(&rec->total, &prev->total, t);
		drop = calc_drop(&rec->total, &prev->total, t);
		info = calc_info(&rec->total, &prev->total, t);
		err  = calc_err(&rec->total, &prev->total, t);
		if (info > 0) {
			i_str = "bulk-average";
			info = (pps+drop) / info; /* calc avg bulk */
		}
		if (err > 0)
			err_str = "drv-err";
		printf(fmt2, "devmap-xmit", "total", pps, drop,
		       info, i_str, err_str);
	}

	printf("\n");
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 610,
  "endLine": 619,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "map_fd",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_object *obj",
    " const char *name"
  ],
  "output": "staticint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static int map_fd(struct bpf_object *obj, const char *name)
{
	struct bpf_map *map;

	map = bpf_object__find_map_by_name(obj, name);
	if (map)
		return bpf_map__fd(map);

	return -1;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 621,
  "endLine": 655,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "stats_collect",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_object *obj",
    " struct stats_record *rec"
  ],
  "output": "staticbool",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static bool stats_collect(struct bpf_object *obj, struct stats_record *rec)
{
	int fd;
	int i;

	/* TODO: Detect if someone unloaded the perf event_fd's, as
	 * this can happen by someone running perf-record -e
	 */

	fd = map_fd(obj, "redirect_err_cnt");

	for (i = 0; i < REDIR_RES_MAX; i++)
		map_collect_record_u64(fd, i, &rec->xdp_redirect[i]);

	fd = map_fd(obj, "exception_cnt");

	for (i = 0; i < XDP_ACTION_MAX; i++) {
		map_collect_record_u64(fd, i, &rec->xdp_exception[i]);
	}

	fd = map_fd(obj, "cpumap_enqueue_cnt");

	for (i = 0; i < MAX_CPUS; i++)
		map_collect_record(fd, i, &rec->xdp_cpumap_enqueue[i]);

	fd = map_fd(obj, "cpumap_kthread_cnt");

	map_collect_record(fd, 0, &rec->xdp_cpumap_kthread);

	fd = map_fd(obj, "devmap_xmit_cnt");

	map_collect_record(fd, 0, &rec->xdp_devmap_xmit);

	return true;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 657,
  "endLine": 671,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "*alloc_rec_per_cpu",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int record_size"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static void *alloc_rec_per_cpu(int record_size)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	void *array;
	size_t size;

	size = record_size * nr_cpus;
	array = malloc(size);
	memset(array, 0, size);
	if (!array) {
		fprintf(stderr, "Mem alloc error (nr_cpus:%u)\n", nr_cpus);
		exit(-1);
	}
	return array;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 673,
  "endLine": 703,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "*alloc_stats_record",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "staticstructstats_record",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static struct stats_record *alloc_stats_record(void)
{
	struct stats_record *rec;
	int rec_sz;
	int i;

	/* Alloc main stats_record structure */
	rec = malloc(sizeof(*rec));
	memset(rec, 0, sizeof(*rec));
	if (!rec) {
		fprintf(stderr, "Mem alloc error\n");
		exit(-1);
	}

	/* Alloc stats stored per CPU for each record */
	rec_sz = sizeof(struct u64rec);
	for (i = 0; i < REDIR_RES_MAX; i++)
		rec->xdp_redirect[i].cpu = alloc_rec_per_cpu(rec_sz);

	for (i = 0; i < XDP_ACTION_MAX; i++)
		rec->xdp_exception[i].cpu = alloc_rec_per_cpu(rec_sz);

	rec_sz = sizeof(struct datarec);
	rec->xdp_cpumap_kthread.cpu = alloc_rec_per_cpu(rec_sz);
	rec->xdp_devmap_xmit.cpu    = alloc_rec_per_cpu(rec_sz);

	for (i = 0; i < MAX_CPUS; i++)
		rec->xdp_cpumap_enqueue[i].cpu = alloc_rec_per_cpu(rec_sz);

	return rec;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 705,
  "endLine": 722,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "free_stats_record",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct stats_record *r"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static void free_stats_record(struct stats_record *r)
{
	int i;

	for (i = 0; i < REDIR_RES_MAX; i++)
		free(r->xdp_redirect[i].cpu);

	for (i = 0; i < XDP_ACTION_MAX; i++)
		free(r->xdp_exception[i].cpu);

	free(r->xdp_cpumap_kthread.cpu);
	free(r->xdp_devmap_xmit.cpu);

	for (i = 0; i < MAX_CPUS; i++)
		free(r->xdp_cpumap_enqueue[i].cpu);

	free(r);
}

/* Pointer swap trick */
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 725,
  "endLine": 732,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "swap",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct stats_record **a",
    " struct stats_record **b"
  ],
  "output": "staticinlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static inline void swap(struct stats_record **a, struct stats_record **b)
{
	struct stats_record *tmp;

	tmp = *a;
	*a = *b;
	*b = tmp;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 734,
  "endLine": 758,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "stats_poll",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_object *obj",
    " int interval",
    " bool err_only"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static void stats_poll(struct bpf_object *obj, int interval, bool err_only)
{
	struct stats_record *rec, *prev;

	rec  = alloc_stats_record();
	prev = alloc_stats_record();
	stats_collect(obj, rec);

	if (err_only)
		printf("\n%s\n", "???");

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	while (1) {
		swap(&prev, &rec);
		stats_collect(obj, rec);
		stats_print(rec, prev, err_only);
		fflush(stdout);
		sleep(interval);
	}

	free_stats_record(rec);
	free_stats_record(prev);
}


/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 761,
  "endLine": 776,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "filename__read_int",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const char *filename",
    " int *value"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
int filename__read_int(const char *filename, int *value)
{
	char line[64];
	int fd = open(filename, O_RDONLY), err = -1;

	if (fd < 0)
		return -1;

	if (read(fd, line, sizeof(line)) > 0) {
		*value = atoi(line);
		err = 0;
	}

	close(fd);
	return err;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 778,
  "endLine": 784,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "sys_perf_event_open",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct perf_event_attr *attr",
    " pid_t pid",
    " int cpu",
    " int group_fd",
    " unsigned long flags"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static inline int
sys_perf_event_open(struct perf_event_attr *attr,
		    pid_t pid, int cpu, int group_fd,
		    unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 786,
  "endLine": 841,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
  "funcName": "*load_bpf_and_trace_attach",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct config *cfg"
  ],
  "output": "staticstructbpf_object",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static struct bpf_object* load_bpf_and_trace_attach(struct config *cfg)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *tp_link;
	int err;

	obj = bpf_object__open_file(cfg->filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERR: opening BPF object file %s failed\n",
			cfg->filename);
		return NULL;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERR: loading BPF object file %s failed\n",
			cfg->filename);
		goto err;
	}

	bpf_object__for_each_program(prog, obj) {
		const char *sec = bpf_program__title(prog, true);
		char *tp;

		if (!sec) {
			fprintf(stderr, "ERR: failed to get program title\n");
			goto err;
		}

		tp = strrchr(sec, '/');
		if (!tp) {
			fprintf(stderr, "ERR: wrong program title %s\n", sec);
			goto err;
		}

		tp++;

		if (verbose)
			printf("Attach tracepoint %s \t(prog sec:%s)\n", tp, sec);

		tp_link = bpf_program__attach_tracepoint(prog, "xdp", tp);

		err = libbpf_get_error(tp_link);
		if (err < 0) {
			fprintf(stderr, "ERR: failed to open raw tracepoint for %s, (%d %s)\n",
				tp, -errno, strerror(errno));
			goto err;
		}
	}

	return obj;

err:
	bpf_object__close(obj);
	return NULL;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 843,
  "endLine": 868,
  "File": "/root/examples/xdp-tutorials/trace_load_and_stats.c",
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
    "All_hookpoints"
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
	struct bpf_object *bpf_obj;
	struct config cfg;
	int interval = 2;

	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	bpf_obj = load_bpf_and_trace_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s)\n", cfg.filename);
	}

	if (check_maps(bpf_obj))
		return EXIT_FAIL_BPF;

	stats_poll(bpf_obj, interval, false);
	return EXIT_OK;
}

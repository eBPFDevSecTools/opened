// SPDX-License-Identifier: GPL-2.0
static const char *__doc__ = "XDP sample packet\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <errno.h>
#include <assert.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <poll.h>
#include <sys/mman.h>
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#include <pcap/dlt.h>
#include "perf-sys.h"
#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "bpf_util.h"
#include <time.h>

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define MAX_CPUS 128
static int pmu_fds[MAX_CPUS];
static struct perf_event_mmap_page *headers[MAX_CPUS];
static __u32 prog_id;

static pcap_t* pd;
static pcap_dumper_t* pdumper;
static unsigned int pcap_pkts;

static const char *default_filename = "samples.pcap";

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 46,
  "endLine": 66,
  "File": "/root/examples/xdp-tutorials/xdp_sample_pkts_user.c",
  "funcName": "do_attach",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int idx",
    " int fd",
    " const char *name",
    " __u32 xdp_flags"
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
static int do_attach(int idx, int fd, const char *name, __u32 xdp_flags)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	int err;

	err = bpf_set_link_xdp_fd(idx, fd, xdp_flags);
	if (err < 0) {
		printf("ERROR: failed to attach program to %s\n", name);
		return err;
	}

	err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
	if (err) {
		printf("can't get prog info - %s\n", strerror(errno));
		return err;
	}
	prog_id = info.id;

	return err;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 68,
  "endLine": 89,
  "File": "/root/examples/xdp-tutorials/xdp_sample_pkts_user.c",
  "funcName": "do_detach",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int idx",
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
static int do_detach(int idx, const char *name)
{
	__u32 curr_prog_id = 0;
	int err = 0;

	err = bpf_get_link_xdp_id(idx, &curr_prog_id, 0);
	if (err) {
		printf("bpf_get_link_xdp_id failed\n");
		return err;
	}
	if (prog_id == curr_prog_id) {
		err = bpf_set_link_xdp_fd(idx, -1, 0);
		if (err < 0)
			printf("ERROR: failed to detach prog from %s\n", name);
	} else if (!curr_prog_id) {
		printf("couldn't find a prog id on a %s\n", name);
	} else {
		printf("program on interface changed, not removing\n");
	}

	return err;
}

#define SAMPLE_SIZE 1024
#define NANOSECS_PER_USEC 1000

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 94,
  "endLine": 133,
  "File": "/root/examples/xdp-tutorials/xdp_sample_pkts_user.c",
  "funcName": "print_bpf_output",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " int size"
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
static int print_bpf_output(void *data, int size)
{
	struct {
		__u16 cookie;
		__u16 pkt_len;
		__u8  pkt_data[SAMPLE_SIZE];
	} __packed *e = data;
	struct pcap_pkthdr h = {
		.caplen	= SAMPLE_SIZE,
		.len	= e->pkt_len,
	};
	struct timespec ts;
	int i, err;

	if (e->cookie != 0xdead) {
		printf("BUG cookie %x sized %d\n",
		       e->cookie, size);
		return LIBBPF_PERF_EVENT_ERROR;
	}

	err = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (err < 0) {
		printf("Error with clock_gettime! (%i)\n", err);
		return LIBBPF_PERF_EVENT_ERROR;
	}

	h.ts.tv_sec  = ts.tv_sec;
	h.ts.tv_usec = ts.tv_nsec / NANOSECS_PER_USEC;

	if (verbose) {
		printf("pkt len: %-5d bytes. hdr: ", e->pkt_len);
		for (i = 0; i < e->pkt_len; i++)
			printf("%02x ", e->pkt_data[i]);
		printf("\n");
	}

	pcap_dump((u_char *) pdumper, &h, e->pkt_data);
	pcap_pkts++;
	return LIBBPF_PERF_EVENT_CONT;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "map_update",
      "map_update": [
        {
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_update_elem": [
      {
        "opVar": "\t\tassert(bpf_map_update_elem(map_fd, &key,\t\t\t\t\t   &pmu_fds[i], BPF_ANY) ",
        "inpVar": [
          ""
        ]
      }
    ]
  },
  "startLine": 135,
  "endLine": 156,
  "File": "/root/examples/xdp-tutorials/xdp_sample_pkts_user.c",
  "funcName": "test_bpf_perf_event",
  "updateMaps": [
    " map_fd"
  ],
  "readMaps": [],
  "input": [
    "int map_fd",
    " int num"
  ],
  "output": "staticvoid",
  "helper": [
    "bpf_map_update_elem"
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
static void test_bpf_perf_event(int map_fd, int num)
{
	struct perf_event_attr attr = {
		.sample_type	= PERF_SAMPLE_RAW,
		.type		= PERF_TYPE_SOFTWARE,
		.config		= PERF_COUNT_SW_BPF_OUTPUT,
		.wakeup_events	= 1, /* get an fd notification for every event */
	};
	int i;

	for (i = 0; i < num; i++) {
		int key = i;

		pmu_fds[i] = sys_perf_event_open(&attr, -1/*pid*/, i/*cpu*/,
						 -1/*group_fd*/, 0);

		assert(pmu_fds[i] >= 0);
		assert(bpf_map_update_elem(map_fd, &key,
					   &pmu_fds[i], BPF_ANY) == 0);
		ioctl(pmu_fds[i], PERF_EVENT_IOC_ENABLE, 0);
	}
}

static int done;

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 160,
  "endLine": 163,
  "File": "/root/examples/xdp-tutorials/xdp_sample_pkts_user.c",
  "funcName": "sig_handler",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int signo"
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
static void sig_handler(int signo)
{
	done = 1;
}

struct perf_event_sample {
	struct perf_event_header header;
	__u32	size;
	char	data[];
};

typedef enum bpf_perf_event_ret (*perf_event_print_fn)(void *data, int size);

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 173,
  "endLine": 197,
  "File": "/root/examples/xdp-tutorials/xdp_sample_pkts_user.c",
  "funcName": "bpf_perf_event_print",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct perf_event_header *hdr",
    " void *private_data"
  ],
  "output": "staticenumbpf_perf_event_ret",
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
static enum bpf_perf_event_ret
bpf_perf_event_print(struct perf_event_header *hdr, void *private_data)
{
	struct perf_event_sample *e = (struct perf_event_sample *)hdr;
	perf_event_print_fn fn = private_data;
	int ret;

	if (e->header.type == PERF_RECORD_SAMPLE) {
		ret = fn(e->data, e->size);
		if (ret != LIBBPF_PERF_EVENT_CONT)
			return ret;
	} else if (e->header.type == PERF_RECORD_LOST) {
		struct {
			struct perf_event_header header;
			__u64 id;
			__u64 lost;
		} *lost = (void *) e;
		printf("lost %lld events\n", lost->lost);
	} else {
		printf("unknown event type=%d size=%d\n",
		       e->header.type, e->header.size);
	}

	return LIBBPF_PERF_EVENT_CONT;
}

static int page_size;
static int page_cnt = 8;

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 202,
  "endLine": 218,
  "File": "/root/examples/xdp-tutorials/xdp_sample_pkts_user.c",
  "funcName": "perf_event_mmap_header",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int fd",
    " struct perf_event_mmap_page **header"
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
int perf_event_mmap_header(int fd, struct perf_event_mmap_page **header)
{
	void *base;
	int mmap_size;

	page_size = getpagesize();
	mmap_size = page_size * (page_cnt + 1);

	base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (base == MAP_FAILED) {
		printf("mmap err\n");
		return -1;
	}

	*header = base;
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
          "Description": "Read the value of a perf event counter. This helper relies on a <[ map ]>(IP: 0) of type BPF_MAP_TYPE_PERF_EVENT_ARRAY. The nature of the perf event counter is selected when <[ map ]>(IP: 0) is updated with perf event file descriptors. The <[ map ]>(IP: 0) is an array whose size is the number of available CPUs , and each cell contains a value relative to one CPU. The value to retrieve is indicated by <[ flags ]>(IP: 1) , that contains the index of the CPU to look up , masked with BPF_F_INDEX_MASK. Alternatively , <[ flags ]>(IP: 1) can be set to BPF_F_CURRENT_CPU to indicate that the value for the current CPU should be retrieved. Note that before Linux 4. 13 , only hardware perf event can be retrieved. Also , be aware that the newer helper bpf_perf_event_read_value() is recommended over bpf_perf_event_read() in general. The latter has some ABI quirks where error and counter value are used as a return code (which is wrong to do since ranges may overlap). This issue is fixed with bpf_perf_event_read_value() , which at the same time provides more features over the bpf_perf_event_read() interface. Please refer to the description of bpf_perf_event_read_value() for details. ",
          "Return": " The value of the perf event counter read from the map, or a  negative  error                     code in case of failure.",
          "Function Name": "bpf_perf_event_read",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_perf_event_read": [
      {
        "opVar": "\t\t\tret ",
        "inpVar": [
          " _simpleheaders[i]",
          "\t\t\t\t\t\t\t page_cnt * page_size",
          "\t\t\t\t\t\t\t page_size",
          " &buf",
          " &len",
          "\t\t\t\t\t\t\t bpf_perf_event_print",
          "\t\t\t\t\t\t\t output_fn"
        ]
      }
    ]
  },
  "startLine": 220,
  "endLine": 258,
  "File": "/root/examples/xdp-tutorials/xdp_sample_pkts_user.c",
  "funcName": "perf_event_poller_multi",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int *fds",
    " struct perf_event_mmap_page **headers",
    " int num_fds",
    " perf_event_print_fn output_fn",
    " int *done"
  ],
  "output": "int",
  "helper": [
    "bpf_perf_event_read"
  ],
  "compatibleHookpoints": [
    "perf_event",
    "kprobe",
    "tracepoint",
    "raw_tracepoint",
    "raw_tracepoint_writable"
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
int perf_event_poller_multi(int *fds, struct perf_event_mmap_page **headers,
			    int num_fds, perf_event_print_fn output_fn,
			    int *done)
{
	enum bpf_perf_event_ret ret;
	struct pollfd *pfds;
	void *buf = NULL;
	size_t len = 0;
	int i;

	pfds = calloc(num_fds, sizeof(*pfds));
	if (!pfds)
		return LIBBPF_PERF_EVENT_ERROR;

	for (i = 0; i < num_fds; i++) {
		pfds[i].fd = fds[i];
		pfds[i].events = POLLIN;
	}

	while (!*done) {
		poll(pfds, num_fds, 1000);
		for (i = 0; i < num_fds; i++) {
			if (!pfds[i].revents)
				continue;

			ret = bpf_perf_event_read_simple(headers[i],
							 page_cnt * page_size,
							 page_size, &buf, &len,
							 bpf_perf_event_print,
							 output_fn);
			if (ret != LIBBPF_PERF_EVENT_CONT)
				break;
		}
	}
	free(buf);
	free(pfds);

	return ret;
}

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"filename",    required_argument,	NULL,  1  },
	 "Store packet sample into <file>", "<file>"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }, NULL, false}
};

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 279,
  "endLine": 366,
  "File": "/root/examples/xdp-tutorials/xdp_sample_pkts_user.c",
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
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	int prog_fd, map_fd;
	struct bpf_object *obj;
	struct bpf_map *map;
	char filename[256];
	int ret, err, i;
	int numcpus = bpf_num_possible_cpus();
	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
	};

	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));

	/* Cmdline options can change these */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	snprintf(filename, sizeof(filename), "xdp_sample_pkts_kern.o");
	prog_load_attr.file = filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return 1;

	if (!prog_fd) {
		printf("load_bpf_file: %s\n", strerror(errno));
		return 1;
	}

	map = bpf_map__next(NULL, obj);
	if (!map) {
		printf("finding a map in obj file failed\n");
		return 1;
	}
	map_fd = bpf_map__fd(map);

	err = do_attach(cfg.ifindex, prog_fd, cfg.ifname, cfg.xdp_flags);
	if (err)
		return err;

	if (signal(SIGINT, sig_handler) ||
	    signal(SIGHUP, sig_handler) ||
	    signal(SIGTERM, sig_handler)) {
		perror("signal");
		return 1;
	}

	test_bpf_perf_event(map_fd, numcpus);

	for (i = 0; i < numcpus; i++)
		if (perf_event_mmap_header(pmu_fds[i], &headers[i]) < 0)
			return 1;

	pd = pcap_open_dead(DLT_EN10MB, 65535);
	if (!pd)
		goto out;

	pdumper = pcap_dump_open(pd, cfg.filename);
	if (!pdumper)
		goto out;

	ret = perf_event_poller_multi(pmu_fds, headers, numcpus,
				      print_bpf_output, &done);

	pcap_dump_close(pdumper);
	pcap_close(pd);

out:
	do_detach(cfg.ifindex, cfg.ifname);
	printf("\n%u packet samples stored in %s\n", pcap_pkts, cfg.filename);
	return ret;
}

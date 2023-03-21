// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/* Ratelimit incoming TCP connections with sliding window approach */

#include <stdio.h>
#include <linux/bpf.h>
#include <signal.h>
#include <ctype.h>
#ifdef __linux__
#include <unistd.h>
#include <sys/resource.h>
#include <sys/time.h>
#endif
#include <getopt.h>
#ifdef __linux__
#include <net/if.h>
#endif
#include <time.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

//#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

//#include "bpf_load.h"
#ifdef __linux__
//#include "bpf_util.h"
#endif

#ifdef WIN32
#include <io.h>
#include <winsock2.h>
#include <netioapi.h>
#define sleep(seconds) Sleep((seconds) * 1000)

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 38,
  "endLine": 44,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_user.c",
  "funcName": "*strsep",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "char **stringp",
    " const char *delim"
  ],
  "output": "char",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_sysctl",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "char *strsep (char **stringp, const char *delim)\n",
    "{\n",
    "    static char *next_token = NULL;\n",
    "    char *input = *stringp;\n",
    "    *stringp = strtok_s (input, delim, &next_token);\n",
    "    return input;\n",
    "}\n"
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
char* strsep(char** stringp, const char* delim)
{
    static char* next_token = NULL;
    char* input = *stringp;
    *stringp = strtok_s(input, delim, &next_token);
    return input;
}
#define close _close
#define strdup _strdup
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 47,
  "endLine": 58,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_user.c",
  "funcName": "gettimeofday",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct timeval *tv",
    " struct timezone *tz"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_sysctl",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "int gettimeofday (struct timeval *tv, struct timezone *tz)\n",
    "{\n",
    "    FILETIME ft;\n",
    "    ULARGE_INTEGER ui;\n",
    "    GetSystemTimeAsFileTime (&ft);\n",
    "    ui.LowPart = ft.dwLowDateTime;\n",
    "    ui.HighPart = ft.dwHighDateTime;\n",
    "    ui.QuadPart /= 10;\n",
    "    tv->tv_sec = (long) (ui.QuadPart / 1000000);\n",
    "    tv->tv_usec = ui.QuadPart % 1000000;\n",
    "    return 0;\n",
    "}\n"
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
int gettimeofday(struct timeval* tv, struct timezone* tz)
{
    FILETIME ft;
    ULARGE_INTEGER ui;
    GetSystemTimeAsFileTime(&ft);
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    ui.QuadPart /= 10; // Convert to usec.
    tv->tv_sec = (long)(ui.QuadPart / 1000000);
    tv->tv_usec = ui.QuadPart % 1000000;
    return 0;
}
#include "bpf/bpf.h"
#endif

#include "bpf/libbpf.h"

#include "constants.h"
#include "log.h"

static const char *__doc__ =
        "Ratelimit incoming TCP connections using XDP";

static int ifindex;

FILE *info;
static char prev_prog_map[1024];
static const struct option long_options[] = {
    {"help",      no_argument,        NULL, 'h' },
    {"iface",     required_argument,  NULL, 'i' },
    {"rate",      required_argument,  NULL, 'r' },
    {"ports",     optional_argument,  NULL, 'p' },
    {"verbose",   optional_argument,  NULL, 'v' },
    {"direction", optional_argument,  NULL, 'd'},
    {"map-name",  optional_argument,  NULL, 'm' },
    {0,           0,                  NULL,  0  }
};

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 85,
  "endLine": 104,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_user.c",
  "funcName": "usage",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "char *argv []"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_sysctl",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static void usage (char *argv [])\n",
    "{\n",
    "    int i;\n",
    "    printf (\"\\nDOCUMENTATION:\\n%s\\n\", __doc__);\n",
    "    printf (\"\\n\");\n",
    "    printf (\" Usage: %s (options-see-below)\\n\", argv[0]);\n",
    "    printf (\" Listing options:\\n\");\n",
    "    for (i = 0; long_options[i].name != 0; i++) {\n",
    "        printf (\" --%-12s\", long_options[i].name);\n",
    "        if (long_options[i].flag != NULL)\n",
    "            printf (\" flag (internal value:%d)\", *long_options[i].flag);\n",
    "        else\n",
    "            printf (\" short-option: -%c\", long_options[i].val);\n",
    "        printf (\"\\n\");\n",
    "    }\n",
    "    printf (\"\\n\");\n",
    "}\n"
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
static void usage(char *argv[])
{
    int i;
    printf("\nDOCUMENTATION:\n%s\n", __doc__);
    printf("\n");
    printf(" Usage: %s (options-see-below)\n", argv[0]);
    printf(" Listing options:\n");
    for (i = 0; long_options[i].name != 0; i++)
    {
        printf(" --%-12s", long_options[i].name);
        if (long_options[i].flag != NULL)
                printf(" flag (internal value:%d)",
                        *long_options[i].flag);
        else
                printf(" short-option: -%c",
                        long_options[i].val);
        printf("\n");
    }
    printf("\n");
}

/* Set log timestamps */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 107,
  "endLine": 118,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_user.c",
  "funcName": "log_timestamp",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "char *log_ts"
  ],
  "output": "void",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_sysctl",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "void log_timestamp (char *log_ts)\n",
    "{\n",
    "    struct timeval tv;\n",
    "    time_t nowtime;\n",
    "    struct tm *nowtm;\n",
    "    char tmbuf [TIMESTAMP_LEN];\n",
    "    gettimeofday (&tv, NULL);\n",
    "    nowtime = tv.tv_sec;\n",
    "    nowtm = localtime (& nowtime);\n",
    "    strftime (tmbuf, DATE_LEN, \"%Y-%m-%d %H:%M:%S\", nowtm);\n",
    "    snprintf (log_ts, DATE_LEN + TIMESTAMP_LEN, \"%s.%06ld\", tmbuf, tv.tv_usec);\n",
    "}\n"
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
void log_timestamp(char *log_ts) {
    struct timeval tv;
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[TIMESTAMP_LEN];

    gettimeofday(&tv, NULL);
    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, DATE_LEN, "%Y-%m-%d %H:%M:%S", nowtm);
    snprintf(log_ts, DATE_LEN+TIMESTAMP_LEN, "%s.%06ld", tmbuf, tv.tv_usec);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 120,
  "endLine": 129,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_user.c",
  "funcName": "get_length",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const char *str"
  ],
  "output": "staticint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_sysctl",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static int get_length (const char *str)\n",
    "{\n",
    "    int len = 0;\n",
    "    if (*str == '\\0')\n",
    "        return 0;\n",
    "    while (str[len] != '\\0')\n",
    "        len++;\n",
    "    return len;\n",
    "}\n"
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
static int get_length(const char *str)
{
    int len = 0;
    if (*str == '\0')
        return 0;
    while (str[len] != '\0')
       len++;

   return len;
}

/* Set the logging output to the default log file configured */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 132,
  "endLine": 145,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_user.c",
  "funcName": "*set_logfile",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "staticFILE",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_sysctl",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static FILE *set_logfile (void)\n",
    "{\n",
    "    if (info != NULL) {\n",
    "        return info;\n",
    "    }\n",
    "    info = fopen (DEFAULT_LOGFILE, \"a\");\n",
    "    if (info == NULL) {\n",
    "        fprintf (stderr, \"could not open log file \");\n",
    "        return NULL;\n",
    "    }\n",
    "    fprintf (stderr, \"writing errors/warnings/info/debug output to %s \\n\", DEFAULT_LOGFILE);\n",
    "    return info;\n",
    "}\n"
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
static FILE* set_logfile(void)
{
    if (info != NULL){
        return info;
    }
    info = fopen(DEFAULT_LOGFILE, "a");
    if (info == NULL) {
        fprintf(stderr, "could not open log file ");
        return NULL;
    }
    fprintf(stderr, "writing errors/warnings/info/debug output to %s \n",
            DEFAULT_LOGFILE);
    return info;
}

// This method to unlink the program
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
          "Description": "Delete entry with <[ key ]>(IP: 1) from map. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_delete_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_delete_elem": [
      {
        "opVar": "       ret ",
        "inpVar": [
          " map_fd",
          " &key"
        ]
      }
    ]
  },
  "startLine": 148,
  "endLine": 167,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_user.c",
  "funcName": "xdp_unlink_bpf_chain",
  "updateMaps": [
    " map_fd"
  ],
  "readMaps": [],
  "input": [
    "const char *map_filename"
  ],
  "output": "staticint",
  "helper": [
    "bpf_map_delete_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_sysctl",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static int xdp_unlink_bpf_chain (const char *map_filename)\n",
    "{\n",
    "    int ret = 0;\n",
    "    int key = 0;\n",
    "    int map_fd = bpf_obj_get (map_filename);\n",
    "    if (map_fd > 0) {\n",
    "        ret = bpf_map_delete_elem (map_fd, & key);\n",
    "        if (ret != 0) {\n",
    "            log_err (\"Failed to remove XDP program from the chain\");\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        log_err (\"Failed to fetch previous XDP program in the chain\");\n",
    "    }\n",
    "    if (remove (xdp_rl_ingress_next_prog) < 0) {\n",
    "        log_warn (\"Failed to remove link to next XDP program in the chain\");\n",
    "    }\n",
    "    return ret;\n",
    "}\n"
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
static int xdp_unlink_bpf_chain(const char *map_filename) {
    int ret = 0;
    int key = 0;
    int map_fd = bpf_obj_get(map_filename);
    if (map_fd > 0) {
       ret = bpf_map_delete_elem(map_fd, &key);
       if (ret != 0) {
           log_err("Failed to remove XDP program from the chain");
       }
    }
    else {
       log_err("Failed to fetch previous XDP program in the chain");
    }

    if (remove(xdp_rl_ingress_next_prog) < 0) {
        log_warn("Failed to remove link to next XDP program in the chain");
    }

    return ret;
}


/* Unlink xdp kernel program on receiving KILL/INT signals */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 171,
  "endLine": 182,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_user.c",
  "funcName": "signal_handler",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int signal"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_sysctl",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static void signal_handler (int signal)\n",
    "{\n",
    "    log_info (\"Received signal %d\", signal);\n",
    "    int i = 0;\n",
    "    xdp_unlink_bpf_chain (prev_prog_map);\n",
    "    for (i = 0; i < MAP_COUNT; i++) {\n",
    "        close (map_fd[i]);\n",
    "    }\n",
    "    if (info != NULL)\n",
    "        fclose (info);\n",
    "    exit (EXIT_SUCCESS);\n",
    "}\n"
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
static void signal_handler(int signal)
{
    log_info("Received signal %d", signal);
    int i = 0;
    xdp_unlink_bpf_chain(prev_prog_map);
    for(i=0; i<MAP_COUNT;i++) {
       close(map_fd[i]);
    }
    if (info != NULL)
        fclose(info);
    exit(EXIT_SUCCESS);
}

/* Get monotonic clock time in ns */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 185,
  "endLine": 199,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_user.c",
  "funcName": "time_get_ns",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "static__u64",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_sysctl",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static __u64 time_get_ns (void)\n",
    "{\n",
    "\n",
    "#ifdef __linux__\n",
    "    struct timespec ts;\n",
    "    clock_gettime (CLOCK_MONOTONIC, &ts);\n",
    "    return ts.tv_sec * 1000000000ull + ts.tv_nsec;\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef WIN32\n",
    "    LARGE_INTEGER frequency, counter;\n",
    "    QueryPerformanceFrequency (&frequency);\n",
    "    QueryPerformanceCounter (&counter);\n",
    "    return (1000000000 * counter.QuadPart) / frequency.QuadPart;\n",
    "\n",
    "#endif\n",
    "}\n"
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
static __u64 time_get_ns(void)
{
#ifdef __linux__
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ull + ts.tv_nsec;
#endif
#ifdef WIN32
    LARGE_INTEGER frequency, counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (1000000000 * counter.QuadPart) / frequency.QuadPart;
#endif
}

/* Delete stale map entries(LRU) based on the timestamp at which
 * a map element is created. */
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
          "Description": "Delete entry with <[ key ]>(IP: 1) from map. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_delete_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_delete_elem": [
      {
        "opVar": "            if (bpf_map_delete_elem(map_fd[1], &next_key) !",
        "inpVar": [
          " 0 "
        ]
      }
    ]
  },
  "startLine": 203,
  "endLine": 226,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_user.c",
  "funcName": "delete_stale_entries",
  "updateMaps": [
    " map_fd[1]"
  ],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "staticvoid",
  "helper": [
    "bpf_map_delete_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_sysctl",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static void delete_stale_entries (void)\n",
    "{\n",
    "    log_debug (\"Deleting stale map entries periodically\");\n",
    "    if (map_fd[1] < 0) {\n",
    "        log_info (\"Window map fd not found\");\n",
    "        exit (EXIT_FAILURE);\n",
    "    }\n",
    "    __u64 first_key = 0, next_key = 0;\n",
    "    __u64 curr_time = time_get_ns ();\n",
    "    log_debug (\"Current time is %llu\", curr_time);\n",
    "    while (!bpf_map_get_next_key (map_fd[1], &first_key, &next_key)) {\n",
    "        if (next_key < (curr_time - buffer_time)) {\n",
    "            log_debug (\"Deleting stale map entry %llu\", next_key);\n",
    "            if (bpf_map_delete_elem (map_fd[1], &next_key) != 0) {\n",
    "                log_info (\"Map element not found\");\n",
    "            }\n",
    "        }\n",
    "        first_key = next_key;\n",
    "    }\n",
    "}\n"
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
static void delete_stale_entries(void)
{
    log_debug("Deleting stale map entries periodically");

    if (map_fd[1] < 0) {
        log_info("Window map fd not found");
        exit(EXIT_FAILURE);
    }

    __u64 first_key = 0, next_key = 0;
    __u64 curr_time = time_get_ns();
    log_debug("Current time is %llu", curr_time);

    while (!bpf_map_get_next_key(map_fd[1], &first_key, &next_key))
    {
        if (next_key < (curr_time - buffer_time)) {
            log_debug("Deleting stale map entry %llu", next_key);
            if (bpf_map_delete_elem(map_fd[1], &next_key) != 0) {
                log_info("Map element not found");
            }
        }
        first_key = next_key;
    }
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 228,
  "endLine": 242,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_user.c",
  "funcName": "*trim_space",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "char *str"
  ],
  "output": "staticchar",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_sysctl",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static char *trim_space (char *str)\n",
    "{\n",
    "    char *end;\n",
    "    while (isspace (*str)) {\n",
    "        str = str + 1;\n",
    "    }\n",
    "    end = str + get_length (str) - 1;\n",
    "    while (end > str && isspace (*end)) {\n",
    "        end = end - 1;\n",
    "    }\n",
    "    *(end + 1) = '\\0';\n",
    "    return str;\n",
    "}\n"
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
static char* trim_space(char *str) {
    char *end;
    /* skip leading whitespace */
    while (isspace(*str)) {
        str = str + 1;
    }
    /* remove trailing whitespace */
    end = str + get_length(str) - 1;
    while (end > str && isspace(*end)) {
        end = end - 1;
    }
    /* write null character */
    *(end+1) = '\0';
    return str;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "strtol": [
      {
        "opVar": "  long long_var ",
        "inpVar": [
          " str",
          " &endptr",
          " 10"
        ]
      }
    ]
  },
  "startLine": 244,
  "endLine": 255,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_user.c",
  "funcName": "strtoi",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const char *str"
  ],
  "output": "staticint",
  "helper": [
    "strtol"
  ],
  "compatibleHookpoints": [
    "cgroup_sysctl"
  ],
  "source": [
    "static int strtoi (const char *str)\n",
    "{\n",
    "    char *endptr;\n",
    "    errno = 0;\n",
    "    long long_var = strtol (str, & endptr, 10);\n",
    "    if (errno == ERANGE || *endptr != '\\0' || str == endptr) {\n",
    "        fprintf (stderr, \"out of range\");\n",
    "    }\n",
    "    return (int) long_var;\n",
    "}\n"
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
static int strtoi(const char *str) {
  char *endptr;
  errno = 0;

  long long_var = strtol(str, &endptr, 10);
  //out of range, extra chars at end
  if (errno == ERANGE || *endptr != '\0' || str == endptr) {
     fprintf(stderr, "out of range");
  }

  return (int) long_var;
}

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
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_update_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "        map_fd[4]",
          " &port",
          " &pval",
          " 0"
        ]
      }
    ]
  },
  "startLine": 257,
  "endLine": 270,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_user.c",
  "funcName": "update_ports",
  "updateMaps": [
    " map_fd[4]"
  ],
  "readMaps": [],
  "input": [
    "char *ports"
  ],
  "output": "staticvoid",
  "helper": [
    "bpf_map_update_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_sysctl",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static void update_ports (char *ports)\n",
    "{\n",
    "    char *ptr, *tmp;\n",
    "    uint16_t port = 0;\n",
    "    uint8_t pval = 1;\n",
    "    tmp = strdup (ports);\n",
    "    while ((ptr = strsep (&tmp, delim)) != NULL) {\n",
    "        ptr = trim_space (ptr);\n",
    "        port = (uint16_t) (strtoi (ptr));\n",
    "        bpf_map_update_elem (map_fd[4], &port, &pval, 0);\n",
    "    }\n",
    "    free (tmp);\n",
    "}\n"
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
static void update_ports(char *ports)
{
    char *ptr,*tmp ;
    uint16_t port = 0;
    uint8_t pval = 1;
    tmp = strdup(ports);
    while((ptr = strsep(&tmp, delim)) != NULL)
    {
        ptr = trim_space(ptr);
        port = (uint16_t)(strtoi(ptr));
        bpf_map_update_elem(map_fd[4], &port, &pval, 0);
    }
    free(tmp);
}

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
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_update_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "            ifprev_prog_map_fd",
          " &pkey",
          " &prog_fd[0]",
          " 0 "
        ]
      },
      {
        "opVar": "        ret ",
        "inpVar": [
          " map_fd[0]",
          " &ckey",
          " &rate",
          " 0"
        ]
      },
      {
        "opVar": "        ret ",
        "inpVar": [
          " map_fd[2]",
          " &rkey",
          " &recv_count",
          " 0"
        ]
      },
      {
        "opVar": "        ret ",
        "inpVar": [
          " map_fd[3]",
          " &dkey",
          " &drop_count",
          " 0"
        ]
      }
    ]
  },
  "startLine": 272,
  "endLine": 423,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_user.c",
  "funcName": "main",
  "updateMaps": [
    " map_fd [3]",
    " prev_prog_map_fd",
    " map_fd [2]",
    " map_fd [0]"
  ],
  "readMaps": [],
  "input": [
    "int argc",
    " char **argv"
  ],
  "output": "int",
  "helper": [
    "bpf_map_update_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_sysctl",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "int main (int argc, char **argv)\n",
    "{\n",
    "    int longindex = 0, rate = 0, opt;\n",
    "    int ret = EXIT_SUCCESS;\n",
    "    char bpf_obj_file [256];\n",
    "    char ports [2048];\n",
    "    verbosity = LOG_INFO;\n",
    "\n",
    "#ifdef __linux__\n",
    "    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}\n",
    "    ;\n",
    "\n",
    "#endif\n",
    "    int len = 0;\n",
    "    snprintf (bpf_obj_file, sizeof (bpf_obj_file), \"%s_kern.o\", argv[0]);\n",
    "    memset (&ports, 0, 2048);\n",
    "    while ((opt = getopt_long (argc, argv, \"h\", long_options, &longindex)) != -1) {\n",
    "        switch (opt) {\n",
    "        case 'r' :\n",
    "            rate = strtoi (optarg);\n",
    "            break;\n",
    "        case 'i' :\n",
    "            ifindex = if_nametoindex (optarg);\n",
    "            break;\n",
    "        case 'v' :\n",
    "            if (optarg) {\n",
    "                verbosity = strtoi (optarg);\n",
    "            }\n",
    "            break;\n",
    "        case 'm' :\n",
    "            if (optarg) {\n",
    "                len = get_length (optarg);\n",
    "                strncpy (prev_prog_map, optarg, len);\n",
    "                prev_prog_map[len] = '\\0';\n",
    "            }\n",
    "            break;\n",
    "        case 'p' :\n",
    "            if (optarg) {\n",
    "                len = get_length (optarg);\n",
    "                strncpy (ports, optarg, len);\n",
    "                ports[len] = '\\0';\n",
    "            }\n",
    "            break;\n",
    "        case 'd' :\n",
    "            break;\n",
    "        case 'h' :\n",
    "        default :\n",
    "            usage (argv);\n",
    "            return EXIT_FAILURE;\n",
    "        }\n",
    "    }\n",
    "\n",
    "#ifdef __linux__\n",
    "    if (setrlimit (RLIMIT_MEMLOCK, &r)) {\n",
    "        perror (\"setrlimit(RLIMIT_MEMLOCK)\");\n",
    "        exit (EXIT_FAILURE);\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    set_logfile ();\n",
    "    __u64 ckey = 0, rkey = 0, dkey = 0, pkey = 0;\n",
    "    __u64 recv_count = 0, drop_count = 0;\n",
    "    if (load_bpf_file (bpf_obj_file)) {\n",
    "        log_err (\"Failed to load bpf program\");\n",
    "        return 1;\n",
    "    }\n",
    "    if (!prog_fd[0]) {\n",
    "        log_err (\"Failed to get bpf program fd\")\n",
    "        return 1;\n",
    "    }\n",
    "    int prev_prog_map_fd = bpf_obj_get (prev_prog_map);\n",
    "    if (prev_prog_map_fd < 0) {\n",
    "        log_err (\"Failed to fetch previous xdp function in the chain\");\n",
    "        exit (EXIT_FAILURE);\n",
    "    }\n",
    "    if (bpf_map_update_elem (prev_prog_map_fd, &pkey, &(prog_fd[0]), 0)) {\n",
    "        log_err (\"Failed to update prog fd in the chain\");\n",
    "        exit (EXIT_FAILURE);\n",
    "    }\n",
    "    close (prev_prog_map_fd);\n",
    "    int next_prog_map_fd = bpf_obj_get (xdp_rl_ingress_next_prog);\n",
    "    if (next_prog_map_fd < 0) {\n",
    "        log_info (\"Failed to fetch next prog map fd, creating one\");\n",
    "        if (bpf_obj_pin (map_fd[5], xdp_rl_ingress_next_prog)) {\n",
    "            log_info (\"Failed to pin next prog fd map\");\n",
    "            exit (EXIT_FAILURE);\n",
    "        }\n",
    "    }\n",
    "    if (!map_fd[0]) {\n",
    "        log_err (\"Failed to fetch config map\");\n",
    "        return -1;\n",
    "    }\n",
    "    ret = bpf_map_update_elem (map_fd [0], & ckey, & rate, 0);\n",
    "    if (ret) {\n",
    "        perror (\"Failed to update config map\");\n",
    "        return 1;\n",
    "    }\n",
    "    if (!map_fd[2]) {\n",
    "        log_err (\"Failed to fetch receive count map\");\n",
    "        return -1;\n",
    "    }\n",
    "    ret = bpf_map_update_elem (map_fd [2], & rkey, & recv_count, 0);\n",
    "    if (ret) {\n",
    "        perror (\"Failed to update receive count map\");\n",
    "        return 1;\n",
    "    }\n",
    "    if (!map_fd[3]) {\n",
    "        log_err (\"Failed to fetch drop count map\");\n",
    "        return -1;\n",
    "    }\n",
    "    ret = bpf_map_update_elem (map_fd [3], & dkey, & drop_count, 0);\n",
    "    if (ret) {\n",
    "        perror (\"Failed to update drop count map\");\n",
    "        return 1;\n",
    "    }\n",
    "    if (get_length (ports)) {\n",
    "        log_info (\"Configured port list is %s\\n\", ports);\n",
    "        update_ports (ports);\n",
    "    }\n",
    "    signal (SIGINT, signal_handler);\n",
    "    signal (SIGTERM, signal_handler);\n",
    "\n",
    "#ifdef __linux__\n",
    "    signal (SIGHUP, signal_handler);\n",
    "\n",
    "#endif\n",
    "    while (1) {\n",
    "        sleep (60);\n",
    "        delete_stale_entries ();\n",
    "        fflush (info);\n",
    "    }\n",
    "}\n"
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
int main(int argc, char **argv)
{
    int longindex = 0, rate = 0, opt;
    int ret = EXIT_SUCCESS;
    char bpf_obj_file[256];
    char ports[2048];
    verbosity = LOG_INFO;
#ifdef __linux__
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
#endif
    int len = 0;
    snprintf(bpf_obj_file, sizeof(bpf_obj_file), "%s_kern.o", argv[0]);

    memset(&ports, 0, 2048);

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "h", long_options, &longindex)) != -1)
    {
        switch (opt) {
            case 'r':
                rate = strtoi(optarg);
                break;
            case 'i':
                ifindex = if_nametoindex(optarg);
                break;
            case 'v':
                if(optarg) {
                    verbosity = strtoi(optarg);
                }
                break;
            case 'm':
                if(optarg) {
                    len = get_length(optarg);
                    strncpy(prev_prog_map, optarg, len);
                    prev_prog_map[len] = '\0';
                }
                break;
            case 'p':
                if(optarg) {
                    len = get_length(optarg);
                    strncpy(ports, optarg, len);
                    ports[len] = '\0';
                }
                break;
            case 'd':
                /* Not honoured as of now */
                break;
            case 'h':
            default:
                usage(argv);
                return EXIT_FAILURE;
        }
    }
#ifdef __linux__
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        exit(EXIT_FAILURE);
    }
#endif
    set_logfile();

    __u64 ckey = 0, rkey = 0, dkey = 0, pkey = 0;
    __u64 recv_count = 0, drop_count = 0;

    if (load_bpf_file(bpf_obj_file)) {
        log_err("Failed to load bpf program");
        return 1;
    }
    if (!prog_fd[0]) {
        log_err("Failed to get bpf program fd")
        return 1;
    }

    /* Get the previous program's map fd in the chain */
    int prev_prog_map_fd = bpf_obj_get(prev_prog_map);
    if (prev_prog_map_fd < 0) {
        log_err("Failed to fetch previous xdp function in the chain");
        exit(EXIT_FAILURE);
    }
    /* Update current prog fd in the last prog map fd,
     * so it can chain the current one */
    if(bpf_map_update_elem(prev_prog_map_fd, &pkey, &(prog_fd[0]), 0)) {
        log_err("Failed to update prog fd in the chain");
        exit(EXIT_FAILURE);
    }
     /* closing map fd to avoid stale map */
     close(prev_prog_map_fd);

    int next_prog_map_fd = bpf_obj_get(xdp_rl_ingress_next_prog);
    if (next_prog_map_fd < 0) {
        log_info("Failed to fetch next prog map fd, creating one");
        if (bpf_obj_pin(map_fd[5], xdp_rl_ingress_next_prog)) {
            log_info("Failed to pin next prog fd map");
            exit(EXIT_FAILURE);
        }
    }

    /* Map FDs are sequenced same as they are defined in the bpf program ie.,
     * map_fd[0] = rl_config_map, map_fd[1] = rl_window_map
     * map_fd[2] = rl_recv_count_map, map_fd[3] = rl_drop_count_map
     * map_fd[4] = rl_ports_map
     * map_fd[5] = xdp_rl_ingress_next_prog*/
    if (!map_fd[0]){
        log_err("Failed to fetch config map");
        return -1;
    }
    ret = bpf_map_update_elem(map_fd[0], &ckey, &rate, 0);
    if (ret) {
        perror("Failed to update config map");
        return 1;
    }

    if (!map_fd[2]) {
        log_err("Failed to fetch receive count map");
        return -1;
    }
    ret = bpf_map_update_elem(map_fd[2], &rkey, &recv_count, 0);
    if (ret) {
        perror("Failed to update receive count map");
        return 1;
    }

    if (!map_fd[3]) {
        log_err("Failed to fetch drop count map");
        return -1;
    }
    ret = bpf_map_update_elem(map_fd[3], &dkey, &drop_count, 0);
    if (ret) {
            perror("Failed to update drop count map");
            return 1;
    }
    if (get_length(ports)) {
        log_info("Configured port list is %s\n", ports);
        update_ports(ports);
    }

    /* Handle signals and exit clean */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#ifdef __linux__
    signal(SIGHUP, signal_handler);
#endif

    while(1)
    {
        sleep(60);
        /* Keep deleting the stale map entries periodically *
         * TODO Check if LRU maps can be used.              */
        delete_stale_entries();
        fflush(info);
    }
}

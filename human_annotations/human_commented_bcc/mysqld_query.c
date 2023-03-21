#include <uapi/linux/ptrace.h>
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Return Type": "int",
          "Description": "For tracing programs , safely attempt to read <[ size ]>(IP: 1) bytes from address <[ src ]>(IP: 2) and store the data in dst. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_probe_read",
          "Input Params": [
            "{Type: void ,Var: *dst}",
            "{Type:  u32 ,Var: size}",
            "{Type:  const void ,Var: *src}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_probe_read": [
      {
        "opVar": "NA",
        "inpVar": [
          "    _user&query",
          " sizeofquery",
          " void *addr"
        ]
      }
    ],
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "    \"%s\\\\n\"",
          " query"
        ]
      }
    ]
  },
  "startLine": 2,
  "endLine": 15,
  "File": "/root/examples/bcc/mysqld_query.c",
  "funcName": "do_trace",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_probe_read",
    "bpf_trace_printk"
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
      "description": "mysqld_query_do_trace() function is used for tracing mysql 
                      queries. It takes as argument a structure ctx of type pt_regs.
                      It uses bpf_usdt_readarg() to store the first argument into 
                      'addr' variable. Then the function bpf_probe_read_user() is 
                      used to store value at memory 'addr' in 'query'. Value in 
                      query is then printed using helper function bpf_trace_printk().
                      It reads the first argument from the query-start probe, which 
                      is the query. The format of this probe is 
                      \"query-start(query, connectionid, database, user, host)\". Refer to
                      https://dev.mysql.com/doc/refman/5.7/en/dba-dtrace-ref-query.html.
                      Function returns 0 on successful completion.",
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
int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    char query[128];
    /*
     * Read the first argument from the query-start probe, which is the query.
     * The format of this probe is:
     * query-start(query, connectionid, database, user, host)
     * see: https://dev.mysql.com/doc/refman/5.7/en/dba-dtrace-ref-query.html
     */
    bpf_usdt_readarg(1, ctx, &addr);
    bpf_probe_read_user(&query, sizeof(query), (void *)addr);
    bpf_trace_printk("%s\\n", query);
    return 0;
};

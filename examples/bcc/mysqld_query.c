#include <uapi/linux/ptrace.h>
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

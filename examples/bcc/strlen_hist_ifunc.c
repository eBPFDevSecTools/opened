#include <uapi/linux/ptrace.h>

BPF_HISTOGRAM(dist);
int count(struct pt_regs *ctx) {
    dist.increment(bpf_log2l(PT_REGS_RC(ctx)));
    return 0;
}


BPF_PERF_OUTPUT(impl_func_addr);
void submit_impl_func_addr(struct pt_regs *ctx) {
    u64 addr = PT_REGS_RC(ctx);
    impl_func_addr.perf_submit(ctx, &addr, sizeof(addr));
}


BPF_PERF_OUTPUT(resolv_func_addr);
int submit_resolv_func_addr(struct pt_regs *ctx) {
    u64 rip = PT_REGS_IP(ctx);
    resolv_func_addr.perf_submit(ctx, &rip, sizeof(rip));
    return 0;
}

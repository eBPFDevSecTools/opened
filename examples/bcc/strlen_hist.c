#include <uapi/linux/ptrace.h>
BPF_HISTOGRAM(dist);
int count(struct pt_regs *ctx) {
    dist.increment(bpf_log2l(PT_REGS_RC(ctx)));
    return 0;
}

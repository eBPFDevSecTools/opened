#include <uapi/linux/ptrace.h>

BPF_HASH(calls, int);
BPF_STACK_TRACE(stack_traces, """ + stacks + """);

int alloc_enter(struct pt_regs *ctx, size_t size) {
    int key = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    if (key < 0)
        return 0;

    // could also use `calls.increment(key, size);`
    u64 zero = 0, *val;
    val = calls.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val) += size;
    }
    return 0;
};

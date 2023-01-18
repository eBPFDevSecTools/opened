#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;
    int user_stack_id;
    char name[TASK_COMM_LEN];
};
BPF_HASH(counts, struct key_t);
BPF_STACK_TRACE_BUILDID(stack_traces, 128);

int do_perf_event(struct bpf_perf_event_data *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // create map key
    struct key_t key = {.pid = pid};
    bpf_get_current_comm(&key.name, sizeof(key.name));

    key.user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);

    if (key.user_stack_id >= 0) {
      counts.increment(key);
    }
    return 0;
}

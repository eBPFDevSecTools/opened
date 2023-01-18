#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 stack_id;
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_STACK_TRACE(stack_traces, 128);
BPF_PERF_OUTPUT(events);

void trace_stack(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER
    struct data_t data = {};
    data.stack_id = stack_traces.get_stackid(ctx, 0),
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
}

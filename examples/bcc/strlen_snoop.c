#include <uapi/linux/ptrace.h>
int printarg(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    u32 pid = bpf_get_current_pid_tgid();
    if (pid != PID)
        return 0;

    char str[80] = {};
    bpf_probe_read_user(&str, sizeof(str), (void *)PT_REGS_PARM1(ctx));
    bpf_trace_printk("%s\\n", &str);

    return 0;
};

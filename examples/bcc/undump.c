#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/aio.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <net/sock.h>
#include <net/af_unix.h>

#define MAX_PKT 512
struct recv_data_t {
    u32 recv_len;
    u8  pkt[MAX_PKT];
};

// single element per-cpu array to hold the current event off the stack
BPF_PERCPU_ARRAY(unix_data, struct recv_data_t, 1);

BPF_PERF_OUTPUT(unix_recv_events);

int trace_unix_stream_read_actor(struct pt_regs *ctx)
{
    u32 zero = 0;
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    FILTER_PID

    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

    struct recv_data_t *data = unix_data.lookup(&zero);
    if (!data)
        return 0;

    unsigned int data_len = skb->len;
    if(data_len > MAX_PKT)
        return 0;

    void *iodata = (void *)skb->data;
    data->recv_len = data_len;

    bpf_probe_read(data->pkt, data_len, iodata);
    unix_recv_events.perf_submit(ctx, data, data_len+sizeof(u32));

    return 0;
}

BPF_PERF_OUTPUT(events);
BPF_ARRAY(counters, u64, 10);
int do_sys_clone(void *ctx) {
  struct {
    u64 ts;
    u64 magic;
  } data = {bpf_ktime_get_ns(), 0x12345678};
  int rc;
  if ((rc = events.perf_submit(ctx, &data, sizeof(data))) < 0)
    bpf_trace_printk("perf_output failed: %d\\n", rc);
  int zero = 0;
  u64 *val = counters.lookup(&zero);
  if (val) lock_xadd(val, 1);
  return 0;
}

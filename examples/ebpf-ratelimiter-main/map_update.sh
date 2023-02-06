iface=${VETH_NAME}
ip link set dev ${iface} xdp obj ratelimiting_kern.o sec xdp_ratelimiting
echo "Setting rate"
#bpftool  map update id ${rate_map} key hex 00 00 00 00 value hex 04 00 00 00 00 00 00 00
bpftool  map update pinned /sys/fs/bpf/xdp/globals/rl_config_map key hex 00 00 00 00 value hex 04 00 00 00 00 00 00 00
bpftool map dump pinned /sys/fs/bpf/xdp/globals/rl_config_map
#bpftool  map update id ${rate_map} key hex 00 00 00 00 value hex 11 11 11 11 11 11 11 11
#bpftool  map update id ${rate_map} key hex 00 00 00 00 value hex 03 03 03 03 03 03 03 03
#bpftool map dump  id ${rate_map}
echo "Setting port"
bpftool map update pinned /sys/fs/bpf/xdp/globals/rl_ports_map key hex 00 06 value hex 06
bpftool map dump pinned /sys/fs/bpf/xdp/globals/rl_ports_map
#bpftool  map update id ${port_map} key hex 00 06  value hex 06
#bpftool map dump  id ${port_map}
echo "Setting recv count"
bpftool  map update pinned /sys/fs/bpf/xdp/globals/rl_recv_count_map key hex 00 00 00 00 00 00 00 00 value hex 00 00 00 00 00 00 00 00
bpftool map dump pinned /sys/fs/bpf/xdp/globals/rl_recv_count_map
#bpftool  map update id ${recv_map} key hex 00 00 00 00 00 00 00 00 value hex 00 00 00 00 00 00 00 00
#bpftool map dump  id ${recv_map}
echo "Setting drop count"
bpftool  map update pinned /sys/fs/bpf/xdp/globals/rl_drop_count_map key hex 00 00 00 00 00 00 00 00 value hex 00 00 00 00 00 00 00 00
bpftool map dump pinned /sys/fs/bpf/xdp/globals/rl_drop_count_map
#bpftool  map update id ${drop_map} key hex 00 00 00 00 00 00 00 00 value hex 00 00 00 00 00 00 00 00
#bpftool map dump  id ${drop_map}

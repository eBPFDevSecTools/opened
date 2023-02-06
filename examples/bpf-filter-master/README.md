tc based bpf filter
===========

Setup
--------
1. Setup clang and llc and bpftool
```
$ sudo apt-get install make gcc libssl-dev bc libelf-dev libcap-dev \
	clang gcc-multilib llvm libncurses5-dev git pkg-config libmnl-dev \
	bison flex graph viz
$ sudo apt install linux-tools-generic
```
1. Setup golang - 
```
$ export GOVERSION=1.15.8
$ mkdir /tmp/golang;
$ pushd; cd /tmp/golang;
$ wget https://dl.google.com/go/go$\{GOVERSION\}.linux-amd64.tar.gz
$ wget https://dl.google.com/go/go${GOVERSION}.linux-amd64.tar.gz
$ tar -xzf go${GOVERSION}.linux-amd64.tar.gz
$ mv go /usr/local/go${GOVERSION}
$ ln -sfn /usr/local/go${GOVERSION} /usr/local/go
	
```
1. Setup iproute2 - 
```
$ git clone https://git.kernel.org/pub/scm/network/iproute2/iproute2.git
$ cd iproute2
$ ./configure --prefix=/usr
$ sudo make install
# Copy the `bpf_api.h` helpers file that lives under `./include`
# to your `/usr/include` directory.
#
# ps.: this could be anywhere - including your current source tree.
$ install -m 0644 ./include/bpf_api.h /usr/include/iproute2
```

Running
--------
```
  $ make
  $ ./bin/main
  $ make drop-install
```

# This repo is based on [florianl/go-tc](https://github.com/florianl/go-tc)

Overview
--------
After the eBPF code is loaded from `ebpf/drop` the eBPF program `ingress_drop` is loaded into the kernel. In a next step this PoC creates a dummy interface. So it does not alter existing configurations or network interfaces. Then a [qdisc and filter](https://man7.org/linux/man-pages/man8/tc.8.html) are attached via the [netlink interface](https://man7.org/linux/man-pages/man7/netlink.7.html) of the kernel to this dummy interface. The file descriptor of the eBPF program `ingress_drop` is passed as argument of the filter to the kernel. With attaching the filter to the interface the eBPF program `ingress_drop` will run on every packet on the interface.

Privileges
----------
This PoC uses the [`netlink`](https://man7.org/linux/man-pages/man7/netlink.7.html) and [`eBPF`](https://man7.org/linux/man-pages/man2/bpf.2.html) interface of the kernel and therefore it requires special privileges. You can provide this privileges by adjusting the `CAP_NET_ADMIN` capabilities.

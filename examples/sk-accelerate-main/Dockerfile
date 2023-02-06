# Need at least glibc, libelf, libz installed to run xdp-loader, bpftool, and other binaries

# Use a slightly older version of fedora so it's linked to an older version of glibc (v2.29)
FROM fedora:32 AS builder
RUN dnf -y update && \
    dnf install -y clang llvm gcc elfutils-libelf-devel glibc-devel.i686 m4 libpcap-devel make bison flex && \
    dnf install -y findutils vim git
COPY ./ /tmp/xdp
RUN make -C /tmp/xdp/src

FROM debian:latest as bpftool
RUN apt-get update -y
RUN apt-get install -y make gcc libssl-dev bc libelf-dev libcap-dev \
	clang gcc-multilib llvm libncurses5-dev git pkg-config libmnl-dev \
	bison flex libbpf-dev iproute2 jq wget apt binutils-dev
RUN git clone --depth 1 -b v6.8.0 --recurse-submodules https://github.com/libbpf/bpftool.git /tmp/bpftool && \
cd /tmp/bpftool/src && \
sed -i 's/\-lbfd //g' Makefile && \
sed -i '/CFLAGS += -O2/ i feature-libbfd := 0' Makefile && \
CFLAGS=--static make && \
strip bpftool && \
ldd bpftool 2>&1 | grep -q -e "Not a valid dynamic program" \
	-e "not a dynamic executable" || \
	( echo "Error: bpftool is not statically linked"; false )

FROM golang:alpine as gobuilder
COPY ./src/sockmap_daemon.go $GOPATH/src
COPY ./src/sockmap_controller.go $GOPATH/src
COPY ./src/go.mod $GOPATH/src
COPY ./src/go.sum $GOPATH/src
RUN cd $GOPATH/src && ls -al /go/src
RUN cd $GOPATH/src && go get github.com/moby/sys/mountinfo
RUN cd $GOPATH/src && go build -o /sockmap_daemon *.go

FROM frolvlad/alpine-glibc:alpine-3.14_glibc-2.33
RUN apk add libelf
RUN mkdir -p /root/bin
COPY --from=bpftool /tmp/bpftool/src/bpftool /root/bin/
COPY --from=builder /tmp/xdp/src/.output/sockmap_redir.o /root/bin/
COPY --from=builder /tmp/xdp/src/.output/sockops.o /root/bin/
COPY --from=gobuilder /sockmap_daemon /root/bin/sockmap_daemon

BINDIR=bin
EXEC=main

IFACE ?= eth0

BPFDIR=ebpf
BPFBIN=${BINDIR}/bpf
BPFEXEC=drop

.PHONY: all
.default: ${EXEC}

${EXEC}: ${BINDIR} drop
	go build -o ${BINDIR}/${EXEC} ${EXEC}.go

drop: ${BPFBIN}
	clang -O2 -g -Wall -emit-llvm -c ${BPFDIR}/drop.c -o ${BPFBIN}/drop.bc
	llc -march=bpf -mcpu=probe -filetype=obj ${BPFBIN}/drop.bc -o ${BPFBIN}/drop.o

drop-install: drop
	tc qdisc add dev ${IFACE} clsact
	tc filter add dev ${IFACE} ingress bpf da obj ${BPFBIN}/drop.o sec classifier_ingress_drop
	tc filter add dev ${IFACE} egress bpf da obj ${BPFBIN}/drop.o sec classifier_egress_drop

drop-uninstall:
	tc qdisc del dev ${IFACE} clsact

show:
	tc filter show dev ${IFACE} ingress
	tc filter show dev ${IFACE} egress

${BINDIR}:
	mkdir -p ${BINDIR}

${BPFBIN}:
	mkdir -p ${BPFBIN}

clean:
	rm -r ${BINDIR}

clean-maps:
	rm -r /sys/fs/bpf/tc/globals/*
#!/bin/bash

iface=${VETH_NAME}
iface_id=${VETH_ID}
pod_mac=${VPEER_MAC}
pod_ip=${POD_IP}

BPF_PROG=${3:-./bin/bpf/drop.o}

TC='/sbin/tc'
BPF_USER="./bin/main"

#run user prog for programming maps
CMD=${BPF_USER}" --mode add --idx "${iface_id}" --pod_mac "${pod_mac}" --pod_ip "${pod_ip}

echo "${CMD}"
${CMD}
if [ $? -eq 1 ]
then
    echo ${CMD}" failed error code "$?
    exit 1
fi

echo "Attaching bpf-filter to tc hookpoint"
${TC} qdisc add dev ${iface} clsact
${TC} filter add dev ${iface} ingress bpf da obj ${BPF_PROG} sec classifier_bpf_filter

#!/bin/bash -x

# Prereq:
# - jq
# - git
# - perf
# - perl

#git clone https://github.com/brendangregg/FlameGraph.git

iperf3_runtime=30
wait_time=$((iperf3_runtime+10))
buffer_len=128K

function run_server()
{
  kubectl run pod1 --image=networkstatic/iperf3 --overrides="{\"spec\": { \"nodeSelector\": {\"kubernetes.io/hostname\": \"$1\"}}}" --command -- iperf3 -s --forceflush
  kubectl expose pod pod1 --port 5201 --name pod1
}

function pod_ip()
{
  ipq=$(kubectl get pods pod1 -o json|jq ".status.podIP")
  ipq1=${ipq#\"}
  ip=${ipq1%\"}
  echo "$ip"
}

function svc_ip()
{
  ipq=$(kubectl get service pod1 -o json | jq ".spec.clusterIP")
  ipq1=${ipq#\"}
  ip=${ipq1%\"}
  echo "$ip"
}

function run_client()
{
  cat >client-job.yaml <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: iperf3-client
spec:
  template:
    spec:
      containers:
      - name: iperf3-client
        image: networkstatic/iperf3
        command: ["iperf3", "-c", "$2", "-t", "$iperf3_runtime", "-l", "$buffer_len", "--forceflush"]
      nodeName: $1
      restartPolicy: Never
  backoffLimit: 4
EOF
  kubectl apply -f client-job.yaml
  client_pod=$(kubectl get pods --selector=job-name=iperf3-client --output=jsonpath='{.items[*].metadata.name}')
}

function run_client_v6()
{
  cat >client-job.yaml <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: iperf3-client
spec:
  template:
    spec:
      containers:
      - name: iperf3-client
        image: networkstatic/iperf3
        command: ["iperf3", "-c", "$2", "-6", "-t", "$iperf3_runtime", "--forceflush"]
      nodeName: $1
      restartPolicy: Never
  backoffLimit: 4
EOF
  kubectl apply -f client-job.yaml
  client_pod=$(kubectl get pods --selector=job-name=iperf3-client --output=jsonpath='{.items[*].metadata.name}')
}

function hostip_of()
{
  hostipq=$(kubectl get pods $1 -o json|jq ".status.hostIP")
  hostipq1=${hostipq#\"}
  hostip=${hostipq1%\"}
  echo $hostip
}

function uid_of()
{
  uidq=$(kubectl get pods $1 -o json|jq ".metadata.uid")
  uidq1=${uidq#\"}
  uid=${uidq1%\"}
  echo $uid
}

function container_of() {
  echo $(kubectl get pod $1 -o json | jq -r ".status.containerStatuses[0].containerID" | cut -b 14-)
}

function cpu_of() {
  pid=$(cat /sys/fs/cgroup/perf_event/kubepods-besteffort-pod${1}.slice:cri-containerd:${2}/cgroup.procs)
  for i in $(seq 0 $iperf3_runtime)
  do
    ps -p $pid -o %cpu= >> ${output_dir}/.${3}_cpu.txt
    sleep 1
  done
}

server_hostname=$1
client_hostname=$2
output_dir=$3
mkdir -p ${output_dir}
run_server ${server_hostname}
server_hostip=$(hostip_of pod1)
server_uid=$(uid_of pod1)
kubectl wait --for=condition=Ready pod/pod1
#run_client_v6 ${client_hostname} $(pod_ip)
run_client ${client_hostname} $(svc_ip)
client_hostip=$(hostip_of ${client_pod})
client_uid=$(uid_of ${client_pod})
kubectl wait --for=condition=Ready pod/${client_pod}
server_containerid=$(container_of pod1)
client_containerid=$(container_of ${client_pod})

#server_alt_uid=$(echo -n $server_uid|tr '-' '_')
#client_alt_uid=$(echo -n $client_uid|tr '-' '_')
#perf record -g -a -o server-perf.data -e cycles -G kubepods-besteffort-pod${server_alt_uid}.slice:cri-containerd:${server_containerid} sleep $iperf3_runtime &
#perf record -g -a -o client-perf.data -e cycles -G kubepods-besteffort-pod${client_alt_uid}.slice:cri-containerd:${client_containerid} sleep $iperf3_runtime &

#rm -f ${output_dir}/.server_cpu.txt
#rm -f ${output_dir}/.client_cpu.txt
#cpu_of $server_alt_uid $server_containerid "server" &
#cpu_of $client_alt_uid $client_containerid "client" &

sleep $wait_time
#kubectl logs pod1 >${output_dir}/server.log
#kubectl logs ${client_pod} >${output_dir}/client.log
kubectl logs ${client_pod}
#perf script -i server-perf.data | ./FlameGraph/stackcollapse-perf.pl | ./FlameGraph/flamegraph.pl >${output_dir}/server-flamegraph.svg
#perf script -i client-perf.data | ./FlameGraph/stackcollapse-perf.pl | ./FlameGraph/flamegraph.pl >${output_dir}/client-flamegraph.svg

#cat ${output_dir}/.server_cpu.txt | sed -e 'H;${x;s/\n/,/g;s/^,//;p;};d' > ${output_dir}/server_cpu.txt
#cat ${output_dir}/.client_cpu.txt | sed -e 'H;${x;s/\n/,/g;s/^,//;p;};d' > ${output_dir}/client_cpu.txt

#rm -f server-perf.data
#rm -f client-perf.data
kubectl delete pod pod1
kubectl delete svc pod1
kubectl delete job iperf3-client
#rm -f client-job.yaml

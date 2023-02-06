#!/bin/bash -x

# Prereq:
# - jq
# - git
# - perf
# - perl

netperf_runtime=30
# Other useful test is TCP_CRR
netperf_test=TCP_RR
wait_time=$((netperf_runtime+10))

function run_server()
{
  kubectl run pod1 --image=networkstatic/netperf --overrides="{\"spec\": { \"nodeSelector\": {\"kubernetes.io/hostname\": \"$1\"}}}" --command -- netserver -4 -D -p 5201
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
  name: netperf-client
spec:
  template:
    spec:
      containers:
      - name: netperf-client
        image: networkstatic/netperf
        command: ["netperf", "-P", "0", "-4", "-t", "${netperf_test}", "-H", "$2", "-p", "5201", "-l", "${netperf_runtime}", "--", "-o", "P50_LATENCY,P90_LATENCY,P99_LATENCY"]
      nodeName: $1
      restartPolicy: Never
  backoffLimit: 4
EOF
  kubectl apply -f client-job.yaml
  client_pod=$(kubectl get pods --selector=job-name=netperf-client --output=jsonpath='{.items[*].metadata.name}')
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

server_hostname=$1
client_hostname=$2
output_dir=$3
mkdir -p ${output_dir}
run_server ${server_hostname}
server_hostip=$(hostip_of pod1)
server_uid=$(uid_of pod1)
kubectl wait --for=condition=Ready pod/pod1
#run_client_v6 ${client_hostname} $(pod_ip)
run_client ${client_hostname} $(pod_ip)
client_hostip=$(hostip_of ${client_pod})
client_uid=$(uid_of ${client_pod})
kubectl wait --for=condition=Ready pod/${client_pod}
server_containerid=$(container_of pod1)
client_containerid=$(container_of ${client_pod})

sleep $wait_time
kubectl logs ${client_pod}
kubectl delete pod pod1
kubectl delete svc pod1
kubectl delete job netperf-client
rm -f client-job.yaml

#Authors
# Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
# Sayandeep Sen <sayandes@in.ibm.com>


# namespace ns1 -> veth1 40.0.1.2/24
# namespace ns2 -> veth2 40.0.2.2/24
import os
import time
import argparse
import os
import re
import subprocess
import glob
import command
import shutil
import argparse
from collections import defaultdict


def check_if_cmd_available():
    commands = ['tcpdump', 'ip', 'tc']
    for cmd in commands:
        if shutil.which(cmd) is None:
            print("Command: ",cmd," unavailable.. ", "Exiting")
            return False
    print("All necessary commands found...")
    return True

def check_if_file_available(files):
    #files = [r'asset/c-extract-functions.txl', r'asset/c-extract-struct.txl', r'asset/c.grm.1', r'asset/bom.grm', r'asset/helper_hookpoint_map.json']
    for fl in files:
        if os.path.isfile(fl) is False:
            print("File: ",fl," unavailable.. ", "Exiting")
            return False
    print("All necessary asset files found...")
    return True

#rm cscope.files cscope.out tags myproject.db 
def clean_intermediate_files(file_list):
    for file_path in file_list:
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))

def run_cmd(cmd):
    print("Running: ",cmd)
    status, output = subprocess.getstatusoutput(cmd)
    if(status != 0):
        print("Failed while running: ",cmd," Exiting...")
        exit(1)
    return output

# Add qdisc to interface
def add_qdisc(iface):
    print("IFACE: "+iface+"\n")
    output = run_cmd("tc qdisc add dev "+iface +"clsact")



def del_qdisc(iface):
    print("IFACE: "+iface+" \n")
    output = run_cmd("tc qdisc del dev "+iface +"clsact")

# Attach TC to interface
def attach_to_filter(iface, prog, sec):
  output = run_cmd("tc filter add dev "+iface+" ingress bpf da obj "+prog+" sec "+sec)


def clean_TC(iface):
    del_qdisc(iface)


# attach_at_TC <iface> <prog> <sec>
def attach_at_TC(iface, prog, sec):
    add_qdisc(iface)
    attach_to_filter(iface, prog, sec)


#attach_at_XDP <prog> <sec>
def attach_at_XDP(iface, prog, sec) :
    output = run_cmd("ip link set "+iface+" xdpgeneric obj "+prog+" sec "+sec)


def clean_XDP(iface):
    output = run_cmd("ip link set "+iface+" xdpgeneric off")



def clean():
    output = run_cmd("ip netns del ns1")
    output = run_cmd("ip netns del ns2")
    output = run_cmd("ip link del veth1")
    output = run_cmd("ip link del veth2")

def setup_interfaces():
    for r in range(1,3):
        i =str(r)
        #output = run_cmd("ip netns del ns"+i+" > /dev/null 2>&1")# remove ns if already existed
        #output = run_cmd("ip link del veth"+i+" > /dev/null 2>&1")
        output = run_cmd("ip netns add ns"+i)
        output = run_cmd("ip link add veth"+i+"_ type veth peer name veth"+i)
        output = run_cmd("ip link set veth"+i+"_ netns ns"+i)
        output = run_cmd("ip netns exec ns"+i+" ip link set dev veth"+i+"_ up")
        output = run_cmd("ip netns exec ns"+i+" ip link set dev lo up")
        output = run_cmd("ip link set dev veth"+i+" up")
        output = run_cmd("ip netns exec ns"+i+" ifconfig veth"+i+"_ 40.0."+i+".2/24")
        output = run_cmd("ifconfig veth"+i+" 40.0."+i+".1/24")
        output = run_cmd("ip netns exec ns"+i+" route add  default gw 40.0."+i+".1 veth"+i+"_")

def start_nc_server(PORT) :
    # run nc server in ns2 and scapy in ns1
    output = run_cmd("ip netns exec ns2 nc -l -p "+PORT+" &")

def start_python_receiver(PORT):
    # run python server in ns2 and scapy in ns1
    cmd = "ip netns exec ns2 python3 ./pkt-gen/recv.py &"
    output = run_cmd(cmd)


def start_python_sender():
    cmd = "ip netns exec ns1 python3 ./pkt-gen/send.py "
    output = run_cmd(cmd)

#attach_and_check <hookpoint> <prog> <sec>
def attach_only(hook_p, obj_f, section, iface):
    #clean
    setup_interfaces()
 
    if hook_p.upper().equals("TC"):
        attach_at_TC(iface, obj_f, section) 
        op_f = "recv-tc.pcap"
    else:
        attach_at_XDP(iface, obj_f, section)
        op_f = "recv-xdp.pcap"
    time.sleep(1)
    cmd = "tcpdump -i "+iface+" -vvv -e -u not arp and not icmp and not ip6 -w "+ op_f+ " &"
    output = run_cmd(cmd)

#attach_and_check <hookpoint> <prog> <sec>
def attach_and_check(hook_p, obj_f, section, iface):
    #clean
    setup_interfaces()
 
    if hook_p.upper().equals("TC"):
        attach_at_TC(iface, obj_f, section) 
        op_f = "recv-tc.pcap"

    else:
        attach_at_XDP(iface, obj_f, section)
        op_f = "recv-xdp.pcap"
    time.sleep(1)
    cmd = "tcpdump -i "+iface+" -vvv -e -u not arp and not icmp and not ip6 -w "+ op_f+ " &"
    output = run_cmd(cmd)
    start_python_receiver(20000)

    start_python_sender()

    #wait for tcpdump to flush
    time.sleep(5)
    output = run_cmd("killall tcpdump")

# main


if __name__=="__main__":
    #<script> <prog> <sec>
    parser = argparse.ArgumentParser(description='eBPF Transformation Verifier')

    parser.add_argument('-t','--bpfTCProgFile', type=str,required=False,
            help='eBPF Object file for TC hook point')

    parser.add_argument('-x','--bpfXDPProgFile', type=str,required=False,
            help='eBPF Object file for XDP hook point')


    parser.add_argument('-u','--TCSec', type=str,required=False,
            help='TC code section name')
    
    parser.add_argument('-y','--XDPSec',type=str,required=False,
            help='XDP code section name')


    args = parser.parse_args()


    print("Args",args)


    PROG_TC= args.bpfTCProgFile
    PROG_XDP=args.bpfXDPProgFile
    SEC_TC=args.TCSec
    SEC_XDP=args.XDPSec

    if PROG_TC == None and PROG_XDP == None:
        print("Atleast one of PROG_TC or PROG_XDP should be set")
        exit(1)

    if PROG_TC != None and SEC_TC == None:
        print("SEC_TC should be set")
        exit(1)

    if PROG_XDP != None and SEC_XDP == None:
        print("SEC_XDP should be set")
        exit(1)

    check_if_cmd_available()

    setup_interfaces()
    iface = "veth1"

    if PROG_XDP != None:
        print("Attaching at XDP")
        attach_at_XDP(iface, PROG_XDP, SEC_XDP) 

    if PROG_TC != None:
        print("Attaching at TC")
        attach_at_TC(iface, PROG_TC, SEC_TC)

#Authors
# Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
# Sayandeep Sen <sayandes@in.ibm.com>


# namespace ns1 -> veth1 40.0.1.2/24
# namespace ns2 -> veth2 40.0.2.2/24


import os
import time

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
    for i in range(2):
	output = run_cmd("ip netns del ns"+i+" > /dev/null 2>&1")# remove ns if already existed
	output = run_cmd("ip link del veth"+i+" > /dev/null 2>&1")
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

check_if_cmd_available()
check_if_file_available(files)

if __name__=="__main__":
    #<script> <prog> <sec>
    parser = argparse.ArgumentParser(description='eBPF Transformation Verifier')

    parser.add_argument('-t','--bpfTCProgFile', type=str,required=True,
            help='eBPF Object file for TC hook point')

    parser.add_argument('-x','--bpfXDPProgFile', type=str,required=True,
            help='eBPF Object file for XDP hook point')


    parser.add_argument('-u','--TCSec', type=str,required=True,
            help='TC code section name')
    
    parser.add_argument('-y','--XDPSec', nargs='+', type=str,required=True,
            help='XDP code section name')


    args = parser.parse_args()


    print("Args",args)


    PROG_TC= args.bpfTCProgFile
    PROG_XDP=args.bpfXDPProgFile
    SEC_TC=args.TCSec
    SEC_XDP=args.XDPSec

    print("Attaching at TC")
    attach_and_check("TC", PROG_TC, SEC_TC)
    #clean_TC veth2
    attach_and_check("XDP",PROG_XDP, SEC_XDP)
    #clean_XDP veth2
    output = run_cmd("python3 ../dep/pcap-diff/pcap-diff.py -i recv-xdp.pcap -i recv-tc.pcap -c -m")

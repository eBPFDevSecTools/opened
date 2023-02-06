import json
import subprocess
import sys

def run_cmd(cmd):
    print("Running: ",cmd)
    status, output = subprocess.getstatusoutput(cmd)
    if(status != 0):
        print("Failed while running: ",cmd," Exiting...")
        exit(1)
    return output



def load_map_json(fname):
    with open(fname, 'r') as f:
        data = json.load(f)
    return data

def get_umaps(maps):
    global rate_map,port_map,recv_map,drop_map
    for m in maps:
        if m['type'] == 'xdp':
            umaps = m['map_ids']
            umaps.sort()
            print(umaps)
            rate_map = umaps[0]
            port_map = umaps[4]
            recv_map = umaps[2]
            drop_map = umaps[3]
            print("RateMap: ",rate_map,"port_map",port_map)
        
if __name__ == "__main__":
    iface = sys.argv[1]
    rate_map=""
    port_map=""
    recv_map=""
    drop_map=""
    
    cmd = "ip link set dev " + iface + " xdp obj ratelimiting_kern.o sec xdp_ratelimiting"
    run_cmd(cmd)
    cmd = "bpftool prog show -j > prog.json"
    run_cmd(cmd)
    fname="prog.json"
    maps = load_map_json(fname)
    get_umaps(maps)
    cmd = "bash map_update.sh " +str(rate_map) + " " + str(port_map) + " " + str(recv_map) + " " + str(drop_map)
    run_cmd(cmd)
    

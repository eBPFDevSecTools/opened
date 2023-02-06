from scapy.all import *
import time
import argparse

def allow_connections(num,sleep_time):
    print("Allow Connections")
    global pcount,scount
    for i in range(num):
        ip=IP(src=src_ip,dst=dst_ip)  
        SYN=TCP(sport=pcount,dport=dport,flags="S",seq=scount)
        send(ip/SYN)
        scount = scount + 1
        pcount = pcount + 1
        time.sleep(sleep_time)

def deny_connections(num):
    print("Deny Connections")
    global pcount,scount
    for i in range(num):
        ip=IP(src=src_ip,dst=dst_ip)  
        SYN=TCP(sport=pcount,dport=dport,flags="S",seq=scount)
        send(ip/SYN)
        scount = scount + 1
        pcount = pcount + 1

if __name__ == "__main__":
    src_ip = "40.0.0.2"
    dst_ip = "40.0.0.1"
    dport = 8080
    pcount = 3000
    scount = 12345
    parser = argparse.ArgumentParser(description='packet loadgen for rate limiter')

    parser.add_argument("-m", "--mode", help="Test limited connection or flood allow/deny", type=str)
    args = parser.parse_args()

    if args.mode == 'allow':
        allow_connections(10, 2)
    elif args.mode == 'deny':
        deny_connections(100)
    else:
        print("Unknown mode for packet crafter. Please pass allow/deny\n")


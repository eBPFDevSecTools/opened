from scapy.all import *
import time

src_mac = "ab:cd:ef:ab:cd:ef"
dst_mac = "ef:cd:ab:ef:cd:ab"
src_ip = "1.2.3.4"
dst_ip = "3.4.5.6"
port = 8080

for i in range(20):
    sendp(Ether(src=src_mac,
                dst=dst_mac)/
                IP(src=src_ip,
                dst=dst_ip)/
                UDP(dport=port)/
                b"hello")

print("Done")

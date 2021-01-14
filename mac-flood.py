#!/usr/bin/python3

import string
from scapy.all import *
import signal
import sys

signal.signal(signal.SIGINT, lambda s, f: sys.exit(-1))	

randmac = lambda: RandMAC("*:*:*:*:*:*")
randip = lambda: RandIP("*.*.*.*")
packet = lambda: Ether(src=randmac(), dst=randmac())/IP(src=randip(), dst=randip())/ICMP()

print("Preparing packets")

pcks = [];
for i in range(0, 65535):
	pcks.append(packet())

print("Prepared {} random packets".format(len(pcks)))

sendp(pcks, iface="enp0s3.104")


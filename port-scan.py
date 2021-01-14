#!/usr/bin/python3

from scapy.all import *
import signal
import sys

signal.signal(signal.SIGINT, lambda s, f: sys.exit(-1))	

if len(sys.argv) < 2:
	print("Usage: {} <target>".format(sys.argv[0]))
	sys.exit(-1)

target = sys.argv[1]

src_port = RandShort()

closed = 0
open = 0
filtered = 0

for dst_port in range(1, 10000):
	chall = IP(dst=target)/TCP(sport=src_port, dport=dst_port, flags="S");
	resp = sr1(chall, timeout=0.2, verbose=0);
	
	if resp and resp.haslayer(TCP):
		flags = resp[TCP].flags
		if flags == 20:
			# closed. don't do anything
			closed = closed + 1
		elif flags == 18:
			open = open + 1
			print("Port {} open".format(dst_port))	
			send(IP(dst=target)/TCP(sport=src_port, dport=dst_port, flags="AR"), verbose=0)
		else:
			filtered = filtered + 1
			print("Port {} filtered".format(dst_port))	
			send(IP(dst=target)/TCP(sport=src_port, dport=dst_port, flags="AR"), verbose=0)

print("Scanned {} ports".format(open + closed + filtered))
print("{} open ports".format(open))
print("{} filtered ports".format(filtered))

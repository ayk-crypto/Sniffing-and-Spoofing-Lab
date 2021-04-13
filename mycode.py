#!/usr/bin/python
from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(filter='tcp dst port 23 and src host x.x.x.x',prn=print_pkt)

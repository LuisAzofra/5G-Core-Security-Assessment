#!/usr/bin/env python3
from scapy.all import *

dst = "my5gc-upf.open5gs.svc.cluster.local"
dst_ip = socket.gethostbyname(dst)

gtp_header = b'\x30\x00\x00\x20'  # G-PDU, no seq/npdu, TEID placeholder
teid = b'\x00\x00\x00\x00'
payload = b'MALICIOUS_DATA'

pkt = IP(dst=dst_ip)/UDP(dport=2152,sport=2152)/Raw(load=gtp_header+teid+payload)
for _ in range(10):
    send(pkt)
    time.sleep(0.1) 
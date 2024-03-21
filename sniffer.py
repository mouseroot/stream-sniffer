#Basic Packet Sniffer in Python

import socket
from struct import *

raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

 

while 1:
    try:
        packet = raw_socket.recvfrom(65565)
    except KeyboardInterrupt:
        print("Stopping Capture")
        break
    packet = packet[0]

    ethernet_length = 14
    ethernet_header = packet[:ethernet_length]
    eth = unpack('!6s6sH' , ethernet_header)
    eth_protocol = socket.ntohs(eth[2])
    print("="*8,"IP HEADER","="*8)
    print(f'Destination MAC : { packet[0:6] }  Source MAC :  { packet[6:12] } Protocol : { eth_protocol }')
    print("="*8,"TCP HEADER","="*8)
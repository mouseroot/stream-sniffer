#Basic Packet Sniffer in Python

import socket
from struct import *

raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)


while 1:
    packet = raw_socket.recvfrom(65565)
    packet = packet[0]

    ip_header = packet[0:20]

    iph = unpack("!BBHHHBBH4s4s", ip_header)

    version = iph[0]
    version = version >> 4

    header_length = version & 0xF
    header_length *= 4

    ttl = iph[5]
    protocol = iph[6]
    if protocol == 6:
        protocol = "TCP"
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);
    print(f"Version {version} - Length: {header_length} - TTL: {ttl} - PROTOCAL: {protocol} \n{s_addr} <---> {d_addr}")
#Basic Packet Sniffer in Python

import socket
from struct import *

raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a):
    a = [ord(str(x)) for x in a]
    try:
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a)
        return b
    except TypeError:
        print(f"Error Formating Address: {a}")
        input("Paused...Enter to resume!")
        return ""
        

while 1:
    packet = raw_socket.recvfrom(65565)
    packet = packet[0]

    ethernet_length = 14
    ethernet_header = packet[:ethernet_length]
    eth = unpack('!6s6sH' , ethernet_header)
    eth_protocol = socket.ntohs(eth[2])
    #print(f"Dest MAC : {packet[0:6]}")
    print(f'Destination MAC : { eth_addr(packet[0:6]) }  Source MAC :  { eth_addr(packet[6:12]) } Protocol : { str(eth_protocol) }')
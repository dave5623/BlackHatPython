import socket
import os

# interface to listen in on
host = "192.168.1.7"

if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

# capture the IP headers as well
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# configure promiscuous mode on Windows boxes
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# read a single packet and print it out
print sniffer.recvfrom(65565)

# if this is windows, turn off promiscuous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


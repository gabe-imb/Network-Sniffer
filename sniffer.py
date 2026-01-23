import ipaddress
import socket
import struct
import sys
import argparse

parser = argparse.ArgumentParser(description='Network Packet Sniffer')
parser.add_argument('--ip', help='IP address to sniff on', required=True)
opts = parser.parse_args()

class Packet:
    def __init__(self, data):
        self.packet = data
        header = struct.unpack('<BBHHHBBH4s4s', self.packet[0:20])
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3] 
        self.off = header[4]
        self.ttl = header[5]
        self.pro = header[6]
        self.num = header[7]
        self.src = header[8]
        self.dst = header[9]

        self.src_addr = ipaddress.ip_address(self.src)
        self.src_addr = ipaddress.ip_address(self.dst)

        self.protocol_map = {1: "ICMP"}

        try:
            self.protocol = self.protocol_map[self.pro]
        except Exception as e:
            print(f'{e} No protocol for {self.pro}')
            self.protocol = str(self.pro)




def sniff():
    pass

if __name__ == '__main__':
    sniff()
import ipaddress
import socket
import struct
import sys
import argparse

parser = argparse.ArgumentParser(description='Network Packet Sniffer')
parser.add_argument('--ip', help='IP address to sniff on', required=True)
opts = parser.parse_args()

class Packet:
    pass

def sniff():
    pass

if __name__ == '__main__':
    sniff()
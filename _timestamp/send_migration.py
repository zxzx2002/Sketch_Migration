#!/usr/bin/env python3
import argparse
import random
import socket

from myTunnel_header import if_control
from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "ens3f1np1" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find ens3f1np1 interface")
        exit(1)
    return iface

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="The destination IP address to use")
    args = parser.parse_args()
    addr = socket.gethostbyname(args.ip_addr)

    iface = get_if()
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / if_control() / IP(dst=addr)

    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()

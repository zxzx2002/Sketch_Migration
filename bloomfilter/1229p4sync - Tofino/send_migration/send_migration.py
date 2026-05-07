#!/usr/bin/env python3
import argparse
import random
import socket
import time

from myTunnel_header import if_control
from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "ens3f1np1" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="The destination IP address to use")
    # parser.add_argument('--switch_id', type=int, default=None, help='Current switch number,default 0')
    # parser.add_argument('--num', type=int, default=192, help='Number of packets')
    args = parser.parse_args()

    addr = socket.gethostbyname(args.ip_addr)
    # switch_id = args.switch_id
    # num = args.num
    iface = get_if()

    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /if_control(if_begin=1 )/ IP(dst=addr)

    pkt.show2()
    # hexdump(pkt)
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()

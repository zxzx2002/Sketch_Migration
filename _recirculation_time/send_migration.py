#!/usr/bin/env python3
import argparse
import random
import socket

from myTunnel_header import MyTunnel
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
    #parser.add_argument('message', type=str, help="The message to include in packet")
    # parser.add_argument('--switch_id', type=int, default=None, help='Current switch number,default 0')
    #parser.add_argument('--load', type=int, default=None, help='The number to store in the register')
    args = parser.parse_args()

    addr = socket.gethostbyname(args.ip_addr)
    # switch_id = args.switch_id
    #load = args.load
    iface = get_if()

    if (addr is not None):
        print("sending on interface {} , switch_id default=0".format(iface))
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / MyTunnel() / IP(dst=addr)
    else:
        print("sending on interface {} to IP addr {}".format(iface, str(addr)))
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        # pkt = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / args.message
        pkt = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535))

    pkt.show2()
#    hexdump(pkt)
#    print "len(pkt) = ", len(pkt)
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()

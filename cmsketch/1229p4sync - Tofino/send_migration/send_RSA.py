#发带有signature包头的测试包，配合test_RSA使用
#!/usr/bin/env python3
import argparse
import random
import socket
from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp
from myTunnel_header import MyTunnel, Signature

def get_if():
    ifs=get_if_list()
    iface=None
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
    pkt = pkt /MyTunnel( )/Signature(proto_id =1 ) / IP(dst=addr)

    pkt.show2()
#    hexdump(pkt)
#    print "len(pkt) = ", len(pkt)
    sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()

from scapy.all import *
import datetime

pcap = rdpcap('timestamp.pcap')   # 读取pcap文件
packet = pcap[2]
hexdump(packet[Raw])

sw1_ig_tstamp = packet[Raw].load[9]+packet[Raw].load[8]*16**2\
    +packet[Raw].load[7]*16**4 +packet[Raw].load[6]*16**6\
    +packet[Raw].load[5]*16**8+packet[Raw].load[4]*16**10
sw1_eg_tstamp = packet[Raw].load[15]+packet[Raw].load[14]*16**2\
    +packet[Raw].load[13]*16**4 +packet[Raw].load[12]*16**6\
    +packet[Raw].load[11]*16**8+packet[Raw].load[10]*16**10
sw2_ig_tstamp = packet[Raw].load[21]+packet[Raw].load[20]*16**2\
    +packet[Raw].load[19]*16**4 +packet[Raw].load[18]*16**6\
    +packet[Raw].load[17]*16**8+packet[Raw].load[16]*16**10
sw2_eg_tstamp = packet[Raw].load[27]+packet[Raw].load[26]*16**2\
    +packet[Raw].load[25]*16**4 +packet[Raw].load[24]*16**6\
    +packet[Raw].load[23]*16**8+packet[Raw].load[22]*16**10

print(sw1_ig_tstamp)
print(sw1_eg_tstamp)
print(sw2_ig_tstamp)
print(sw2_eg_tstamp)
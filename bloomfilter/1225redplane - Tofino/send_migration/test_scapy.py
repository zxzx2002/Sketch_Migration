from scapy.all import *
from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp
import time

TYPE_MYTUNNEL = 0x1212
TYPE_IF_CONTROL = 0x3637
TYPE_IPV4 = 0x0800

output_file = "captured_packets.txt"
switch_id_list = []
load_sketch_list = []
register_id_list = []
read_place_id_list = []
if_finish_list = []
ig_timestamp = [0]
eg_timestamp = [0]
start = 0
middle = 0
end = 0

def get_load_sketch(packet):
    if(Ether in packet ):
        try:
            global start
            start = time.time_ns()
            hexdump(packet[Raw])
            switch_id_list.append(packet[Raw].load[5])
            load_sketch_list.append(packet[Raw].load[13] + \
                                    packet[Raw].load[12] * (16 ** 2) + \
                                    packet[Raw].load[11] * (16 ** 3) + \
                                    packet[Raw].load[10] * (16 ** 4))
            register_id_list.append(packet[Raw].load[15])
            read_place_id_list.append(packet[Raw].load[19] + \
                                      packet[Raw].load[18] * (16 ** 2))
            if_finish_list.append(packet[Raw].load[21])
            ig_timestamp.append(packet[Raw].load[27] + \
                                    packet[Raw].load[26] * (16 ** 2) + \
                                    packet[Raw].load[25] * (16 ** 3) + \
                                    packet[Raw].load[24] * (16 ** 4)+ \
                                    packet[Raw].load[23] * (16 ** 5) + \
                                    packet[Raw].load[22] * (16 ** 6))
            eg_timestamp.append(packet[Raw].load[33] + \
                                    packet[Raw].load[32] * (16 ** 2) + \
                                    packet[Raw].load[31] * (16 ** 3) + \
                                    packet[Raw].load[30] * (16 ** 4)+ \
                                    packet[Raw].load[29] * (16 ** 5) + \
                                    packet[Raw].load[28] * (16 ** 6))
            print(eg_timestamp[-1] - ig_timestamp[-1])
            print("switch_id=", switch_id_list[-1], "\nload_sketch = ", load_sketch_list[-1], "\nregister_id = ", register_id_list[-1],
                  "\nread_place_id = ", read_place_id_list[-1], "\nif_finish = ", if_finish_list[-1],"\nig_timestamp = ", ig_timestamp[-1],
                  "\neg_timestamp = ", eg_timestamp[-1])
            with open(output_file, "a") as f:
                f.write(f"{switch_id_list[-1]} {load_sketch_list[-1]} {register_id_list[-1]} {read_place_id_list[-1]} {if_finish_list[-1]} {ig_timestamp[-1]} {eg_timestamp[-1]}\n")
            # # 全收到之后，才把数据构造数据包发出去
            # if (if_finish_list[-1] == 1):
            # if (read_place_id_list[-1] >= 120):
            #     send_packet(switch_id_list, load_sketch_list, register_id_list, read_place_id_list, if_finish_list, ig_timestamp, eg_timestamp)
        except:
            print("******** Stop ********")

def send_packet(switch_id, load_sketch, register_id, read_place_id, if_finish, ig_timestamp, eg_timestamp):
    iface = "ens3f1np1"
    addr = socket.gethostbyname('10.0.0.2')

    for i in range(len(switch_id)):
        switch_id_value = 1#0=switch0,1=switch1
        load_sketch_value = load_sketch[i]
        register_id_value = register_id[i]
        read_place_id_value = read_place_id[i]
        if_finish_value = if_finish[i]
        ig_timestamp_value = ig_timestamp[i]
        eg_timestamp_value = eg_timestamp[i]
        # print("switch_id=", switch_id_value, "\nload_sketch = ", load_sketch_value, "\nregister_id = ", register_id_value,
        #       "\nread_place_id = ", read_place_id_value, "\nif_finish = ", if_finish_value)
        from myTunnel_header import MyTunnel
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / MyTunnel(switch_id=switch_id_value, load_sketch = load_sketch_value, register_id = register_id_value,
                             read_place_id =  read_place_id_value, if_finish = if_finish_value, ig_tstamp_sw0 = ig_timestamp_value,
                             eg_tstamp_sw0 = eg_timestamp_value) / IP(dst=addr)
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    with open(output_file, "w") as f:  #clear the file
        f.write("")
    sniff( prn=get_load_sketch, count=100, iface = "ens3f0np0")
    middle = time.time_ns()
    send_packet(switch_id_list, load_sketch_list, register_id_list, read_place_id_list, if_finish_list, ig_timestamp,
                eg_timestamp)
    end = time.time_ns()
    print("start =",start, "\nmiddle = ",middle, "\nend =",end)
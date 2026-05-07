from scapy.all import *

TYPE_MYTUNNEL = 0x1212
TYPE_IF_CONTROL = 0x3637
TYPE_IPV4 = 0x0800

class MyTunnel(Packet):
    name = "MyTunnel"
    fields_desc = [
        ShortField("pid", 0),#ShortField is 16bit
        IntField("switch_id", 0),#IntField is 32bit
        LongField("load_sketch", 0),
        ShortField("register_id", 0),
        IntField("read_place_id", 0),
        ShortField("if_finish", 0),

        BitField("ig_tstamp_sw0", 0, 48),
        BitField("eg_tstamp_sw0", 0, 48),
        BitField("ig_tstamp_sw1", 0, 48),
        BitField("eg_tstamp_sw1", 0, 48),
    ]

bind_layers(Ether, MyTunnel, type=TYPE_MYTUNNEL)
bind_layers(MyTunnel, IP, pid=TYPE_IPV4)


from scapy.all import *

TYPE_MYTUNNEL = 0x1212
TYPE_IF_CONTROL = 0x1214
TYPE_SIGN = 0x3637
TYPE_IPV4 = 0x0800

class MyTunnel(Packet):
    name = "MyTunnel"
    fields_desc = [
        ShortField("pid", 0),#ShortField is 16bit
        ShortField("switch_id", 0),
        LongField("load_sketch", 12),
        ShortField("register_id", 0),
        IntField("read_place_id", 32),
        ShortField("if_finish", 0),
        LongField("siphash",0),
        BitField("ig_tstamp",0, 48),
        BitField("eg_tstamp",0, 48),
    ]
bind_layers(Ether, MyTunnel, type=TYPE_MYTUNNEL)
bind_layers(MyTunnel, IP, pid=TYPE_IPV4)

class if_control(Packet):
    name = "if_control"
    fields_desc = [
        ShortField("pid", 0),#ShortField is 16bit
        ShortField("if_begin", 1),
    ]
bind_layers(Ether,if_control, type=TYPE_IF_CONTROL)
bind_layers(if_control, IP, pid=TYPE_IPV4)

class Signature(Packet):
    name = "Signature"
    fields_desc = [ShortField("proto_id", 0),
        BitField("sign", 0, 1024)]
bind_layers(Ether, MyTunnel, type=TYPE_MYTUNNEL)
bind_layers(MyTunnel, Signature, pid=TYPE_SIGN)
bind_layers(Signature, IP, proto_id = TYPE_IPV4)



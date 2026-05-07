from scapy.all import *

TYPE_IF_CONTROL = 0x1212
TYPE_IPV4 = 0x0800

class if_control(Packet):
    name = "if_control"
    fields_desc = [
        ShortField("proto_id", 0),#ShortField is 16bit
        ShortField("switch_id", 0),
        BitField("sw1_ig_tstamp", 0, 48),
        BitField("sw1_eg_tstamp", 0, 48),
        BitField("sw2_ig_tstamp", 0, 48),
        BitField("sw2_eg_tstamp", 0, 48),
    ]
    def mysummary(self):
        return self.sprintf("pid=%pid%, switch_id=%switch_id%")


bind_layers(Ether,if_control, type=TYPE_IF_CONTROL)
bind_layers(if_control, IP, proto_id=TYPE_IPV4)
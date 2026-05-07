from scapy.all import *

TYPE_MYTUNNEL = 0x1212
TYPE_IPV4 = 0x0800

class MyTunnel(Packet):
    name = "MyTunnel"
    fields_desc = [
        ShortField("pid", 0),#ShortField is 16bit
        BitField("ig_tstamp", 0, 48),
        BitField("eg_tstamp", 0, 48),
        BitField("ig_tstamp_1", 0, 48),
        BitField("eg_tstamp_1", 0, 48),
    ]
    def mysummary(self):
        return self.sprintf("pid=%pid%, switch_id=%switch_id%, load=%load%, register_id=%register_id%, read_place_id=%read_place_id%, if_finish=%if_finish%")


bind_layers(Ether, MyTunnel, type=TYPE_MYTUNNEL)
bind_layers(MyTunnel, IP, pid=TYPE_IPV4)




from scapy.all import *

TYPE_MYTUNNEL = 0x1212
TYPE_IPV4 = 0x0800

class MyTunnel(Packet):
    name = "MyTunnel"
    fields_desc = [
        ShortField("pid", 0),#ShortField is 16bit
        IntField("switch_id", 0),#IntField is 32bit
        LongField("load_mvsketch_lo", 0),
        LongField("load_mvsketch_hi", 0),
        LongField("load_subkey1_lo", 0),
        LongField("load_subkey1_hi", 0),
        LongField("load_subkey2_lo", 0),
        LongField("load_subkey2_hi", 0),
        #ShortField("if_ingress", 0),
        IntField("read_place_id", 0),
        ShortField("if_finish", 0),
        BitField("ig_tstamp", 0, 48),
        BitField("eg_tstamp", 0, 48),
    ]
    def mysummary(self):
        return self.sprintf("pid=%pid%, switch_id=%switch_id%, load=%load%, register_id=%register_id%, read_place_id=%read_place_id%, if_finish=%if_finish%")


bind_layers(Ether, MyTunnel, type=TYPE_MYTUNNEL)
bind_layers(MyTunnel, IP, pid=TYPE_IPV4)


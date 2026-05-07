from scapy.all import *

#TYPE_MYTUNNEL = 0x1212
TYPE_IF_CONTROL = 0x3637
TYPE_IPV4 = 0x0800

class if_control(Packet):
    name = "if_control"
    fields_desc = [
        ShortField("pid", 0),#ShortField is 16bit
        IntField("switch_id", 0),#IntField is 32bit
        ShortField("if_begin", 0)
    ]
    def mysummary(self):
        return self.sprintf("pid=%pid%, switch_id=%switch_id%, if_begin=%if_begin%")


bind_layers(Ether,if_control, type=TYPE_IF_CONTROL)
bind_layers(if_control, IP, pid=TYPE_IPV4)
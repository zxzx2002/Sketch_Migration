/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/
typedef bit<4> mirror_type_t;
const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;

//这一段TofinoIngressParser不知道干什么的，但加上才能解析后面的字段
parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

//这里开始是解析过程
parser MyIngressParser(packet_in packet,
                out headers hdr,
		        out metadata meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;//固定写法

    state start {
        tofino_parser.apply(packet, ig_intr_md);//固定写法
        transition parse_ethernet ;
    }

     state parse_ethernet {
	packet.extract(hdr.mirror);
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_MYTUNNEL: parse_myTunnel;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_myTunnel {
        packet.extract(hdr.myTunnel);
        transition select(hdr.myTunnel.proto_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6 : parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
control MyIngressDeparser(
        packet_out packet,
        inout headers hdr,
        in metadata meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    //Mirror() mirror;
    apply {
        //if (ig_dprsr_md.mirror_type == MIRROR_TYPE_I2E) {
        //    mirror.emit<mirror_t>(meta.sid, {meta.pkt_type});
        //}
        packet.emit(hdr.mirror);
	packet.emit(hdr.ethernet);
        packet.emit(hdr.myTunnel);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/
parser MyEgressParser(
        packet_in packet,
	    out headers hdr,
	    out metadata meta,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        packet.extract(eg_intr_md);
        //transition parse_mirror;
        transition parse_ethernet;
    }
    /*
    state parse_mirror {
        mirror_t mirror_md = packet.lookahead<mirror_t>();
        transition select(mirror_md.pkt_type) {
            1 : parse_mirror_md;
            default : parse_ethernet;
        }
    }

    state parse_mirror_md {
        packet.extract(hdr.mirror);
        transition parse_ethernet;
    }
    */

    state parse_ethernet {
	packet.extract(hdr.mirror);
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_MYTUNNEL: parse_myTunnel;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_myTunnel {
        packet.extract(hdr.myTunnel);
        transition select(hdr.myTunnel.proto_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6 : parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
control MyEgressDeparser(
        packet_out packet,
        inout headers hdr,
        in metadata meta,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    apply {
        packet.emit(hdr.mirror);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.myTunnel);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

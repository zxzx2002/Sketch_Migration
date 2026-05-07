#include <core.p4>
#include <t2na.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 64//64个位置
#define SKETCH_CELL_BIT_WIDTH 64//每个位置64bit

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    #define BLOOM_FILTER_REGISTER(num) Register<bit<SKETCH_CELL_BIT_WIDTH>, bit<32>>(SKETCH_BUCKET_LENGTH) bloomfilter##num;\
    RegisterAction<bit<64>, bit<32>, bit<64>>(bloomfilter##num) \
        action_bloomfilter##num = {\
            void apply(inout bit<64> value_bloomfilter##num, out bit<64> read_value_bloomfilter##num) {\
                read_value_bloomfilter##num = 0;\
                value_bloomfilter##num = 1;\
                read_value_bloomfilter##num = value_bloomfilter##num;\
            }};\
    RegisterAction<bit<64>, bit<32>, bit<64>>(bloomfilter##num) \
        action_read_bloomfilter##num = {\
            void apply(inout bit<64> value_bloomfilter##num, out bit<64> read_value_bloomfilter##num) {\
                read_value_bloomfilter##num = value_bloomfilter##num;\
            }};\
    RegisterAction<bit<64>, bit<32>, bit<64>>(bloomfilter##num) \
        action_renew_bloomfilter##num = {\
            void apply(inout bit<64> value_bloomfilter##num, out bit<64> read_value_bloomfilter##num) {\
                value_bloomfilter##num = hdr.myTunnel.load_sketch;\
                read_value_bloomfilter##num = value_bloomfilter##num;\
            }};\

    BLOOM_FILTER_REGISTER(0)
    BLOOM_FILTER_REGISTER(1)
    BLOOM_FILTER_REGISTER(2)

    CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
                           true,          // reversed
                           false,         // use msb?
                           false,         // extended?
                           32w0xFFFFFFFF, // initial shift register value
                           32w0xFFFFFFFF  // result xor
                           ) poly0;
    CRCPolynomial<bit<32>>(32w0xEDB88320, // polynomial
                           true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly1;
    CRCPolynomial<bit<32>>(32w0xDB710641, // polynomial
                           true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly2;

    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly0) myhash0;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) myhash1;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly2) myhash2;

    action check_bloomfilter0() {
        meta.index_sketch0 = (myhash0.get({ hdr.ipv4.srcAddr }))&0x003f; //hash.get is different from cm_sketch
    }
    action check_bloomfilter1() {
        meta.index_sketch1 = (myhash1.get({ hdr.ipv4.srcAddr }))&0x003f;
    }
    action check_bloomfilter2() {
        meta.index_sketch2 = (myhash2.get({ hdr.ipv4.srcAddr }))&0x003f;
    }

    table tbl_bloomfilter0 {
        actions = {check_bloomfilter0;}
        size = 64;
        const default_action = check_bloomfilter0();
    }
    table tbl_bloomfilter1 {
        actions = {check_bloomfilter1;}
        size = 64;
        const default_action = check_bloomfilter1();
    }
    table tbl_bloomfilter2 {
        actions = {check_bloomfilter2;}
        size = 64;
        const default_action = check_bloomfilter2();
    }

/*************************************************************************
**************  M Y  C O N T R O L  P R O G R A M  *******************
*************************************************************************/
    action add_header(){
        hdr.myTunnel.setValid();
        hdr.myTunnel.proto_id = TYPE_IPV4;
	    hdr.ethernet.etherType = TYPE_MYTUNNEL;
        //注意添加包头之后，解析顺序要与parser.p4一致
    }

    action drop(){
		ig_dprsr_md.drop_ctl = 0x1;
	}

    action set_egress_port(bit<9> egress_port){
        ig_tm_md.ucast_egress_port = egress_port;
    }

    table forwarding {
        key = {ig_intr_md.ingress_port: exact;}
        actions = {set_egress_port; drop; NoAction;}
        size = 64;
        default_action = drop;
    }

    apply {
        tbl_bloomfilter0.apply();
        tbl_bloomfilter1.apply();
        tbl_bloomfilter2.apply();
        action_bloomfilter0.execute(meta.index_sketch0);
        action_bloomfilter1.execute(meta.index_sketch1);
        action_bloomfilter2.execute(meta.index_sketch2);
        add_header();
        hdr.myTunnel.ig_tstamp = ig_prsr_md.global_tstamp;
        forwarding.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyEgress(inout headers hdr,
	inout metadata meta,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
	inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
	inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md){
	apply{
	    hdr.myTunnel.eg_tstamp = eg_intr_md_from_prsr.global_tstamp;
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(MyIngressParser(),
         MyIngress(),
         MyIngressDeparser(),
         MyEgressParser(),
         MyEgress(),
         MyEgressDeparser()) pipe;
Switch(pipe) main;
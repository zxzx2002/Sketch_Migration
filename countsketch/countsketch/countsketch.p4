#include <core.p4>
#include <t2na.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 64//64位置
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

    #define COUNT_SKETCH_REGISTER(num) Register<bit<SKETCH_CELL_BIT_WIDTH>, bit<32>>(SKETCH_BUCKET_LENGTH) count_sketch##num;\
    RegisterAction<bit<64>, bit<32>, bit<64>>(count_sketch##num) \
        action_count_sketch##num = {\
            void apply(inout bit<64> value_count_sketch##num, out bit<64> read_value_count_sketch##num) {\
                bit<64> in_value = value_count_sketch##num;\
                if(meta.count_sketch_flag == 0)\
                    value_count_sketch##num = in_value + 1;\
                else if(!(meta.count_sketch_flag == 0))\
                    value_count_sketch##num = in_value - 1;\
                read_value_count_sketch##num = value_count_sketch##num;\
            }};\
    RegisterAction<bit<64>, bit<32>, bit<64>>(count_sketch##num) \
        action_read_count_sketch##num = {\
            void apply(inout bit<64> value_count_sketch##num, out bit<64> read_value_count_sketch##num) {\
                read_value_count_sketch##num = value_count_sketch##num;\
            }};\
    RegisterAction<bit<64>, bit<32>, bit<64>>(count_sketch##num) \
        action_renew_count_sketch##num = {\
            void apply(inout bit<64> value_count_sketch##num, out bit<64> read_value_count_sketch##num) {\
                value_count_sketch##num = hdr.myTunnel.load_sketch;\
                read_value_count_sketch##num = value_count_sketch##num;\
            }};\

    COUNT_SKETCH_REGISTER(0)
    COUNT_SKETCH_REGISTER(1)
    COUNT_SKETCH_REGISTER(2)

    CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
                           true,          // reversed
                           false,         // use msb?
                           true,         // extended?
                           32w0, // initial shift register value
                           32w0  // result xor
                           ) poly0;
    CRCPolynomial<bit<32>>(32w0xEDB88320, // polynomial
                           true, false, true, 32w0, 32w0) poly1;
    CRCPolynomial<bit<32>>(32w0xDB710641, // polynomial
                           true, false, true, 32w0, 32w0) poly2;
   CRCPolynomial<bit<16>>(16w7, false, false, true, 16w0, 16w0) poly_init;

    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly0) myhash0;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) myhash1;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly2) myhash2;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_init) hash_init;

    action check_count_sketch0() {
        meta.index_sketch0 = (myhash0.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0x003f; //hash.get is different from cm_sketch
    }
    action check_count_sketch1() {
        meta.index_sketch1 = (myhash1.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0x003f;
    }
    action check_count_sketch2() {
        meta.index_sketch2 = (myhash2.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0x003f;
    }
    action do_init() {
        meta.count_sketch_flag = hash_init.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr })&0x0001;
    }

    table tbl_count_sketch0 {
        actions = {check_count_sketch0;}
        size = 64;
        const default_action = check_count_sketch0();
    }
    table tbl_count_sketch1 {
        actions = {check_count_sketch1;}
        size = 64;
        const default_action = check_count_sketch1();
    }
    table tbl_count_sketch2 {
        actions = {check_count_sketch2;}
        size = 64;
        const default_action = check_count_sketch2();
    }
    table tbl_do_init{
        actions = {do_init;}
        size = 1;
        const default_action = do_init();
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
        tbl_do_init.apply();
        tbl_count_sketch0.apply();
        tbl_count_sketch1.apply();
        tbl_count_sketch2.apply();
        action_count_sketch0.execute(meta.index_sketch0);
        action_count_sketch1.execute(meta.index_sketch1);
        action_count_sketch2.execute(meta.index_sketch2);
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
#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 46500
#define SKETCH_CELL_BIT_WIDTH 64

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
        forwarding.apply();
    }
}

/*************************************************************************
**************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyEgress(
        inout headers hdr,
        inout metadata meta,
        in    egress_intrinsic_metadata_t   eg_intr_md,
        in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    #define SKETCH_REGISTER(num) Register<bit<SKETCH_CELL_BIT_WIDTH>, bit<32>>(SKETCH_BUCKET_LENGTH) sketch##num;\
        RegisterAction<bit<64>, bit<32>, bit<64>> (sketch##num)\
            action_sketch##num = {\
                void apply(inout bit<64> value_sketch##num, out bit<64> read_value_sketch##num) {\
                    bit<64> tmp_sketch = value_sketch##num + 1;\
                    value_sketch##num = tmp_sketch;\
                    read_value_sketch##num = tmp_sketch;\
                }};\
        RegisterAction<bit<64>, bit<32>, bit<64>> (sketch##num)\
            action_read_sketch##num = {\
                void apply(inout bit<64> value_read_sketch##num, out bit<64> read_value_read_sketch##num) {\
                    read_value_read_sketch##num = value_read_sketch##num;\
                }};\
        RegisterAction<bit<64>, bit<32>, bit<64>> (sketch##num)\
            action_renew_sketch##num = {\
                void apply(inout bit<64> value_renew_sketch##num, out bit<64> read_value_renew_sketch##num) {\
                    bit<64>tmp_renew = value_renew_sketch##num + hdr.myTunnel.load_sketch##num;\
                    value_renew_sketch##num = tmp_renew;\
                    read_value_renew_sketch##num = tmp_renew;\
                }\
        };

    SKETCH_REGISTER(0)
    SKETCH_REGISTER(1)
    SKETCH_REGISTER(2)

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

    action sketch0_count(){
        meta.index_sketch0 = (myhash0.get({
            hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}))&0x0fff;
    }
    action sketch1_count(){
        meta.index_sketch1 = (myhash1.get({
            hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}))&0x0fff;
    }
    action sketch2_count(){
        meta.index_sketch2 = (myhash2.get({
            hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}))&0x0fff;
    }

    table tbl_myhash0 {
        actions = {sketch0_count;}
        size = 64;
        const default_action = sketch0_count();
    }
    table tbl_myhash1 {
        actions = {sketch1_count;}
        size = 64;
        const default_action = sketch1_count();
    }
    table tbl_myhash2 {
        actions = {sketch2_count;}
        size = 64;
        const default_action = sketch2_count();
    }

    action del_mirror_hdr(){
        hdr.mirror.setInvalid();
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid() && !hdr.myTunnel.isValid()){
            tbl_myhash0.apply();
            tbl_myhash1.apply();
            tbl_myhash2.apply();
            action_sketch0.execute(meta.index_sketch0);
            action_sketch1.execute(meta.index_sketch1);
            action_sketch2.execute(meta.index_sketch2);
        }

        if(hdr.myTunnel.isValid()){
            if(hdr.myTunnel.if_finish==0){
                if(hdr.myTunnel.switch_id==0){
                    hdr.myTunnel.load_sketch0 = action_read_sketch0.execute(hdr.myTunnel.read_place_id);
                    hdr.myTunnel.load_sketch1 = action_read_sketch1.execute(hdr.myTunnel.read_place_id);
                    hdr.myTunnel.load_sketch2 = action_read_sketch2.execute(hdr.myTunnel.read_place_id);
                    hdr.myTunnel.switch_id = 1;         //set flag and send to switch1
                }else{
                    action_renew_sketch0.execute(hdr.myTunnel.read_place_id);
                    action_renew_sketch1.execute(hdr.myTunnel.read_place_id);
                    action_renew_sketch2.execute(hdr.myTunnel.read_place_id);
                }
            }
        }
        hdr.myTunnel.eg_tstamp = eg_prsr_md.global_tstamp;
        del_mirror_hdr();
    }
}

Pipeline(MyIngressParser(),
         MyIngress(),
         MyIngressDeparser(),
         MyEgressParser(),
         MyEgress(),
         MyEgressDeparser()) pipe;
Switch(pipe) main;

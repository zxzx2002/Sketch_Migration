#include <core.p4>
#include <t2na.p4>

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

    #define SKETCH_LEARN_REGISTER(num) \
        Register<bit<64>, bit<32>>(SKETCH_BUCKET_LENGTH) sketch_learn##num;\
        RegisterAction<bit<64>, bit<32>, bit<64>>(sketch_learn##num) \
            reg_sketch_learn##num = {\
                void apply(inout bit<64> value) {\
                    bit<64> in_value = value;    value = in_value + 1;\
            }};\
        RegisterAction<bit<64>, bit<32>, bit<64>> (sketch_learn##num)\
            action_read_sketch##num = {\
                void apply(inout bit<64> value_read_sketch##num, out bit<64> read_value_read_sketch##num) {\
                    read_value_read_sketch##num = value_read_sketch##num;\
                }};\
        RegisterAction<bit<64>, bit<32>, bit<64>> (sketch_learn##num)\
            action_renew_sketch##num = {\
                void apply(inout bit<64> value_renew_sketch##num, out bit<64> read_value_renew_sketch##num) {\
                    value_renew_sketch##num = hdr.myTunnel.load_sketch##num;\
                    read_value_renew_sketch##num = value_renew_sketch##num;\
                }};\
        action set_sketch##num() {\
            reg_sketch_learn##num.execute(meta.index);\
        }\
        table tbl_set_sketch##num {\
                actions = {set_sketch##num;}  size = 64;\
                const default_action = set_sketch##num();\
        }

    SKETCH_LEARN_REGISTER(0)
    SKETCH_LEARN_REGISTER(1)
    SKETCH_LEARN_REGISTER(2)

    CRCPolynomial<bit<32>>(
        32w0x04C11DB7, true,  false,  true,  32w0xFFFFFFFF, 32w0xFFFFFFFF) poly0;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly0) myhash;

    action execute_hash() {
        meta.index = (myhash.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0xffff;
    }
    action modify_flag_1() {
        meta.flag1 = (bit<1>)(hdr.ipv4.dstAddr >> 1)&0x0001;
        meta.flag2 = (bit<1>)(hdr.ipv4.dstAddr >> 2)&0x0001;
    }

    table tbl_execute_hash {
        actions = {execute_hash;}
        size = 32;
        const default_action = execute_hash();
    }
    table modify_flag1 {
        actions = {modify_flag_1;}
        size = 1;
        const default_action = modify_flag_1();
    }

    action del_mirror_hdr(){
        hdr.mirror.setInvalid();
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid() && !hdr.myTunnel.isValid()){
            tbl_execute_hash.apply();
            tbl_set_sketch0.apply();

            modify_flag1.apply();
            if (meta.flag1 == 1)  tbl_set_sketch1.apply();
            if (meta.flag2 == 1)  tbl_set_sketch2.apply();
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

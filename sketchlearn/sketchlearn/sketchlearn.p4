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

    #define SKETCH_LEARN_REGISTER(num) \
        Register<bit<SKETCH_CELL_BIT_WIDTH>, bit<32>>(SKETCH_BUCKET_LENGTH) sketch_learn##num;\
        RegisterAction<bit<64>, bit<32>, bit<64>>(sketch_learn##num) reg_sketch_learn##num = {\
            void apply(inout bit<64> value) {bit<64> in_value = value;    value = in_value + 1;}};\
        action set_sketch##num() {reg_sketch_learn##num.execute(meta.index);}\
        table tbl_set_sketch##num {\
            actions = {set_sketch##num;}  size = 64;\
            const default_action = set_sketch##num();\
        }

    SKETCH_LEARN_REGISTER(0)

    SKETCH_LEARN_REGISTER(1)
    SKETCH_LEARN_REGISTER(2)
    /*SKETCH_LEARN_REGISTER(3)
    SKETCH_LEARN_REGISTER(4)
    SKETCH_LEARN_REGISTER(5)
    SKETCH_LEARN_REGISTER(6)
    SKETCH_LEARN_REGISTER(7)
    SKETCH_LEARN_REGISTER(8)
    SKETCH_LEARN_REGISTER(9)
    SKETCH_LEARN_REGISTER(10)
    SKETCH_LEARN_REGISTER(11)
    SKETCH_LEARN_REGISTER(12)
    SKETCH_LEARN_REGISTER(13)
    SKETCH_LEARN_REGISTER(14)
    SKETCH_LEARN_REGISTER(15)
    SKETCH_LEARN_REGISTER(16)
    SKETCH_LEARN_REGISTER(17)
    SKETCH_LEARN_REGISTER(18)
    SKETCH_LEARN_REGISTER(19)
    SKETCH_LEARN_REGISTER(20)
    SKETCH_LEARN_REGISTER(21)
    SKETCH_LEARN_REGISTER(22)
    SKETCH_LEARN_REGISTER(23)
    SKETCH_LEARN_REGISTER(24)
    SKETCH_LEARN_REGISTER(25)
    SKETCH_LEARN_REGISTER(26)
    SKETCH_LEARN_REGISTER(27)
    SKETCH_LEARN_REGISTER(28)
    SKETCH_LEARN_REGISTER(29)
    SKETCH_LEARN_REGISTER(30)
    SKETCH_LEARN_REGISTER(31)
    //SKETCH_LEARN_REGISTER(32)*/

    CRCPolynomial<bit<32>>(32w0x04C11DB7, true,  false,  true,  32w0xFFFFFFFF, 32w0xFFFFFFFF) poly0;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly0) myhash;

    action execute_hash() {
        meta.index = (myhash.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0x003f;
    }

    action modify_flag_1() {
        meta.flag1 = (bit<1>)(hdr.ipv4.srcAddr >> 1)&0x0001;
        meta.flag2 = (bit<1>)(hdr.ipv4.srcAddr >> 2)&0x0001;
        /*meta.flag3 = (bit<1>)(hdr.ipv4.srcAddr >> 3)&0x0001;
        meta.flag4 = (bit<1>)(hdr.ipv4.srcAddr >> 4)&0x0001;
        meta.flag5 = (bit<1>)(hdr.ipv4.srcAddr >> 5)&0x0001;
        meta.flag6 = (bit<1>)(hdr.ipv4.srcAddr >> 6)&0x0001;
        meta.flag7 = (bit<1>)(hdr.ipv4.srcAddr >> 7)&0x0001;
        meta.flag8 = (bit<1>)(hdr.ipv4.srcAddr >> 8)&0x0001;*/
    }
    /*action modify_flag_2() {
        meta.flag1 = (bit<1>)(hdr.ipv4.srcAddr >> 9)&0x0001;
        meta.flag2 = (bit<1>)(hdr.ipv4.srcAddr >> 10)&0x0001;
        meta.flag3 = (bit<1>)(hdr.ipv4.srcAddr >> 11)&0x0001;
        meta.flag4 = (bit<1>)(hdr.ipv4.srcAddr >> 12)&0x0001;
        meta.flag5 = (bit<1>)(hdr.ipv4.srcAddr >> 13)&0x0001;
        meta.flag6 = (bit<1>)(hdr.ipv4.srcAddr >> 14)&0x0001;
        meta.flag7 = (bit<1>)(hdr.ipv4.srcAddr >> 15)&0x0001;
        meta.flag8 = (bit<1>)(hdr.ipv4.srcAddr >> 16)&0x0001;
    }
    action modify_flag_3() {
        meta.flag1 = (bit<1>)(hdr.ipv4.srcAddr >> 17)&0x0001;
        meta.flag2 = (bit<1>)(hdr.ipv4.srcAddr >> 18)&0x0001;
        meta.flag3 = (bit<1>)(hdr.ipv4.srcAddr >> 19)&0x0001;
        meta.flag4 = (bit<1>)(hdr.ipv4.srcAddr >> 20)&0x0001;
        meta.flag5 = (bit<1>)(hdr.ipv4.srcAddr >> 21)&0x0001;
        meta.flag6 = (bit<1>)(hdr.ipv4.srcAddr >> 22)&0x0001;
        meta.flag7 = (bit<1>)(hdr.ipv4.srcAddr >> 23)&0x0001;
        meta.flag8 = (bit<1>)(hdr.ipv4.srcAddr >> 24)&0x0001;
    }
    action modify_flag_4() {
        meta.flag1 = (bit<1>)(hdr.ipv4.srcAddr >> 25)&0x0001;
        meta.flag2 = (bit<1>)(hdr.ipv4.srcAddr >> 26)&0x0001;
        meta.flag3 = (bit<1>)(hdr.ipv4.srcAddr >> 27)&0x0001;
        meta.flag4 = (bit<1>)(hdr.ipv4.srcAddr >> 28)&0x0001;
        meta.flag5 = (bit<1>)(hdr.ipv4.srcAddr >> 29)&0x0001;
        meta.flag6 = (bit<1>)(hdr.ipv4.srcAddr >> 30)&0x0001;
        meta.flag7 = (bit<1>)(hdr.ipv4.srcAddr >> 31)&0x0001;
        //meta.flag8 = (bit<1>)(hdr.ipv4.srcAddr >> 32)&0x0001;
    }*/

    table tbl_execute_hash {actions = {execute_hash;}  size = 32; const default_action = execute_hash();}
    table modify_flag1 {actions = {modify_flag_1;}  size = 1; const default_action = modify_flag_1();}
    //table modify_flag2 {actions = {modify_flag_2;}  size = 1; const default_action = modify_flag_2();}
    //table modify_flag3 {actions = {modify_flag_3;}  size = 1; const default_action = modify_flag_3();}
    //table modify_flag4 {actions = {modify_flag_4;}  size = 1; const default_action = modify_flag_4();}

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
        tbl_execute_hash.apply();
        tbl_set_sketch0.apply();

        modify_flag1.apply();
        if (meta.flag1 == 1)  tbl_set_sketch1.apply();
        if (meta.flag2 == 1)  tbl_set_sketch2.apply();
        /*if (meta.flag3 == 1)  tbl_set_sketch3.apply();
        if (meta.flag4 == 1)  tbl_set_sketch4.apply();
        if (meta.flag5 == 1)  tbl_set_sketch5.apply();
        if (meta.flag6 == 1)  tbl_set_sketch6.apply();
        if (meta.flag7 == 1)  tbl_set_sketch7.apply();
        if (meta.flag8 == 1)  tbl_set_sketch8.apply();

        modify_flag2.apply();
        if (meta.flag1 == 1)  tbl_set_sketch9.apply();
        if (meta.flag2 == 1)  tbl_set_sketch10.apply();
        if (meta.flag3 == 1)  tbl_set_sketch11.apply();
        if (meta.flag4 == 1)  tbl_set_sketch12.apply();
        if (meta.flag5 == 1)  tbl_set_sketch13.apply();
        if (meta.flag6 == 1)  tbl_set_sketch14.apply();
        if (meta.flag7 == 1)  tbl_set_sketch15.apply();
        if (meta.flag8 == 1)  tbl_set_sketch16.apply();

        modify_flag3.apply();
        if (meta.flag1 == 1)  tbl_set_sketch17.apply();
        if (meta.flag2 == 1)  tbl_set_sketch18.apply();
        if (meta.flag3 == 1)  tbl_set_sketch19.apply();
        if (meta.flag4 == 1)  tbl_set_sketch20.apply();
        if (meta.flag5 == 1)  tbl_set_sketch21.apply();
        if (meta.flag6 == 1)  tbl_set_sketch22.apply();
        if (meta.flag7 == 1)  tbl_set_sketch23.apply();
        if (meta.flag8 == 1)  tbl_set_sketch24.apply();

        modify_flag4.apply();
        if (meta.flag1 == 1)  tbl_set_sketch25.apply();
        if (meta.flag2 == 1)  tbl_set_sketch26.apply();
        if (meta.flag3 == 1)  tbl_set_sketch27.apply();
        if (meta.flag4 == 1)  tbl_set_sketch28.apply();
        if (meta.flag5 == 1)  tbl_set_sketch29.apply();
        if (meta.flag6 == 1)  tbl_set_sketch30.apply();
        if (meta.flag7 == 1)  tbl_set_sketch31.apply();
        //if (meta.flag8 == 1)  tbl_set_sketch32.apply();
*/
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


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

    Register<bit<32>,bit<32>>(1) read_place_id;
    RegisterAction<bit<32>, bit<32>, bit<32>> (read_place_id)
        read_place_id_action = {
            void apply(inout bit<32> read_place_id_value, out bit<32> read_place_id_read_value) {
                read_place_id_read_value=read_place_id_value;
                bit<32>tmp32 = read_place_id_value+1;
                read_place_id_value = tmp32;
            }
    };

    Register<bit<16>,bit<16>>(1) if_begin;
    RegisterAction<bit<16>, bit<16>, bit<16>> (if_begin)
        begin_action = {
            void apply(inout bit<16> begin_value, out bit<16> read_begin_value) {
                begin_value = 1;
                read_begin_value = begin_value;
            }};
    RegisterAction<bit<16>, bit<16>, bit<16>> (if_begin)
        stop_action = {
            void apply(inout bit<16> stop_value, out bit<16> read_stop_value) {
                stop_value = 0;
                read_stop_value = stop_value;
            }};
    RegisterAction<bit<16>, bit<16>, bit<16>> (if_begin)
        get_if_begin_action = {
            void apply(inout bit<16> if_begin_value, out bit<16> read_if_begin_value) {
                read_if_begin_value = if_begin_value;
    }};

    #define SKETCH_LEARN_REGISTER(num) \
        Register<bit<64>, bit<32>>(SKETCH_BUCKET_LENGTH) sketch_learn##num;\
        RegisterAction<bit<64>, bit<32>, bit<64>>(sketch_learn##num) \
            reg_sketch_learn##num = {\
                void apply(inout bit<64> value, out bit<64> read_value) {\
                    bit<64> in_value = value;    value = in_value + 1;\
                    read_value = value;\
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
            meta.value_sketch##num = reg_sketch_learn##num.execute(meta.index);\
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
/*************************************************************************
**************  M Y  C O N T R O L  P R O G R A M  *******************
*************************************************************************/
    action read_sketch0(bit<32> index) {
        hdr.myTunnel.load_sketch0 = action_read_sketch0.execute(index);
    }
    action read_sketch1(bit<32> index) {
        hdr.myTunnel.load_sketch1 = action_read_sketch1.execute(index);
    }
    action read_sketch2(bit<32> index) {
        hdr.myTunnel.load_sketch2 = action_read_sketch2.execute(index);
    }

    action renew_sketch0(bit<32> index) {
        action_renew_sketch0.execute(index);
    }
    action renew_sketch1(bit<32> index) {
        action_renew_sketch1.execute(index);
    }
    action renew_sketch2(bit<32> index) {
        action_renew_sketch2.execute(index);
    }

    action begin(){
        begin_action.execute(0);
    }

    action get_if_begin(){
        meta.if_begin = get_if_begin_action.execute(0);//judge if migration has begun
    }

   action stop(){
        stop_action.execute(0);
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

    action add_header(){
        hdr.myTunnel.setValid();
        hdr.myTunnel.proto_id = TYPE_IPV4;
	    hdr.ethernet.etherType = TYPE_MYTUNNEL;
        //注意添加包头之后，解析顺序要与parser.p4一致
        hdr.myTunnel.if_finish = 0;
    }

    action del_header(){
        hdr.myTunnel.setInvalid();
        hdr.ethernet.etherType = TYPE_IPV4;
    }

    /*基于背景流的迁移整体处理流程
        1 定义标志位，判断是否开始迁移
        2 进入第一个交换机，启用数据包头部，存储数据
        3 检查是否完成传输，更新if_finish字段
        4 设定端口转发，避免了修改IP
        5 进入第二个交换机，读取数据，删掉数据包头部
        */

   apply {
        if(hdr.if_control.isValid()){
            if(hdr.if_control.if_begin==1){                 //send control pkt, 迁移结束的条件放在控制包里面，开始和结束各有一个控制包
                begin();
                hdr.if_control.switch_id = 1;
            }
            else{
                stop();
            }
        }
        else{  //background flow
            get_if_begin();                     //judge if migration has begun
            if(meta.if_begin==0){         //begin migration
                tbl_execute_hash.apply();
                tbl_set_sketch0.apply();//swingstate 里面，要直接读出寄存器的值，这里的table和别sketchlearn的不一样
                modify_flag1.apply();
                if (meta.flag1 == 1)  tbl_set_sketch1.apply();
                if (meta.flag2 == 1)  tbl_set_sketch2.apply();
            }
            else if(meta.if_begin!=0){
                if(!hdr.myTunnel.isValid()){  //switch0
                    add_header();
                    hdr.myTunnel.ig_tstamp = ig_prsr_md.global_tstamp;

                    hdr.myTunnel.num_of_pkt = read_place_id_action.execute(0);
                    hdr.myTunnel.read_place_id0 = hdr.myTunnel.num_of_pkt;//sketchlearn only has one index
                    hdr.myTunnel.read_place_id1 = hdr.myTunnel.num_of_pkt;
                    hdr.myTunnel.read_place_id2 = hdr.myTunnel.num_of_pkt;

                    read_sketch0(hdr.myTunnel.read_place_id0);
                    read_sketch1(hdr.myTunnel.read_place_id1);
                    read_sketch2(hdr.myTunnel.read_place_id2);
                }
                else{                       //switch1
                    renew_sketch0(hdr.myTunnel.read_place_id0);
                    renew_sketch1(hdr.myTunnel.read_place_id1);
                    renew_sketch2(hdr.myTunnel.read_place_id2);
                    //del_header();
                }
            }
        }
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
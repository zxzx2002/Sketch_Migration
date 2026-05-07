#include <core.p4>
#include <t2na.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 46500//64位置
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

    Register<bit<32>,bit<32>>(1) read_place_id;
    RegisterAction<bit<32>, bit<32>, bit<32>> (read_place_id)
        read_place_id_action = {
            void apply(inout bit<32> read_place_id_value, out bit<32> read_place_id_read_value) {
                read_place_id_read_value=read_place_id_value;
                bit<32>tmp32 = read_place_id_value+1;
                bit<32>if_46500 = SKETCH_BUCKET_LENGTH - 1;
                if(read_place_id_value == if_46500)
                    read_place_id_value = 0;
                else
                    read_place_id_value = tmp32;
            }};

    Register<bit<16>,bit<16>>(1) register_id;
    RegisterAction<bit<16>, bit<16>, bit<16>> (register_id)
        register_id_action = {
            void apply(inout bit<16> register_id_value, out bit<16> read_register_id_value) {
                read_register_id_value = register_id_value;
                if((bit<16>)meta.result_read_place_id == 0)
                    register_id_value = register_id_value + 1;
            }};

    Register<bit<64>,bit<64>>(1) siphash;
    RegisterAction<bit<64>, bit<64>, bit<64>> (siphash)
        siphash_action = {
            void apply(inout bit<64> siphash_value, out bit<64> read_siphash_value) {
                read_siphash_value=siphash_value;
            }};
    RegisterAction<bit<64>, bit<64>, bit<64>> (siphash)
        renew_siphash_action = {
            void apply(inout bit<64> siphash_value, out bit<64> read_siphash_value) {
                //siphash_value = hdr.myTunnel.siphash;
                siphash_value = meta.siphash;
                read_siphash_value = siphash_value;
            }};

    #define SKETCH_REGISTER(num) Register<bit<SKETCH_CELL_BIT_WIDTH>, bit<32>>(SKETCH_BUCKET_LENGTH) sketch##num;\
        RegisterAction<bit<64>, bit<32>, bit<64>> (sketch##num)\
            action_sketch##num = {\
                void apply(inout bit<64> value_sketch##num, out bit<64> read_value_sketch##num) {\
                    bit<64> tmp64 = 1;\
                    value_sketch##num = tmp64;\
                    read_value_sketch##num = value_sketch##num;\
                }};\
        RegisterAction<bit<64>, bit<32>, bit<64>> (sketch##num)\
            action_read_sketch##num = {\
                void apply(inout bit<64> value_read_sketch##num, out bit<64> read_value_read_sketch##num) {\
                    read_value_read_sketch##num = value_read_sketch##num;\
                }};\
        RegisterAction<bit<64>, bit<32>, bit<64>> (sketch##num)\
            action_renew_sketch##num = {\
                void apply(inout bit<64> value_renew_sketch##num, out bit<64> read_value_renew_sketch##num) {\
                    value_renew_sketch##num = hdr.myTunnel.load_sketch;\
                    read_value_renew_sketch##num = value_renew_sketch##num;\
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
            hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}))&0xffff;
    }
    action sketch1_count(){
        meta.index_sketch1 = (myhash1.get({
            hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}))&0xffff;
    }
    action sketch2_count(){
        meta.index_sketch2 = (myhash2.get({
            hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}))&0xffff;
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
/*************************************************************************
**************  M Y  C O N T R O L  P R O G R A M  *******************
*************************************************************************/
    action read_sketch0(bit<32> index) {
        hdr.myTunnel.load_sketch = action_read_sketch0.execute(index);
    }
    action read_sketch1(bit<32> index) {
        hdr.myTunnel.load_sketch = action_read_sketch1.execute(index);
    }
    action read_sketch2(bit<32> index) {
        hdr.myTunnel.load_sketch = action_read_sketch2.execute(index);
    }
    action sub_read_place_id() {
        meta.result_read_place_id = SKETCH_BUCKET_LENGTH - 1 - hdr.myTunnel.read_place_id;
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

    action add_myTunnel(){
        hdr.myTunnel.setValid();
        hdr.myTunnel.proto_id = TYPE_IPV4;
	    hdr.ethernet.etherType = TYPE_MYTUNNEL;
        //注意添加包头之后，解析顺序要与parser.p4一致
        hdr.myTunnel.if_finish = 0;
    }

    action add_signature(){//p4sync里面是添加signature包头，在最后一个包生效
        hdr.signature.setValid();
        hdr.signature.proto_id = 1;
	    hdr.ethernet.etherType = TYPE_MYTUNNEL;
	    hdr.myTunnel.proto_id = TYPE_SIGN;
        //注意添加包头之后，解析顺序要与parser.p4一致
    }

    // For siphash
    // Copy from SPINE code,    Keys Generated by siphash_key_generator.py
    const bit<64> const_1 = 0x736f6d6570736575;
    const bit<64> const_2 = 0x646f72616e646f6d;
    const bit<64> const_3 = 0x6c7967656e657261;
    const bit<64> const_4 = 0x7465646279746573;
    const bit<64> key1 = 3597013258797167272;
    const bit<64> key2 = 7987411727713180468;

    //siphash()
    action sip_round1(){meta.v0 = meta.v0 + meta.v1;}
    action sip_round2(){meta.v2 = meta.v2 + meta.v3;}
    action sip_round3(){meta.v1 = (bit<64>) (meta.v1 << 13);}
    action sip_round4(){meta.v3 = (bit<64>) (meta.v3 << 16);}
    action sip_round5(){meta.v1 = meta.v1 ^ meta.v0;}
    action sip_round6(){meta.v3 = meta.v3 ^ meta.v2;}
    action sip_round7(){meta.v0 = (bit<64>) (meta.v0 << 32);}
    action sip_round8(){meta.v2 = meta.v2 + meta.v1;}
    action sip_round9(){meta.v0 = meta.v0 + meta.v3;}
    action sip_round10(){meta.v1 = (bit<64>) (meta.v1 << 17);}
    action sip_round11(){meta.v3 = (bit<64>) (meta.v3 << 21);}
    action sip_round12(){meta.v1 = meta.v1 ^ meta.v2;}
    action sip_round13(){meta.v3 = meta.v3 ^ meta.v0;}
    action sip_round14(){meta.v2 = (bit<64>) (meta.v2 << 32);}

    action sip_hash0(bit<64> message0, bit<64> message1) {
        meta.v0 = key1 ^ const_1;
        meta.v1 = key2 ^ const_2;
        meta.v2 = key1 ^ const_3;
        meta.v3 = key2 ^ const_4;
    }
    action sip_hash1(bit<64> message0, bit<64> message1){meta.v3 = meta.v3 ^ message0;}
    action sip_hash2(bit<64> message0, bit<64> message1){meta.v0 = meta.v0 ^ message0;}
    action sip_hash3(bit<64> message0, bit<64> message1){meta.v3 = meta.v3 ^ message1;}
    action sip_hash4(bit<64> message0, bit<64> message1){meta.v0 = meta.v0 ^ message1;}
    action sip_hash5(bit<64> message0, bit<64> message1){meta.v2 = meta.v2 ^ 0x00000000000000ff;}

    //meta.mac = meta.v0 ^ meta.v1 ^ meta.v2 ^ meta.v3;
    action mac_action1(){meta.mac= meta.v0 ^ meta.v1;}
    action mac_action2(){meta.mac= meta.mac ^ meta.v2;}
    action mac_action3(){meta.mac= meta.mac ^ meta.v3;}

   apply {
        /*
        实验流程：
        send_RSA 可以发出同时带有MyTunnel和Signature协议的包，实验时不需要用到
        在最后一个包，会自动补上Signature包头
        RSASender收到之后，构造加密，放到Signature字段里面
        发给交换机，再转发给RSAReceiver判断解密结果

        判断是不是迁移包，如果是，就开始siphash
        到最后一个位置，添加signature包头，转发给RSASender
        判断协议里面Signature的内容，然后设置转发端口到RSAreceiver

        signature包头用于判断RSA签名，MyTunnel用于判断背景流还是迁移流
        */

        forwarding.apply();

        if(hdr.if_control.isValid()){
            if(hdr.if_control.if_begin==1){                 //send control pkt, 迁移结束的条件放在控制包里面，开始和结束各有一个控制包
                begin();
            }
            else{stop();}
        }
        else{  //background flow
            if(!hdr.signature.isValid()){
                get_if_begin();                     //judge if migration has begun
                if(meta.if_begin==0){
                    tbl_myhash0.apply();
                    tbl_myhash1.apply();
                    tbl_myhash2.apply();
                    action_sketch0.execute(meta.index_sketch0);
                    action_sketch1.execute(meta.index_sketch1);
                    action_sketch2.execute(meta.index_sketch2);
                }
                else if(meta.if_begin!=0){         //begin migration
                    if(!hdr.myTunnel.isValid()){//switch0
                        add_myTunnel();
                        hdr.myTunnel.ig_tstamp = ig_prsr_md.global_tstamp;

                        meta.read_place_id = read_place_id_action.execute(0);
                        hdr.myTunnel.read_place_id = meta.read_place_id;
                        sub_read_place_id();
                        hdr.myTunnel.register_id = register_id_action.execute(0);

                        if(hdr.myTunnel.register_id==0)
                            read_sketch0(hdr.myTunnel.read_place_id);
                        if(hdr.myTunnel.register_id==1)
                            read_sketch1(hdr.myTunnel.read_place_id);
                        if(hdr.myTunnel.register_id==2){
                            read_sketch2(hdr.myTunnel.read_place_id);
                            if(meta.result_read_place_id == 0){  //the last packet
                                hdr.myTunnel.if_finish=1;
                                add_signature();
                                set_egress_port(144);   //send to RSA_sender
                                hdr.myTunnel.switch_id=0;//line 355 for timestamp
                            }
                        }

                        //begin siphash
                        meta.message0 = siphash_action.execute(0);
                        meta.message1 = hdr.myTunnel.load_sketch;//only use one num to simplify stage calculation

                        sip_hash0(meta.message0, meta.message1);
                        sip_hash1(meta.message0, meta.message1);
                        sip_round1();
                        sip_round2();
                        sip_round3();
                        sip_round4();
                        sip_round5();
                        sip_round6();
                        sip_round7();
                        sip_round8();
                        sip_round9();
                        sip_round10();
                        sip_round11();
                        sip_round12();
                        sip_round13();
                        sip_round14();
                        sip_hash2(meta.message0, meta.message1);
                        sip_hash3(meta.message0, meta.message1);
                        sip_round1();
                        sip_round2();
                        sip_round3();
                        sip_round4();
                        sip_round5();
                        sip_round6();
                        sip_round7();
                        sip_round8();
                        sip_round9();
                        sip_round10();
                        sip_round11();
                        sip_round12();
                        sip_round13();
                        sip_round14();
                        sip_hash4(meta.message0, meta.message1);
                        sip_hash5(meta.message0, meta.message1);
                        sip_round1();
                        sip_round2();
                        sip_round3();
                        sip_round4();
                        sip_round5();
                        sip_round6();
                        sip_round7();
                        sip_round8();
                        sip_round9();
                        sip_round10();
                        sip_round11();
                        sip_round12();
                        sip_round13();
                        sip_round14();

                        sip_round1();
                        sip_round2();
                        sip_round3();
                        sip_round4();
                        sip_round5();
                        sip_round6();
                        sip_round7();
                        sip_round8();
                        sip_round9();
                        sip_round10();
                        sip_round11();
                        sip_round12();
                        sip_round13();
                        sip_round14();

                        mac_action1();
                        mac_action2();
                        mac_action3();
                        meta.siphash = meta.mac;
                        //hdr.myTunnel.siphash = meta.siphash;
                        //@stage(6){renew_siphash_action.execute(0);}
                    }
                    else{  //switch1
                        if(hdr.myTunnel.register_id==0)
                            renew_sketch0(hdr.myTunnel.read_place_id);//后续设计迁移完整性实验，可以加寄存器，记录哪些迁移了，哪些没迁移
                        if(hdr.myTunnel.register_id==1)
                            renew_sketch1(hdr.myTunnel.read_place_id);
                        if(hdr.myTunnel.register_id==2)
                            renew_sketch2(hdr.myTunnel.read_place_id);
                    }
                }
            }
        }
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
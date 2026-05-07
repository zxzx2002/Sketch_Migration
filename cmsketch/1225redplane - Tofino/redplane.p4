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

    #define SKETCH_REGISTER(num) Register<bit<SKETCH_CELL_BIT_WIDTH>, bit<32>>(SKETCH_BUCKET_LENGTH) sketch##num;\
        RegisterAction<bit<64>, bit<32>, bit<64>> (sketch##num)\
            action_sketch##num = {\
                void apply(inout bit<64> value_sketch##num, out bit<64> read_value_sketch##num) {\
                    bit<64> tmp64 = value_sketch##num + 1;\
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

   apply {
        /*
        RedPlane流程
        (1) 控制面下发指令，开始迁移，准备下发背景流
        (2)在s1，添加MyTunnel，按寄存器顺序和读取位置顺序，每次带走一个状态√
        (3) 全部迁移后，finish改标志位
        (4)在h2，解析MyTunnel，存储在寄存器对应位置
        */

        /*
        bmv2运行程序流程
        (1)拓扑是三个服务器，三个交换机，h1-s1-s2-(h2,s3)  s3-h3，要设定s2的转发方式，是端口1->2, 2->3,
        (2)先在s1 s2 set_hashes，因为发控制包if_control的时候，同时通过s1 s2，这俩都认为自己是switch0，最后数据也是从s2给到h2
        (3)然后下发send_sketch，再send_migration下发if_control控制包
        (4)h2运行test_scapy，可以再开一个跑 tail -f capture_packets.txt
        (5)h1下发背景流，tcpreplay -v -i h1-eth0 pcap文件，当全部迁移到h2之后，交换机的if_finish标志位变1，h2也识别这一字段，从而开始发包给h3
        (6)s3收到的是myTunnel包头，认为自己是switch1，存储sketch的数据，完成迁移整个过程
        */

        if(hdr.if_control.isValid()){
            if(hdr.if_control.if_begin==1) begin();     //send control pkt, 迁移结束的条件放在控制包里面，开始和结束各有一个控制包
            else stop();
        }
        else{                                           //background flow
            get_if_begin();                     //judge if migration has begun
            if(meta.if_begin==0){
                tbl_myhash0.apply();
                tbl_myhash1.apply();
                tbl_myhash2.apply();
                @stage(3){                      //@stage to avoid conflict with sketch_read
                    action_sketch0.execute(meta.index_sketch0);
                    action_sketch1.execute(meta.index_sketch1);
                    action_sketch2.execute(meta.index_sketch2);
                }
            }
            else if(meta.if_begin!=0){           //begin migration
                if(!hdr.myTunnel.isValid()){  //switch0
                    add_header();
                    hdr.myTunnel.ig_tstamp_sw0 = ig_prsr_md.global_tstamp;

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
                        if(meta.result_read_place_id == 0)
                                hdr.myTunnel.if_finish=1;
                    }
                }

                else{                       //switch1
                    if(hdr.myTunnel.register_id==0)
                        renew_sketch0(hdr.myTunnel.read_place_id);//后续设计迁移完整性实验，可以加寄存器，记录哪些迁移了，哪些没迁移
                    if(hdr.myTunnel.register_id==1)
                        renew_sketch1(hdr.myTunnel.read_place_id);
                    if(hdr.myTunnel.register_id==2)
                        renew_sketch2(hdr.myTunnel.read_place_id);
                    hdr.myTunnel.ig_tstamp_sw1 = ig_prsr_md.global_tstamp;
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
	    if(hdr.myTunnel.switch_id == 0)
	        hdr.myTunnel.eg_tstamp_sw0 = eg_intr_md_from_prsr.global_tstamp;
        else if(hdr.myTunnel.switch_id == 1)
	        hdr.myTunnel.eg_tstamp_sw1 = eg_intr_md_from_prsr.global_tstamp;
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
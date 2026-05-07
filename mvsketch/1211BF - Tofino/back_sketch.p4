#include <core.p4>
#include <t2na.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define SKETCH_BUCKET_LENGTH 23250  //因为每个register里面是mv_struct 128bit，所以要46500/2 = 23250
#define SKETCH_CELL_BIT_WIDTH 64

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
struct mv_struct{
    bit<64> hi;
    bit<64> lo;
};

control MyIngress(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    Register<bit<16>,bit<16>>(1) if_begin;
    RegisterAction<bit<16>, bit<16>, bit<16>> (if_begin) if_begin_action = {
            void apply(inout bit<16> if_begin_value, out bit<16> read_if_begin_value) {
                if_begin_value = 1;
            }};
    /*RegisterAction<bit<16>, bit<16>, bit<16>> (if_begin) reset_if_begin_action = {
            void apply(inout bit<16> if_begin_value, out bit<16> read_if_begin_value) {
                if_begin_value = 0;
            }};*/
    RegisterAction<bit<16>, bit<16>, bit<16>> (if_begin) get_if_begin_action = {
            void apply(inout bit<16> if_begin_value, out bit<16> read_if_begin_value) {
                read_if_begin_value = if_begin_value;
    }};

    Register<bit<32>,bit<32>>(1) read_place_id;
    RegisterAction<bit<32>, bit<32>, bit<32>> (read_place_id)
        read_place_id_action = {
            void apply(inout bit<32> read_place_id_value, out bit<32> read_place_id_read_value) {
                read_place_id_read_value=read_place_id_value;
                bit<32>tmp32 = read_place_id_value+1;
                read_place_id_value = tmp32;
            }
    };

    Register<mv_struct, bit<32>>(SKETCH_BUCKET_LENGTH) mvsketch_count;
    Register<mv_struct, bit<32>>(SKETCH_BUCKET_LENGTH) mvsketch_subkey1;
    Register<mv_struct, bit<32>>(SKETCH_BUCKET_LENGTH) mvsketch_subkey2;

    RegisterAction<mv_struct, bit<32>, bit<64>>(mvsketch_count) action_mvsketch = {
        void apply(inout mv_struct value_mvsketch, out bit<64> read_value_mvsketch) {
            mv_struct value = value_mvsketch;
            if (!(meta.mvsketch_flag == 1))
                value_mvsketch.lo = (bit<64>)((bit<64>)value.lo + meta.len);
            else if (meta.mvsketch_flag == 1 && (bit<64>)value.lo >= meta.len)
                value_mvsketch.lo = (bit<64>)((bit<64>)value.lo - meta.len);

            value_mvsketch.hi = (bit<64>)((bit<64>)value.hi + meta.len);
            if (meta.mvsketch_flag == 1 && !((bit<64>)value.lo >= meta.len))
                read_value_mvsketch = (bit<64>)value_mvsketch.hi;
            }};
    RegisterAction<mv_struct, bit<32>, bit<64>>(mvsketch_count) action_read_mvsketch_lo = {
        void apply(inout mv_struct value_mvsketch, out bit<64> read_value_mvsketch) {
            read_value_mvsketch = value_mvsketch.lo;
        }};
    RegisterAction<mv_struct, bit<32>, bit<64>>(mvsketch_count) action_read_mvsketch_hi = {
        void apply(inout mv_struct value_mvsketch, out bit<64> read_value_mvsketch) {
            read_value_mvsketch = value_mvsketch.hi;
        }};
    RegisterAction<mv_struct, bit<32>, bit<64>>(mvsketch_count) action_renew_mvsketch = {
        void apply(inout mv_struct value_mvsketch, out bit<64> read_value_mvsketch) {
            //value_mvsketch.lo = hdr.myTunnel.load_mvsketch_lo;
            value_mvsketch.hi = hdr.myTunnel.load_mvsketch_hi;
        }};

    RegisterAction<mv_struct, bit<32>, bit<64>>(mvsketch_subkey1) action_subkey1 = {
        void apply(inout mv_struct value_subkey1, out bit<64> read_value_subkey1) {
            mv_struct in_value = value_subkey1;
            if ((bit<32>)in_value.hi != hdr.ipv4.dstAddr || (bit<32>)in_value.lo != hdr.ipv4.srcAddr)
                read_value_subkey1 = 1;
            value_subkey1.lo = (bit<64>)hdr.ipv4.srcAddr;
            value_subkey1.hi = (bit<64>)hdr.ipv4.dstAddr;
        }};
    RegisterAction<mv_struct, bit<32>, bit<64>>(mvsketch_subkey1) action_read_subkey1_lo = {
        void apply(inout mv_struct value_subkey1, out bit<64> read_value_subkey1) {
            read_value_subkey1 = value_subkey1.lo;
        }};
    RegisterAction<mv_struct, bit<32>, bit<64>>(mvsketch_subkey1) action_read_subkey1_hi = {
        void apply(inout mv_struct value_subkey1, out bit<64> read_value_subkey1) {
            read_value_subkey1 = value_subkey1.hi;
        }};
    RegisterAction<mv_struct, bit<32>, bit<64>>(mvsketch_subkey1) action_renew_subkey1 = {
        void apply(inout mv_struct value_subkey1, out bit<64> read_value_subkey1) {
            //value_subkey1.lo = hdr.myTunnel.load_subkey1_lo;
            value_subkey1.hi = hdr.myTunnel.load_subkey1_hi;
        }};

    RegisterAction<mv_struct, bit<32>, bit<64>>(mvsketch_subkey2) action_subkey2 = {
        void apply(inout mv_struct value_subkey2, out bit<64> read_value_subkey2) {
            mv_struct in_value = value_subkey2;
            if ((bit<8>)in_value.hi != hdr.ipv4.protocol || (bit<16>)in_value.lo != hdr.tcp.dstPort)
                read_value_subkey2 = 1;
            value_subkey2.lo = (bit<64>)hdr.tcp.dstPort;
            value_subkey2.hi = (bit<64>)hdr.ipv4.protocol;
        }};
    RegisterAction<mv_struct, bit<32>, bit<64>>(mvsketch_subkey2) action_read_subkey2_lo = {
        void apply(inout mv_struct value_subkey2, out bit<64> read_value_subkey2) {
            read_value_subkey2 = value_subkey2.lo;
        }};
    RegisterAction<mv_struct, bit<32>, bit<64>>(mvsketch_subkey2) action_read_subkey2_hi = {
        void apply(inout mv_struct value_subkey2, out bit<64> read_value_subkey2) {
            read_value_subkey2 = value_subkey2.hi;
        }};
    RegisterAction<mv_struct, bit<32>, bit<64>>(mvsketch_subkey2) action_renew_subkey2 = {
        void apply(inout mv_struct value_subkey2, out bit<64> read_value_subkey2) {
            //value_subkey2.lo = hdr.myTunnel.load_subkey2_lo;
            value_subkey2.hi = hdr.myTunnel.load_subkey2_hi;
        }};

    CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
                           true,          // reversed
                           false,         // use msb?
                           true,         // extended?
                           32w0xFFFFFFFF, // initial shift register value
                           32w0xFFFFFFFF  // result xor
                           ) poly0;
    CRCPolynomial<bit<32>>(32w0xEDB88320, // polynomial
                           true, false, true, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly1;
    CRCPolynomial<bit<32>>(32w0xDB710641, // polynomial
                           true, false, true, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly2;

    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly0) myhash0;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) myhash1;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly2) myhash2;

    action mvsketch() {
        meta.index_mvsketch = (myhash0.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0xffff; //hash.get is different from cm_sketch
    }
    action subkey1() {
        meta.index_subkey1 = (myhash1.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0xffff;
    }
    action subkey2() {
        meta.index_subkey2 = (myhash2.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0xffff;
    }

    table tbl_mvsketch {
        actions = {mvsketch;} size = 64; const default_action = mvsketch();}
    table tbl_subkey1 {
        actions = {subkey1;} size = 64; const default_action = subkey1();}
    table tbl_subkey2 {
        actions = {subkey2;} size = 64; const default_action = subkey2();}

/*************************************************************************
**************  M Y  C O N T R O L  P R O G R A M  *******************
*************************************************************************/
    action read_mvsketch_lo(bit<32> index) {
        //hdr.myTunnel.load_mvsketch_lo = action_read_mvsketch_lo.execute(index);
    }
    action read_mvsketch_hi(bit<32> index) {
        hdr.myTunnel.load_mvsketch_hi = action_read_mvsketch_hi.execute(index);
    }
    action read_subkey1_lo(bit<32> index) {
        //hdr.myTunnel.load_subkey1_lo = action_read_subkey1_lo.execute(index);
    }
    action read_subkey1_hi(bit<32> index) {
        hdr.myTunnel.load_subkey1_hi = action_read_subkey1_hi.execute(index);
    }
    action read_subkey2_lo(bit<32> index) {
        //hdr.myTunnel.load_subkey2_lo = action_read_subkey2_lo.execute(index);
    }
    action read_subkey2_hi(bit<32> index) {
        hdr.myTunnel.load_subkey2_hi = action_read_subkey2_hi.execute(index);
    }

    action read_read_place_id(){
        hdr.myTunnel.read_place_id = read_place_id_action.execute(0);
    }
    action sub_read_place_id(){
        meta.result_read_place_id = SKETCH_BUCKET_LENGTH;   //judge whether we reach the last place_id
        meta.result_read_place_id = meta.result_read_place_id - hdr.myTunnel.read_place_id;
    }

    action renew_mvsketch(bit<32> index) {
        action_renew_mvsketch.execute(index);
    }
    action renew_subkey1(bit<32> index) {
        action_renew_subkey1.execute(index);
    }
    action renew_subkey2(bit<32> index) {
        action_renew_subkey2.execute(index);
    }

    action begin(){
        if_begin_action.execute(0);
    }

    action get_if_begin(){
        meta.if_begin = get_if_begin_action.execute(0);//judge if migration has begun
    }

   action finish(){
        hdr.myTunnel.if_finish = 1;
        //reset_if_begin_action.execute(0);
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
        get_if_begin();

        if(hdr.if_control.isValid()){//send control pkt
            hdr.if_control.switch_id = hdr.if_control.switch_id+1;
            begin();
        }

         //增加一个包头，用于发控制平面信息，这个包要携带判断是哪个交换机的信息，switch_id,存在寄存器里面
        //对于控制包，只负责改switch_id寄存器的数值，还有if_begin的数值
        //后面的数据包，结合switch_id寄存器数值，决定是读取信息还是写入信息

        /*实验时，按照以下步骤
        (1) 在s1，set_hashes，由h1下发用于sketch计数的数据包，用send_sketch.py
        (2) 在s2，set_hashes，由h1下发迁移指令的控制包，用send_migration.py
        (3) 在h1，下发带有28个包的PCAP数据集用于迁移
        (4) 在h1，下发大PCAP用于增加sketch计数，比较s1 s2的sketch计数情况
        */

        if (meta.if_begin==0){
            meta.len = (bit<64>)hdr.ipv4.totalLen;
            tbl_subkey1.apply();
            tbl_subkey2.apply();
            tbl_mvsketch.apply();// hash to get index
            //meta.mvsketch_flag = (bit<16>) action_subkey1.execute(meta.index_subkey1);
            //meta.mvsketch_flag = (bit<16>) action_subkey2.execute(meta.index_subkey2);
            //meta.repass_flag = (bit<16>)action_mvsketch.execute(meta.index_mvsketch);
        }
        else if(meta.if_begin!=0) {//begin migration
            if(!hdr.myTunnel.isValid()){
                add_header();
                hdr.myTunnel.ig_tstamp = ig_prsr_md.global_tstamp;

                read_read_place_id();
                //read_mvsketch_lo(hdr.myTunnel.read_place_id);
                read_mvsketch_hi(hdr.myTunnel.read_place_id);
                //read_subkey1_lo(hdr.myTunnel.read_place_id);
                read_subkey1_hi(hdr.myTunnel.read_place_id);
                //read_subkey2_lo(hdr.myTunnel.read_place_id);
                read_subkey2_hi(hdr.myTunnel.read_place_id);

                sub_read_place_id();
                if(meta.result_read_place_id == 0){
                    finish();
                }
            }
            else{
                action_renew_subkey1.execute(hdr.myTunnel.read_place_id);
                action_renew_subkey2.execute(hdr.myTunnel.read_place_id);
                action_renew_mvsketch.execute(hdr.myTunnel.read_place_id);
                if(hdr.myTunnel.if_finish!=0){
                    finish();
                }
                //del_header();
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

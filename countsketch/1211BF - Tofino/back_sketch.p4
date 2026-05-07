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
                value_count_sketch##num = hdr.myTunnel.load_sketch##num;\
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
    action read_read_place_id(){
        hdr.myTunnel.read_place_id = read_place_id_action.execute(0);
    }

    action read_sketch0(bit<32> index) {
        hdr.myTunnel.load_sketch0 = action_read_count_sketch0.execute(index);
    }
    action read_sketch1(bit<32> index) {
        hdr.myTunnel.load_sketch1 = action_read_count_sketch1.execute(index);
    }
    action read_sketch2(bit<32> index) {
        hdr.myTunnel.load_sketch2 = action_read_count_sketch2.execute(index);
    }
    action sub_read_place_id() {
        meta.result_read_place_id = SKETCH_BUCKET_LENGTH - 1 - hdr.myTunnel.read_place_id;
    }

    action renew_sketch0(bit<32> index) {
        action_renew_count_sketch0.execute(index);
    }
    action renew_sketch1(bit<32> index) {
        action_renew_count_sketch1.execute(index);
    }
    action renew_sketch2(bit<32> index) {
        action_renew_count_sketch2.execute(index);
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

        if (hdr.ipv4.isValid() && hdr.tcp.isValid() && !hdr.if_control.isValid() && meta.if_begin==0){
            tbl_do_init.apply();
            tbl_count_sketch0.apply();
            tbl_count_sketch1.apply();
            tbl_count_sketch2.apply();
            action_count_sketch0.execute(meta.index_sketch0);
            action_count_sketch1.execute(meta.index_sketch1);
            action_count_sketch2.execute(meta.index_sketch2);
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

        if(hdr.if_control.isValid()){//send control pkt
            hdr.if_control.switch_id = hdr.if_control.switch_id+1;
            begin();
        }

        if (meta.if_begin!=0 && meta.if_finish==0 ) {//begin migration
            if(!hdr.myTunnel.isValid()){
                add_header();

                hdr.myTunnel.ig_tstamp = ig_prsr_md.global_tstamp;

                read_read_place_id();
                read_sketch0(hdr.myTunnel.read_place_id);
                read_sketch1(hdr.myTunnel.read_place_id);
                read_sketch2(hdr.myTunnel.read_place_id);
                sub_read_place_id();
                if(meta.result_read_place_id == 0){
                    finish();
                    //hdr.myTunnel.eg_tstamp = ig_prsr_md.global_tstamp;
                }
            }
            else{
                renew_sketch0(hdr.myTunnel.read_place_id);
                renew_sketch1(hdr.myTunnel.read_place_id);
                renew_sketch2(hdr.myTunnel.read_place_id);
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

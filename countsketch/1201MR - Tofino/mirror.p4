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

    action sub_read_place_id(){
        meta.result_read_place_id = SKETCH_BUCKET_LENGTH;   //judge whether we reach the last place_id
        meta.result_read_place_id = meta.result_read_place_id - hdr.myTunnel.read_place_id;
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

    action clone_set(){
        meta.sid = 27;
        meta.pkt_type = 1;
        ig_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
    }

    action recirculate(bit<7> recirc_port) {
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];//set pipeline
        ig_tm_md.ucast_egress_port[6:0] = recirc_port; //set  port
    }

    apply {
        /*整体处理逻辑
        (1)第一次来控制包，判断hdr.myTunnel，开始迁移。
        (2)先克隆一份，I2E的包不执行ingress，直接去egress里面迁移。原始包在ingress配置Recirculate。
        (3)原始包：recirculate可以携带该轮循环之前的数据，所以每一轮镜像包里面的read_place_id实际是上一轮原始包的read_place_id
        镜像包：由于不执行ingress，所有操作要在e里面完成
        (4)egress可以根据出端口判断是镜像包还是循环包，对于循环包，存储数据可能浪费一点时间，待优化
        对于迁移包，迁移sketch寄存器内容
        (5)循环包从128端口回到ingress，再次镜像
        */
        if(hdr.myTunnel.isValid()){
            if(ig_intr_md.ingress_port==128){//recirculate port
                hdr.myTunnel.switch_id = 0; //reset flag if it is the recirculate pkt in switch0
                hdr.myTunnel.ig_tstamp = ig_prsr_md.global_tstamp;
            }
            if(hdr.myTunnel.if_finish==0){
                if(hdr.myTunnel.switch_id==0){//switch0
                    clone_set();//镜像包不会执行ingress后续的内容，所以要靠原始包把read_place_id带过去
                    hdr.myTunnel.read_place_id = read_place_id_action.execute(0);
                    sub_read_place_id();
                    if(meta.result_read_place_id==0){
                        hdr.myTunnel.if_finish = 1;
                        ig_tm_md.ucast_egress_port = 144;//stop recirculate
                    }
                    else{
                        recirculate(0);
                    }
                }
            }
        }
        else{
            forwarding.apply();
        }
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

    action del_mirror_hdr(){
        hdr.mirror.setInvalid();
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid() && !hdr.myTunnel.isValid()){
            tbl_do_init.apply();
            tbl_count_sketch0.apply();
            tbl_count_sketch1.apply();
            tbl_count_sketch2.apply();
            action_count_sketch0.execute(meta.index_sketch0);
            action_count_sketch1.execute(meta.index_sketch1);
            action_count_sketch2.execute(meta.index_sketch2);
        }

        if(hdr.myTunnel.isValid()){
            if(hdr.myTunnel.if_finish==0){
                if(hdr.myTunnel.switch_id==0){
                    hdr.myTunnel.load_sketch0 = action_read_count_sketch0.execute(hdr.myTunnel.read_place_id);
                    hdr.myTunnel.load_sketch1 = action_read_count_sketch1.execute(hdr.myTunnel.read_place_id);
                    hdr.myTunnel.load_sketch2 = action_read_count_sketch2.execute(hdr.myTunnel.read_place_id);
                    hdr.myTunnel.switch_id = 1;         //set flag and send to switch1
                }else{
                    action_renew_count_sketch0.execute(hdr.myTunnel.read_place_id);
                    action_renew_count_sketch1.execute(hdr.myTunnel.read_place_id);
                    action_renew_count_sketch2.execute(hdr.myTunnel.read_place_id);
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

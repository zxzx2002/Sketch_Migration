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
#define SKETCH_BUCKET_LENGTH 23250
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
            value_mvsketch.lo = hdr.myTunnel.load_mvsketch_lo;
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
            value_subkey1.lo = hdr.myTunnel.load_subkey1_lo;
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
            value_subkey2.lo = hdr.myTunnel.load_subkey2_lo;
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

    action read_mvsketch_lo(bit<32> index) {
        hdr.myTunnel.load_mvsketch_lo = action_read_mvsketch_lo.execute(index);
    }
    action read_mvsketch_hi(bit<32> index) {
        hdr.myTunnel.load_mvsketch_hi = action_read_mvsketch_hi.execute(index);
    }
    action read_subkey1_lo(bit<32> index) {
        hdr.myTunnel.load_subkey1_lo = action_read_subkey1_lo.execute(index);
    }
    action read_subkey1_hi(bit<32> index) {
        hdr.myTunnel.load_subkey1_hi = action_read_subkey1_hi.execute(index);
    }
    action read_subkey2_lo(bit<32> index) {
        hdr.myTunnel.load_subkey2_lo = action_read_subkey2_lo.execute(index);
    }
    action read_subkey2_hi(bit<32> index) {
        hdr.myTunnel.load_subkey2_hi = action_read_subkey2_hi.execute(index);
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

     action del_mirror_hdr(){
        hdr.mirror.setInvalid();
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid() && !hdr.myTunnel.isValid()){
            meta.len = (bit<64>)hdr.ipv4.totalLen;
            tbl_subkey1.apply();
            tbl_subkey2.apply();
            tbl_mvsketch.apply();// hash to get index

            meta.mvsketch_flag = (bit<16>) action_subkey1.execute(meta.index_subkey1);
            meta.mvsketch_flag = (bit<16>) action_subkey2.execute(meta.index_subkey2);
            meta.repass_flag = (bit<16>)action_mvsketch.execute(meta.index_mvsketch);
        }

        else if(hdr.myTunnel.isValid()){
            if(hdr.myTunnel.if_finish==0){
                //read_mvsketch_lo(hdr.myTunnel.read_place_id);
                read_mvsketch_hi(hdr.myTunnel.read_place_id);
                //read_subkey1_lo(hdr.myTunnel.read_place_id);
                read_subkey1_hi(hdr.myTunnel.read_place_id);
                //read_subkey2_lo(hdr.myTunnel.read_place_id);
                read_subkey2_hi(hdr.myTunnel.read_place_id);
                hdr.myTunnel.switch_id = 1;         //set flag and send to switch1
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

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

    Register<mv_struct, bit<32>>(64) mvsketch_count;
    Register<mv_struct, bit<32>>(64) mvsketch_subkey1;
    Register<mv_struct, bit<32>>(64) mvsketch_subkey2;

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
            //value_mvsketch.lo = hdr.myTunnel.load_sketch_lo;
            //value_mvsketch.hi = hdr.myTunnel.load_sketch_hi;
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
            //value_subkey1.lo = hdr.myTunnel.load_sketch_lo;
            //value_subkey1.hi = hdr.myTunnel.load_sketch_hi;
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
            //value_subkey2.lo = hdr.myTunnel.load_sketch_lo;
            //value_subkey2.hi = hdr.myTunnel.load_sketch_hi;
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
        meta.index_mvsketch = (myhash0.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0x003f; //hash.get is different from cm_sketch
    }
    action subkey1() {
        meta.index_key1 = (myhash1.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0x003f;
    }
    action subkey2() {
        meta.index_key2 = (myhash2.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0x003f;
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
        meta.len = (bit<64>)hdr.ipv4.totalLen;
        tbl_subkey1.apply();
        tbl_subkey2.apply();
        tbl_mvsketch.apply();// hash to get index
        meta.mvsketch_flag = (bit<16>) action_subkey1.execute(meta.index_key1);
        meta.mvsketch_flag = (bit<16>) action_subkey2.execute(meta.index_key2);
        meta.repass_flag = (bit<16>)action_mvsketch.execute(meta.index_mvsketch);
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
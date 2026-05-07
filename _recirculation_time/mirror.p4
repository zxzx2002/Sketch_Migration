#include <core.p4>
#include <t2na.p4>

#include "include/headers.p4"
#include "include/parsers.p4"
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


    action read_sketch0(bit<32> index) {
        meta.load_sketch = read_place_id_action.execute(index);
    }

    action set_egress_port(bit<9> egress_port){
        ig_tm_md.ucast_egress_port = egress_port;
    }

    action recirculate(bit<7> recirc_port) {
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];//set pipeline
        ig_tm_md.ucast_egress_port[6:0] = recirc_port; //set  port
    }

    apply {
        read_sketch0(0);
        if(hdr.myTunnel.isValid()){
            if(ig_intr_md.ingress_port==144){//recirculate port
                hdr.myTunnel.ig_tstamp = ig_prsr_md.global_tstamp;
                recirculate(0);
            }
            if(ig_intr_md.ingress_port==128){//recirculate port
                hdr.myTunnel.ig_tstamp_1 = ig_prsr_md.global_tstamp;
                set_egress_port(144);
            }
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

    apply {
        if((bit<16>)hdr.myTunnel.ig_tstamp_1==0)//bit 48 can not calculate
            hdr.myTunnel.eg_tstamp = eg_prsr_md.global_tstamp;
        else
            hdr.myTunnel.eg_tstamp_1 = eg_prsr_md.global_tstamp;
    }
}

Pipeline(MyIngressParser(),
         MyIngress(),
         MyIngressDeparser(),
         MyEgressParser(),
         MyEgress(),
         MyEgressDeparser()) pipe;
Switch(pipe) main;

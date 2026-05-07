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
        if(hdr.if_control.switch_id==0)
            hdr.if_control.sw1_ig_tstamp = ig_prsr_md.global_tstamp;
        else if(hdr.if_control.switch_id==2)
            hdr.if_control.sw2_ig_tstamp = ig_prsr_md.global_tstamp;
        hdr.if_control.switch_id=hdr.if_control.switch_id+1;
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
	    if(hdr.if_control.switch_id==1)
	        hdr.if_control.sw1_eg_tstamp = eg_intr_md_from_prsr.global_tstamp;
        else if(hdr.if_control.switch_id==3)
            hdr.if_control.sw2_eg_tstamp = eg_intr_md_from_prsr.global_tstamp;
	    hdr.if_control.switch_id=hdr.if_control.switch_id+1;
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

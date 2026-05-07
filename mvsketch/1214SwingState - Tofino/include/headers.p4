/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
const bit<16> TYPE_MYTUNNEL = 0x1212;
const bit<16> TYPE_IF_CONTROL = 0x3637;
const bit<16> TYPE_IPV4 = 0x800;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header myTunnel_t {
    bit<16> proto_id;
    bit<16> switch_id;
    bit<32> index_mvsketch;//作为index
    bit<64> load_mvsketch_hi;
    bit<32> index_subkey1;
    bit<64> load_subkey1_hi;
    bit<32> index_subkey2;
    bit<64> load_subkey2_hi;
    bit<32> read_place_id;
    bit<16> if_finish;
    bit<32> num_of_pkt;

    bit<48> ig_tstamp;
    bit<48> eg_tstamp;
}

header if_control_t{
    bit<16> proto_id;
    bit<32> switch_id;
    bit<16> if_begin;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<32> index_mvsketch;
    bit<32> index_subkey1;
    bit<32> index_subkey2;
    bit<64> value_mvsketch;
    bit<64> value_subkey1;
    bit<64> value_subkey2;
    bit<32> read_place_id;
	bit<32> result_read_place_id;

    bit<64> mvsketch_flag;
    bit<64> repass_flag;
    bit<64> len;

    bit<16> if_begin;
}

struct headers {
    ethernet_t   ethernet;
    myTunnel_t   myTunnel;
    if_control_t    if_control;
    ipv4_t       ipv4;
    tcp_t        tcp;
}


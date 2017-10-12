#define ETHERTYPE_IPV4 0x0800
#define IPPROTO_UDP 17


header_type ethernet_t {
  fields {
    dstAddr   : 48;
    srcAddr   : 48;
    etherType : 16;
  }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        reserved_flag : 1;
        df_flag : 1;
        mf_flag : 1;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type udp_t {
    fields {
        srcPort  : 16;
        dstPort  : 16;
        len      : 16;
        checksum : 16;
    }
}

header ethernet_t ethernet;
header ipv4_t ipv4;
header udp_t udp;

parser parse_ethernet {
  extract(ethernet);
  return select(latest.etherType) {
    ETHERTYPE_IPV4:    parse_ipv4;
    default:  ingress;
  }
}

parser parse_ipv4 {
  extract(ipv4);
  return select(latest.protocol) {
    IPPROTO_UDP:     parse_udp;
    default:  ingress;
  }
}

parser parse_udp {
  extract(udp);
  return ingress;
}


parser start {
  return parse_ethernet;
}


primitive_action payload_scan();

action act_drop(){
  drop();
}


action act_modify_and_send(port){
  payload_scan();
  modify_field (standard_metadata.egress_spec, port);
}

action act_do_forward(espec) {
    modify_field(standard_metadata.egress_spec, espec);
}

table tbl_forward_udp {
  actions {
    act_modify_and_send;
  }
}

table tbl_drop {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
		act_drop;
    }
}


control ingress {
    if(valid(udp)){
        apply(tbl_forward_udp);
   } else {
       apply(tbl_drop);
   }
}

control egress {
}
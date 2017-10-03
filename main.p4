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
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header ethernet_t ethernet;
header ipv4_t ipv4;

parser parse_ethernet {
  extract(ethernet);
  return select(latest.etherType) {
    0x800:    parse_ipv4;
    default:  ingress;
  }
}

parser parse_ipv4 {
  extract(ipv4);
  return ingress;
}

parser start {
  return parse_ethernet;
}

primitive_action modify_sth();
primitive_action payload_scan();

action act_drop()
{
  drop();
}

action act_send_to_default(port) {
  modify_field (standard_metadata.egress_spec, port);
}


action act_modify_and_send(port){
  payload_scan();
  //modify_sth();
  modify_field (standard_metadata.egress_spec, port);
}

table tbl_forward_udp {
  reads {
    ipv4.dstAddr : exact ;
  }
  actions {
    act_modify_and_send;
    act_send_to_default;
    act_drop;
  }
}

control ingress {
   apply(tbl_forward_udp);
}

control egress {
}
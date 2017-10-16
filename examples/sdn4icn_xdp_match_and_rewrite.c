/*
 * Copyright (c) 2017 TNO
 */
/* File does not compile without the KBUILD_MODNAME */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h> /* Ethernet header: http://elixir.free-electrons.com/linux/v3.2/source/include/linux/if_ether.h */
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h> /* Ip header: http://elixir.free-electrons.com/linux/latest/source/include/linux/ip.h  And http://elixir.free-electrons.com/linux/latest/source/include/uapi/linux/ip.h#L85 */
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h> /* UDP header: http://elixir.free-electrons.com/linux/latest/source/include/linux/udp.h And http://elixir.free-electrons.com/linux/latest/source/include/uapi/linux/udp.h#L22 */
#include "bpf_helpers.h"

#define TX_NEW_TTL 0x80 /* 128 */
#define TNO_XDP_MATCH (XDP_TX + 1)
#define ETH_HLEN 14
#define UDP_HLEN 8
#define MAX_OCTET_COUNT 8 /* Changing this to be a value above 8 results in a back-edge error*/
#define IPV4_ETHERTYPE 0x0800
#define UDP_TX_PORT  0xdc2b /* the number 56363 is used as forward port*/
#define UDP_TARGETED_PORT  0x18DB /* the number 6363 is used as source port*/
#define INVALID_PACKET_ACTION XDP_DROP
#define NDN_TYPE_INTEREST 0x05
#define NDN_TYPE_DATA 0x06 /* https://named-data.net/doc/ndn-tlv/types.html */
#define NDN_TYPE_NAME 0x07 /* https://named-data.net/doc/ndn-tlv/types.html */
#define NDN_TYPE_NAME_COMPONENT 0x08 /* https://named-data.net/doc/ndn-tlv/types.html */
#define STRING_TO_MATCH "test"  /* { 0x74,0x65,0x73,0x74 }; */
#define STRING_TO_MATCH_LENGTH sizeof(STRING_TO_MATCH) - 1

#ifdef  DEBUG
/* Only use this for debug output. Notice output from  bpf_trace_printk() end-up in /sys/kernel/debug/tracing/trace_pipe */
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif


static __always_inline void recalc_ip_header_checksum(struct iphdr *ip_header) {
	u16 *next_iph_u16 = (u16 *)ip_header;
	ip_header->check = 0;
	u32 csum = 0;
#pragma clang loop unroll(full)
	for (size_t i = 0; i < sizeof(*ip_header) >> 1; i++) {
		csum += *next_iph_u16++;
	}
	ip_header->check = ~((csum & 0xffff) + (csum >> 16));
}

static __always_inline void adjust_ip_destination(struct iphdr *ip_header) {
	ip_header->daddr = ntohl(0x0a000a04); /* 10.0.10.4 TODO: Which ip to place here ? */
}

static __always_inline void adjust_mac_destination(struct ethhdr *ethernet_header, uint8_t destination_mac[ETH_ALEN]) {
#pragma clang loop unroll(full)
	for (size_t i = 0; i < ETH_ALEN; i++){
		ethernet_header->h_dest[i] = destination_mac[i];
	}
}

static __always_inline void perform_action(struct ethhdr *ethernet_header, struct iphdr *ip_header, struct  udphdr *udp_header) {
	uint8_t destination_mac[ETH_ALEN] = { 0x00, 0x15, 0x4d, 0x12, 0x20, 0xae }; /* TODO: Which MAC address should be used ?*/
	adjust_mac_destination(ethernet_header, destination_mac); /* 	dp.ofproto_parser.OFPActionSetField(eth_dst=router.mac) */
	adjust_ip_destination(ip_header); /* dp.ofproto_parser.OFPActionSetField(ipv4_dst=lpm_cl.ip), : lpm_cl = max(cls, key=lambda _cl: len(_cl.name))*/
	ip_header->ttl = TX_NEW_TTL; /* dp.ofproto_parser.OFPActionSetNwTtl(128) */
	udp_header->source = ntohs(UDP_TX_PORT); /* dp.ofproto_parser.OFPActionSetField(udp_src=6363) */
	udp_header->dest = ntohs(UDP_TX_PORT); /* dp.ofproto_parser.OFPActionSetField(udp_dst=6363) */
	/* 	dp.ofproto_parser.OFPActionOutput(port)]) - 	router = [router for router in self.routers if router.dpid == dpid][0] :port = router.port :: TODO: Is this outbound interface ? not yet possible with XDP */
	recalc_ip_header_checksum(ip_header);
}

static __always_inline int found_match(uint8_t payload_position, void *packet_end, uint8_t *data) {
	char match_string[] = STRING_TO_MATCH;
	bpf_debug("found match for string: %s \n", match_string);
	return TNO_XDP_MATCH;
}

static __always_inline uint8_t find_match(uint8_t payload_position, void *packet_end, uint8_t *data, uint32_t tlv_length) {
	uint8_t matches = 0;
#pragma clang loop unroll(full)
	for (size_t k = 0; (data + payload_position + 1 <= packet_end) && (k < STRING_TO_MATCH_LENGTH /* Create upper bound to prevent back-edge error*/ && k < tlv_length); k++) {
		if (data[payload_position] != STRING_TO_MATCH[k]) {
			break;
		}
		matches += 1;
		payload_position += 1;
	}
	return matches;
}

static __always_inline uint32_t tlv_length_offset(uint8_t *data, uint8_t payload_position, uint8_t amount_of_octets, void *packet_end) {
	uint8_t first_octet = data[payload_position++]; //get length and advance
	if (first_octet < 253) {
		return first_octet;
	}
	uint32_t length = 0;
#pragma clang loop unroll(full)
	for (size_t i = 0; (data + payload_position + 1 <= packet_end) && (i < MAX_OCTET_COUNT /* Create upper bound to prevent back-edge error*/ && i < amount_of_octets) ; i++) {
		length = length * 256 + (uint8_t ) data[payload_position++];
	}

	return length;
}

static __always_inline uint8_t tlv_amount_of_octets(uint8_t *data, uint8_t payload_position) {
	uint8_t first_octet = data[payload_position];
	uint8_t amount_of_octets = 1;

	if (first_octet<253)
		amount_of_octets = 1;
	else {
		//length encoded in following 2,4,or 8 octets
		switch (first_octet) {
			case 253:
				amount_of_octets = 2;
				break;
			case 254:
				amount_of_octets = 4;
				break;
			case 255:
				amount_of_octets = 8;
				break;
			}
		amount_of_octets++; //account for the fact that first octet plays now indication role
	}
	return amount_of_octets;
}

static __always_inline int ndn(void *packet, void *packet_end, uint16_t offset, uint8_t *data) {
	bpf_debug("\n\n\t\t Received NDN interest \n");
	/* NDN packet examples - https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/interest.t.cpp */
	/* Byte 0 of the pointer 'data' is the NDN-Type, so we start at 1*/
	uint8_t payload_position = 1;

	if (data + payload_position + 1 > packet_end) {
		return XDP_DROP;
	}

	uint16_t totallen;
	uint8_t tlv_octet_amount = tlv_amount_of_octets(data, payload_position);
	uint32_t tlv_length = tlv_length_offset(data, payload_position, tlv_octet_amount, packet_end);

	payload_position += tlv_octet_amount;

	bpf_debug("Offset is %d \n", offset);
	if (data + payload_position + 1 > packet_end) {
		return XDP_DROP;
	}

	uint8_t type_name = data[payload_position];

	if (type_name != NDN_TYPE_NAME){
		return XDP_PASS;
	}

	payload_position+=1;

	if (data + payload_position + 1 > packet_end) {
		return XDP_DROP;
	}

	tlv_octet_amount = tlv_amount_of_octets(data, payload_position);
	tlv_length = tlv_length_offset(data, payload_position, tlv_octet_amount, packet_end);

	payload_position += tlv_octet_amount;

	/* This for loop represents the while loop originally present in the icn_match file, due to verifier constraints it is not possible to loop more than 2 times */
	for (uint8_t i = 0; i < 2; i++)
	{
		if (data + payload_position + 1 > packet_end) {
			return XDP_DROP;
		}
		uint8_t type_name_component = data[payload_position];
		if (type_name_component != NDN_TYPE_NAME_COMPONENT) {
			return XDP_PASS;
		}

		payload_position += 1;

		if (data + payload_position + 1 > packet_end) {
			return XDP_DROP;
		}

		tlv_octet_amount = tlv_amount_of_octets(data, payload_position);
		tlv_length = tlv_length_offset(data, payload_position, tlv_octet_amount, packet_end);

		payload_position += tlv_octet_amount;

		uint8_t matches = find_match(payload_position, packet_end, data, tlv_length);

		if (matches == STRING_TO_MATCH_LENGTH) {
			return found_match(payload_position, packet_end, data);
		}
		bpf_debug("Was not a match - had %x matches \n", matches);
		payload_position += tlv_length;
	}

	return XDP_PASS;
}

SEC("xdp1")
int xdp_prog1(struct xdp_md *xdp)
{
	void *packet_end = (void *)(long)xdp->data_end;
	void *packet = (void *)(long)xdp->data;
	struct ethhdr *ethernet_header = packet;

	uint8_t ethernet_header_offset = sizeof(*ethernet_header);

	if (packet + ethernet_header_offset > packet_end) {
		return INVALID_PACKET_ACTION;
	}

	/* Pass packet along if it is not ipv4: https://en.wikipedia.org/wiki/EtherType*/
	if (htons(ethernet_header->h_proto) != IPV4_ETHERTYPE) {
		return XDP_PASS;
	}

	struct iphdr *ip_header = (struct iphdr*)(packet + ethernet_header_offset);

	/* Drop packets with an invalid IP header */
	if (ip_header + 1 > packet_end) {
		return INVALID_PACKET_ACTION;
	}

	/* https://stackoverflow.com/questions/6385792/what-does-a-bitwise-shift-left-or-right-do-and-what-is-it-used-for */
	/* the length of the header is defined by IHL, which describes how many data words are in the header. Each word is 4 bytes longs, and if IHL is 5, then we expect the header to be 160 bits (or 20 bytes) */
	uint8_t ip_header_length = ip_header->ihl * 4;
	if (ip_header->protocol == IPPROTO_IPIP /* http://elixir.free-electrons.com/linux/latest/ident/IPPROTO_IPIP */) {
		ip_header = packet + ethernet_header_offset + ip_header_length;
		if (ip_header + 1 > packet_end) {
			return INVALID_PACKET_ACTION;
		}
		ip_header_length = ip_header->ihl * 4;
	}

	/* Pass the packet along if it is not UDP*/
	if (ip_header->protocol != IPPROTO_UDP /* http://elixir.free-electrons.com/linux/latest/source/include/uapi/linux/in.h#L34 */) {
		return XDP_PASS;
	}

	struct udphdr *udp_header = (struct udphdr*)(packet + ethernet_header_offset + ip_header_length);

	if (udp_header + 1 > packet_end) {
		/* Drop packets with an invalid UDP header */
		return INVALID_PACKET_ACTION;
	}

	/* Pass along packets that are not destined for the targeted port */
	if (htons(udp_header->source) != UDP_TARGETED_PORT) {
		return XDP_PASS;
	}

	uint16_t udp_header_offset = ethernet_header_offset + ip_header_length + sizeof(struct udphdr);

	if (packet + udp_header_offset + 1 > packet_end) {
		/* Drop packets with no payload */
		return INVALID_PACKET_ACTION;
	}

	uint8_t *data = packet + udp_header_offset;
	uint8_t type_interest = data[0];

	/* Pass along all non-interest type packets */
	if (type_interest != NDN_TYPE_INTEREST) {
		bpf_debug("Was not interest - was %x \n", type_interest);
		return XDP_PASS;
	}

	/* Check first byte of UDP payload for NDN-Type */
	uint8_t result = ndn(packet, packet_end, udp_header_offset, data);
	if (result == TNO_XDP_MATCH) {
		bpf_debug("t'was a match \n");
		perform_action(ethernet_header, ip_header, udp_header);
		return XDP_TX;
	}

	return result;
}

char _license[] SEC("license") = "GPL";

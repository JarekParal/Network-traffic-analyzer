//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 11.11.2016.
//

#ifndef ISA_PROJECT_STRUCTURES_H
#define ISA_PROJECT_STRUCTURES_H

#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>

#include "convert.h"

// pcap file description
// Source for structure: pcap_glob_hdr_s, pcap_packet_hdr_s
// https://wiki.wireshark.org/Development/LibpcapFileFormat
typedef struct pcap_glob_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
    // suma = 6*32 bits = 192 bits = 24 bytes
} pcap_glob_hdr_t; //pcap_hdr_t;

typedef struct pcap_packet_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
    // suma = 32 * 4 bits = 128 bits = 16 bytes
} pcap_packet_hdr_t; //pcaprec_hdr_t;

// Ethernet header description
// Source (<netinet/in.h>)
// http://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html
// Documentation: https://wiki.wireshark.org/Ethernet
typedef struct ether_header_s {
    uint8_t	ether_dhost[6];
    uint8_t	ether_shost[6];
    uint16_t ether_type;
} ether_header_t;

#define	ETHERTYPE_PUP	0x0200		/* PUP protocol */
#define	ETHERTYPE_IP	0x0800		/* IP(v4) protocol */
#define ETHERTYPE_ARP	0x0806		/* Addr. resolution protocol (ARP) */
#define ETHERTYPE_IP6	0x08DD		/* IPv6 protocol */

const char ETHERTYPE_IP_STRING[] = "IPv4";
const char ETHERTYPE_IP6_STRING[] = "IPv6";
const char ETHERTYPE_ARP_STRING[] = "ARP";

void parsePcapGlobalHeader(pcap_glob_hdr_t& pcapGlobalHeader, char* buffer, int& pointer);
void printPcapGlobalHeader(pcap_glob_hdr_t & pcapGlobalHeader);

void parsePcapPacketHeader(pcap_packet_hdr_t& pcapPacketHeader, char* buffer, int& pointer);
void printPcapPacketHeader(pcap_packet_hdr_t & pcapPacketHeader);

void printMacAddr(uint8_t* etherMac);
const char* giveEtherTypeString(uint16_t etherType);
void printEtherType(uint16_t etherType);

void parseEthernetHeader(ether_header_t & etherHeader, char* buffer, int& pointer);
void printEthernetHeader(ether_header_t & etherHeader);

#endif //ISA_PROJECT_STRUCTURES_H

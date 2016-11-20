//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 11.11.2016.
//

#ifndef ISA_PROJECT_STRUCTURES_H
#define ISA_PROJECT_STRUCTURES_H

#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <string> // std::to_string
#include <sstream> // std::ostringstream



// Source: http://stackoverflow.com/a/4433027
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <winsock2.h>
#include <windows.h>
#else
// unix includes here
#include <sys/socket.h> /* socket specific definitions */
#include <netinet/in.h> /* INET constants and stuff */
#include <arpa/inet.h> /* IP address conversion stuff */
#endif

#include "convert.h"


// ----- IP - ipNextHeaderProtocol
enum ipNextHeaderProtocol {
    TCP = 0x06, /* Transmission Control Protocol */
    UDP = 0x11, /* User Datagram Protocol */
    unk = 0xFF  /* unknown - my internal type */
};


// ----- TCP/UDP
typedef struct tcp_udp_header_s {
    uint16_t dst_port;
    uint16_t src_port;
    uint8_t data_offset;
    uint16_t length;
    ipNextHeaderProtocol tcp_udp;
} tcp_udp_header_t;


// ----- IP header
enum ipVersion {
    v4 = 4,
    v6 = 6
};

const char IPPROT_TCP_STRING[] = "TCP";
const char IPPROT_UDP_STRING[] = "UDP";
const char IPPROT_UNKNOWN[] = "Unknown";

typedef struct ip_header_s {
    ipVersion version; // = uint8_t
    uint8_t header_length;
    uint16_t total_length;
    uint16_t payload_length;
    uint16_t nextHeader_length;

    ipNextHeaderProtocol nextHeader_protocol; // = uint8_t
    uint8_t	v4_dst[4];
    uint8_t	v4_src[4];
    uint16_t v6_dst[8];
    uint16_t v6_src[8];

    tcp_udp_header_t tcpUdpHeader;
} ip_header_t;


// ----- Ethernet
enum class etherTypeEnum {
    PUP = 0x0200,		/* PUP protocol */
    IP  = 0x0800,		/* IP(v4) protocol */
    ARP = 0x0806,		/* Addr. resolution protocol (ARP) */
    IP6 = 0x08DD,		/* IPv6 protocol */
    e8021Q =  0x0810,	/* 802.1Q tag (optional) */
    unk = 0x0001        /* unknown - my internal type */
    //TODO: Check if "unk" work correctly!
};

const char ETHERTYPE_IP_STRING[] = "IPv4";
const char ETHERTYPE_IP6_STRING[] = "IPv6";
const char ETHERTYPE_ARP_STRING[] = "ARP";
const char ETHERTYPE_UNKNOWN_STRING[] = "Unknown";

// Ethernet struct
// Source (<netinet/in.h>)
// http://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html
// Documentation: https://wiki.wireshark.org/Ethernet
typedef struct ether_header_s {
    uint8_t	ether_dhost[6];
    uint8_t	ether_shost[6];
    etherTypeEnum ether_type; // = uint16_t
    bool vlan802_1Q;

    ip_header_t ipHeader;
} ether_header_t;


// ----- Pcap
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

    ether_header_t etherHeader;
} pcap_packet_hdr_t; //pcaprec_hdr_t;


void printDecAndHex(int num);
std::string decAndHexStr(int num);

void pcapGlobalHeaderParse(pcap_glob_hdr_t& pcapGlobalHeader, char* buffer, int& pointer);
void pcapGlobalHeaderPrint(pcap_glob_hdr_t& pcapGlobalHeader);

void pcapPacketHeaderParse(pcap_packet_hdr_t& pcapPacketHeader, char* buffer, int& pointer);
void pcapPacketHeaderPrint(pcap_packet_hdr_t& pcapPacketHeader);

void macAddrPrint(uint8_t* etherMac, bool printLine = true);
const char* etherTypeGiveString(etherTypeEnum etherType);
void etherTypePrint(etherTypeEnum etherType);
bool etherTypeIsDefine(etherTypeEnum etherType);

int ethernetHeaderParse(pcap_packet_hdr_t& packetHeader, char* buffer, int& pointer);
void ethernetHeaderPrint(ether_header_t& etherHeader);

int ipHeaderParse(pcap_packet_hdr_t& packetHeader, char* buffer, int& pointer);
void ipHeaderPrint(ip_header_t& ipHeader);
void ipAddrPrint(uint8_t* ipAddr, bool printLine = true, bool numAlignment = false);
void ipAddrPrint(uint16_t* ipAddr, bool printLine = true);
const char* ipNextHeaderProtocolGiveString(ipNextHeaderProtocol nextHeaderProtocol);

int tcpUdpHeaderParse(pcap_packet_hdr_t& packetHeader, char* buffer, int& pointer);
void tcpUdpPrint(tcp_udp_header_t& tcpUdpHeader);

void packetPrint(pcap_packet_hdr_t& packetHeader, int packetNumber, int transferDataSizeByte);

#endif //ISA_PROJECT_STRUCTURES_H

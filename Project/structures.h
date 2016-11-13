//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 11.11.2016.
//

#ifndef ISA_PROJECT_STRUCTURES_H
#define ISA_PROJECT_STRUCTURES_H

#include <cstdint>
#include <iostream>

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


void readPcapGlobalHeader(pcap_glob_hdr_t & pcapGlobalHeader, char * buffer, int & pointer);
void printPcapGlobalHeader(pcap_glob_hdr_t & pcapGlobalHeader);
void readPcapPacketHeader(pcap_packet_hdr_t & pcapPacketHeader, char * buffer, int & pointer);
void printPcapPacketHeader(pcap_packet_hdr_t & pcapPacketHeader);

#endif //ISA_PROJECT_STRUCTURES_H

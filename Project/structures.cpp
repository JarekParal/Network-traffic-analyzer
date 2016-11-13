//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 13.11.2016.
//


#include "structures.h"

using std::cout;
using std::endl;

void readPcapGlobalHeader(pcap_glob_hdr_t & pcapGlobalHeader, char * buffer, int & pointer)
{
    pcapGlobalHeader.magic_number = toUint32(buffer, pointer);
    pcapGlobalHeader.version_major = toUint16(buffer, pointer);
    pcapGlobalHeader.version_minor = toUint16(buffer, pointer);
    pcapGlobalHeader.thiszone = toInt32(buffer, pointer);
    pcapGlobalHeader.sigfigs = toUint32(buffer, pointer);
    pcapGlobalHeader.snaplen = toUint32(buffer, pointer);
    pcapGlobalHeader.network = toUint32(buffer, pointer);
}

void printPcapGlobalHeader(pcap_glob_hdr_t & pcapGlobalHeader)
{
    cout << std::dec << pcapGlobalHeader.magic_number << " (" << std::hex
         << pcapGlobalHeader.magic_number << ")" << endl;
    cout << std::dec << pcapGlobalHeader.version_major << " (" << std::hex
         << pcapGlobalHeader.version_major << ")" << endl;
    cout << std::dec << pcapGlobalHeader.version_minor << " (" << std::hex
         << pcapGlobalHeader.version_minor << ")" << endl;
    cout << std::dec << pcapGlobalHeader.thiszone << " (" << std::hex
         << pcapGlobalHeader.thiszone << ")" << endl;
    cout << std::dec << pcapGlobalHeader.sigfigs << " (" << std::hex
         << pcapGlobalHeader.sigfigs << ")" << endl;
    cout << std::dec << pcapGlobalHeader.snaplen << " (" << std::hex
         << pcapGlobalHeader.snaplen << ")" << endl;
    cout << std::dec << pcapGlobalHeader.network << " (" << std::hex
         << pcapGlobalHeader.network << ")" << endl;
}

void readPcapPacketHeader(pcap_packet_hdr_t & pcapPacketHeader, char * buffer, int & pointer)
{
    pcapPacketHeader.ts_sec = toUint32(buffer, pointer);
    pcapPacketHeader.ts_usec = toUint32(buffer, pointer);
    pcapPacketHeader.incl_len = toUint32(buffer, pointer);
    pcapPacketHeader.orig_len = toUint32(buffer, pointer);
}

void printPcapPacketHeader(pcap_packet_hdr_t & pcapPacketHeader)
{
    cout << "Epoch time: " << std::dec
         << pcapPacketHeader.ts_sec << "."
         << pcapPacketHeader.ts_usec << endl;
    cout << "Epoch time (hex): " << std::hex
         << pcapPacketHeader.ts_sec << "."
         << pcapPacketHeader.ts_usec << std::dec << endl;
    cout << "Frame number: "
         << pcapPacketHeader.incl_len
         << " (" << std::hex << pcapPacketHeader.incl_len << ")" << std::dec << endl;
    cout << "Frame number: "
         << pcapPacketHeader.orig_len
         << " (" << std::hex << pcapPacketHeader.orig_len << ")" << std::dec << endl;
}
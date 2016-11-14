//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 13.11.2016.
//

#include "structures.h"

using std::cout;
using std::endl;
using std::setw;
using std::setfill;

void parsePcapGlobalHeader(pcap_glob_hdr_t& pcapGlobalHeader, char* buffer, int& pointer) {
    pcapGlobalHeader.magic_number = toUint32(buffer, pointer);
    pcapGlobalHeader.version_major = toUint16(buffer, pointer);
    pcapGlobalHeader.version_minor = toUint16(buffer, pointer);
    pcapGlobalHeader.thiszone = toInt32(buffer, pointer);
    pcapGlobalHeader.sigfigs = toUint32(buffer, pointer);
    pcapGlobalHeader.snaplen = toUint32(buffer, pointer);
    pcapGlobalHeader.network = toUint32(buffer, pointer);
}

void printPcapGlobalHeader(pcap_glob_hdr_t & pcapGlobalHeader) {
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

void parsePcapPacketHeader(pcap_packet_hdr_t& pcapPacketHeader, char* buffer, int& pointer) {
    pcapPacketHeader.ts_sec = toUint32(buffer, pointer);
    pcapPacketHeader.ts_usec = toUint32(buffer, pointer);
    pcapPacketHeader.incl_len = toUint32(buffer, pointer);
    pcapPacketHeader.orig_len = toUint32(buffer, pointer);
}

void printPcapPacketHeader(pcap_packet_hdr_t & pcapPacketHeader) {
    cout << "Epoch time: " << std::dec
         << pcapPacketHeader.ts_sec << "."
         << pcapPacketHeader.ts_usec << endl;
    cout << "Epoch time (hex): " << std::hex
         << pcapPacketHeader.ts_sec << "."
         << pcapPacketHeader.ts_usec << std::dec << endl;
    cout << "Frame Length: "
         << pcapPacketHeader.incl_len
         << " (" << std::hex << setw(8) << setfill('0') << pcapPacketHeader.incl_len << ")"
         << std::dec << endl;
    cout << "Capture Length: "
         << pcapPacketHeader.orig_len
         << " (" << std::hex << setw(8) << setfill('0') << pcapPacketHeader.orig_len << ")"
         << std::dec << endl;
}

void printMacAddr(uint8_t* etherMac) {
    for(int i = 0; i < 6; i++){
        cout << std::hex << setw(2) << setfill('0') << static_cast<int>(etherMac[i]);

        if(i != 5)
            cout << ":";
        else
            cout << std::dec << endl;
    }
}

const char* giveEtherTypeString(uint16_t etherType) {
    switch(etherType) {
        case ETHERTYPE_IP:
            return ETHERTYPE_IP_STRING;
        case ETHERTYPE_IP6:
            return ETHERTYPE_IP6_STRING;
        case ETHERTYPE_ARP:
            return ETHERTYPE_ARP_STRING;
    }
}

void printEtherType(uint16_t etherType) {
    switch(etherType) {
        case ETHERTYPE_IP:
            cout << ETHERTYPE_IP_STRING;
            break;
        case ETHERTYPE_IP6:
            cout << ETHERTYPE_IP6_STRING;
            break;
        case ETHERTYPE_ARP:
            cout << ETHERTYPE_ARP_STRING;
            break;
    }
}

void parseEthernetHeader(ether_header_t& etherHeader, char* buffer, int& pointer) {
    memcpy(etherHeader.ether_dhost, buffer + pointer, 6);
    pointer += 6;
    memcpy(etherHeader.ether_shost, buffer + pointer, 6);
    pointer += 6;
    etherHeader.ether_type = toUint16(buffer, pointer);
//    // TODO: Doesn't work right - check why
//    memcpy(etherHeader.ether_shost, buffer + pointer, 6);
//    pointer += 6;
}

void printEthernetHeader(ether_header_t& etherHeader) {
    cout << "Dst: ";
    printMacAddr(etherHeader.ether_dhost);

    cout << "Src: ";
    printMacAddr(etherHeader.ether_shost);

    cout << "Type: "
         << etherHeader.ether_type
         << " (" << std::hex << setw(4) << setfill('0')
         << etherHeader.ether_type << ") => " << std::dec
         << giveEtherTypeString(etherHeader.ether_type) << endl;
}

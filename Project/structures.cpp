//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 13.11.2016.
//

#include "structures.h"

using std::cout;
using std::cerr;
using std::endl;
using std::setw;
using std::setfill;

void pcapGlobalHeaderParse(pcap_glob_hdr_t& pcapGlobalHeader, char* buffer, int& pointer) {
    pcapGlobalHeader.magic_number = toUint32(buffer, pointer);
    pcapGlobalHeader.version_major = toUint16(buffer, pointer);
    pcapGlobalHeader.version_minor = toUint16(buffer, pointer);
    pcapGlobalHeader.thiszone = toInt32(buffer, pointer);
    pcapGlobalHeader.sigfigs = toUint32(buffer, pointer);
    pcapGlobalHeader.snaplen = toUint32(buffer, pointer);
    pcapGlobalHeader.network = toUint32(buffer, pointer);
}

void pcapGlobalHeaderPrint(pcap_glob_hdr_t& pcapGlobalHeader) {
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

void pcapPacketHeaderParse(pcap_packet_hdr_t& pcapPacketHeader, char* buffer, int& pointer) {
    pcapPacketHeader.ts_sec = toUint32(buffer, pointer);
    pcapPacketHeader.ts_usec = toUint32(buffer, pointer);
    pcapPacketHeader.incl_len = toUint32(buffer, pointer);
    pcapPacketHeader.orig_len = toUint32(buffer, pointer);
}

void pcapPacketHeaderPrint(pcap_packet_hdr_t& pcapPacketHeader) {
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

void macAddrPrint(uint8_t* etherMac) {
    for(int i = 0; i < 6; i++){
        cout << std::hex << setw(2) << setfill('0') << static_cast<int>(etherMac[i]);

        if(i != 5)
            cout << ":";
        else
            cout << std::dec << endl;
    }
}

const char* etherTypeGiveString(etherTypeEnum etherType) {
    switch(etherType) {
        case etherTypeEnum::IP:
            return ETHERTYPE_IP_STRING;
        case etherTypeEnum::IP6:
            return ETHERTYPE_IP6_STRING;
        case etherTypeEnum::ARP:
            return ETHERTYPE_ARP_STRING;
        default:
            return ETHERTYPE_UNKNOWN_STRING;
    }
}

void etherTypePrint(etherTypeEnum etherType) {
    switch(etherType) {
        case etherTypeEnum::IP:
            cout << ETHERTYPE_IP_STRING;
            break;
        case etherTypeEnum::IP6:
            cout << ETHERTYPE_IP6_STRING;
            break;
        case etherTypeEnum::ARP:
            cout << ETHERTYPE_ARP_STRING;
            break;
        default:
            cout << ETHERTYPE_UNKNOWN_STRING;
            break;

    }
}

bool etherTypeIsDefine(etherTypeEnum etherType) {
    return static_cast<int>(etherType) >= 0x0600;
}

int ethernetHeaderParse(ether_header_t& etherHeader, char* buffer, int& pointer) {
    int pointerStartValue = pointer;

    memcpy(etherHeader.ether_dhost, buffer + pointer, 6);
    pointer += 6;
    memcpy(etherHeader.ether_shost, buffer + pointer, 6);
    pointer += 6;
    etherHeader.ether_type = static_cast<etherTypeEnum>(toUint16(buffer, pointer));

    if(etherHeader.ether_type == etherTypeEnum::e8021Q) {
        etherHeader.vlan802_1Q = true;
        pointer += 2;
        etherHeader.ether_type = static_cast<etherTypeEnum>(toUint16(buffer, pointer));
    } else {
        etherHeader.vlan802_1Q = false;
    }

    return pointer - pointerStartValue;

//    // TODO: Doesn't work right - check why
//    memcpy(etherHeader.ether_type, buffer + pointer, 2);
//    pointer += 2;
}

void ethernetHeaderPrint(ether_header_t& etherHeader) {
    cout << "Dst: ";
    macAddrPrint(etherHeader.ether_dhost);

    cout << "Src: ";
    macAddrPrint(etherHeader.ether_shost);

    cout << "Type: "
         << static_cast<int>(etherHeader.ether_type)
         << " (" << std::hex << setw(4) << setfill('0')
         << static_cast<int>(etherHeader.ether_type) << ") => " << std::dec
         << etherTypeGiveString(etherHeader.ether_type) << endl;
}

int ipHeaderParse(ip_header_t& ipHeader, char* buffer, int& pointer) {
    int pointerStartValue = pointer;

    uint8_t version_IHL = toUint8(buffer, pointer);
    ipHeader.version = static_cast<ipVersion>((version_IHL & 0xF0) >> 4);
    ipHeader.header_length = static_cast<uint8_t>((version_IHL & 0x0F));

    if(ipHeader.version == ipVersion::v4) {
        pointer += 1; // jump to total length
        ipHeader.total_length = toUint16(buffer, pointer);
        pointer += 5;
        ipHeader.nextHeader_protocol
                = static_cast<ipNextHeaderProtocol>(toUint8(buffer, pointer));
        pointer += 2;

        memcpy(ipHeader.v4_dst, buffer + pointer, 4);
        pointer += 4;
        memcpy(ipHeader.v4_src, buffer + pointer, 4);
        pointer += 4;

        if(ipHeader.header_length > 5)
            pointer += ipHeader.header_length - 5;
    }
    else if(ipHeader.version == ipVersion::v6) {
        pointer += 3; // jump to payload length
        ipHeader.payload_length = toUint16(buffer, pointer);
        ipHeader.nextHeader_protocol
                = static_cast<ipNextHeaderProtocol>(toUint8(buffer, pointer));
        pointer += 1;

        memcpy(ipHeader.v6_dst, buffer + pointer, 8);
        pointer += 8;
        memcpy(ipHeader.v6_src, buffer + pointer, 8);
        pointer += 8;
    }
    else
        return 0; // error

    return pointer - pointerStartValue;
}

void ipAddrPrint(uint8_t* ipAddr) {
    for(int i = 0; i < 4; i++){
        cout << static_cast<int>(ipAddr[i]);

        if(i != 3)
            cout << ".";
        else
            cout << endl;
    }
}

void ipAddrPrint(uint16_t* ipAddr) {
    for(int i = 0; i < 8; i++){
        cout << std::hex << setw(2) << setfill('0') << static_cast<uint16_t>(ipAddr[i]);

        if(i != 5)
            cout << ":";
        else
            cout << std::dec << endl;
    }
}

const char* ipNextHeaderProtocolGiveString(ipNextHeaderProtocol nextHeaderProtocol) {
    switch(nextHeaderProtocol) {
        case ipNextHeaderProtocol::TCP:
            return IPPROT_TCP_STRING;
        case ipNextHeaderProtocol::UDP:
            return IPPROT_UDP_STRING;
        default:
            return IPPROT_UNKNOWN;
    }
}

void ipHeaderPrint(ip_header_t& ipHeader) {
    cout << "Version: " << ipHeader.version << endl;

    if (ipHeader.version == ipVersion::v4) {
        cout << "Header length: " << static_cast<int>(ipHeader.header_length) << endl;
        cout << "Total length: " << ipHeader.total_length << endl;
        cout << "Next header/protocol: "
             << ipNextHeaderProtocolGiveString(ipHeader.nextHeader_protocol) << endl;

        cout << "Dst: ";
        ipAddrPrint(ipHeader.v4_dst);
        cout << "Src: ";
        ipAddrPrint(ipHeader.v4_src);
    } else if (ipHeader.version == ipVersion::v6) {
        cout << "Header length: " << static_cast<int>(ipHeader.payload_length) << endl;
        cout << "Next header/protocol: "
             << ipNextHeaderProtocolGiveString(ipHeader.nextHeader_protocol) << endl;

        cout << "Dst: ";
        ipAddrPrint(ipHeader.v6_dst);
        cout << "Src: ";
        ipAddrPrint(ipHeader.v6_src);
    } else
        cerr << "Error: IP header - unknown version: " << ipHeader.version << endl;
}


//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 13.11.2016.
//
#include "packet.h"

int inet_pton_patch() {
#ifdef _WIN32
    //InetPton()
    //https://msdn.microsoft.com/en-us/library/cc805844(v=vs.85).aspx
    //http://stackoverflow.com/questions/15660203/inet-pton-identifier-not-found
    //https://memset.wordpress.com/2010/10/09/inet_ntop-for-win32/
    //https://www.ipv6.cz/Inetpton()
    //http://stackoverflow.com/questions/17379741/issues-when-using-wsaaddresstostring
#else
    if (inet_pton(AF_INET6, ip6str, &result) == 1) // success!
    {
        //successfully parsed string into "result"
    }
    else
    {
        //failed, perhaps not a valid representation of IPv6?
    }
#endif
}

// Source stdPatch: http://stackoverflow.com/a/20861692
namespace stdPatch
{
    template < typename T > std::string to_string( const T& n , bool hex = false)
    {
        std::ostringstream stm ;
        if(hex)
            stm << std::hex;
        stm << n ;
        return stm.str() ;
    }
}

void printDecAndHex(int num) {
    cout << num << " (0x" << std::hex
         << num << ")"  << std::dec;
}

string decAndHexStr(int num) {
    return stdPatch::to_string(num) + string(" (0x") + stdPatch::to_string(num, true) + string(")");
}

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
    cout << "Magic number: " << decAndHexStr(pcapGlobalHeader.magic_number) << endl;
    cout << "Major version: " << decAndHexStr(pcapGlobalHeader.version_major) << endl;
    cout << "Minor version: " << decAndHexStr(pcapGlobalHeader.version_minor) << endl;
    cout << "GMT to local correction: " << decAndHexStr(pcapGlobalHeader.thiszone) << endl;
    cout << "Accuracy of timestamps: " << decAndHexStr(pcapGlobalHeader.sigfigs)  << endl;
    cout << "Max length of captured packets, in octets: " << decAndHexStr(pcapGlobalHeader.snaplen) << endl;
    cout << "Data link type: " << decAndHexStr(pcapGlobalHeader.network) << endl;
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
         << " (0x" << std::hex << setw(8) << setfill('0') << pcapPacketHeader.incl_len << ")"
         << std::dec << endl;
    cout << "Capture Length: "
         << pcapPacketHeader.orig_len
         << " (0x" << std::hex << setw(8) << setfill('0') << pcapPacketHeader.orig_len << ")"
         << std::dec << endl;
}

void macAddrPrint(uint8_t* etherMac, bool printLine) {
    for(int i = 0; i < 6; i++){
        cout << std::hex << setw(2) << setfill('0') << static_cast<int>(etherMac[i]);

        if(i != 5)
            cout << ":";
        else {
            cout << std::dec;
            if(printLine)
                cout << endl;
        }
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

int ethernetHeaderParse(pcap_packet_hdr_t& packetHeader, char* buffer, int& pointer) {
    ether_header_t& etherHeader = packetHeader.etherHeader;

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

    etherHeader.size = pointer - pointerStartValue;
    return etherHeader.size;

//    // TODO: Doesn't work right - check why
//    memcpy(etherHeader.ether_type, buffer + pointer, 2);
//    pointer += 2;
}

void ethernetHeaderPrint(ether_header_t& etherHeader) {
    cout << "Src: ";
    macAddrPrint(etherHeader.ether_shost);

    cout << "Dst: ";
    macAddrPrint(etherHeader.ether_dhost);

    cout << "Type: "
         << static_cast<int>(etherHeader.ether_type)
         << " (0x" << std::hex << setw(4) << setfill('0')
         << static_cast<int>(etherHeader.ether_type) << ") => " << std::dec
         << etherTypeGiveString(etherHeader.ether_type) << endl;
}

const int ipHeader_header_length_minValueByte = 20; // IHL - Internet Header Length
// https://en.wikipedia.org/wiki/IPv4#Packet_structure#IHL

int ipHeaderParse(pcap_packet_hdr_t& packetHeader, char* buffer, int& pointer) {
    ip_header_t & ipHeader = packetHeader.etherHeader.ipHeader;
    int pointerStartValue = pointer;

    uint8_t version_IHL = toUint8(buffer, pointer);
    ipHeader.version = static_cast<ipVersion>((version_IHL & 0xF0) >> 4);
    ipHeader.header_length = static_cast<uint8_t>((version_IHL & 0x0F)*4); // *4 => convert to byte

    if(ipHeader.version == ipVersion::v4) {
        pointer += 1; // jump to total length
        ipHeader.total_length = toUint16(buffer, pointer);

        if((packetHeader.orig_len - packetHeader.etherHeader.size) < ipHeader.total_length) {
//            cerr << "IP packet wrong: ipHeader.total_length > packetHeader.orig_len - packetHeader.etherHeader.size" << endl;
//            cerr << "ipHeader.total_length: " << ipHeader.total_length << endl;
//            cerr << "packetHeader.orig_len: " << packetHeader.orig_len << endl;
//            cerr << "packetHeader.etherHeader.size: " << packetHeader.etherHeader.size << endl;
//            cerr << "packetHeader.orig_len - packetHeader.etherHeader.size: " << packetHeader.orig_len - packetHeader.etherHeader.size << endl;
//            return 0;
            ipHeader.nextHeader_length = (packetHeader.orig_len - packetHeader.etherHeader.size) - ipHeader.header_length;
        }
        else
            ipHeader.nextHeader_length = ipHeader.total_length - ipHeader.header_length;

        pointer += 5;
        ipHeader.nextHeader_protocol
                = static_cast<ipNextHeaderProtocol>(toUint8(buffer, pointer));
        pointer += 2;

        memcpy(ipHeader.v4_src, buffer + pointer, 4);
        pointer += 4;
        memcpy(ipHeader.v4_dst, buffer + pointer, 4);
        pointer += 4;

        if(ipHeader.header_length > ipHeader_header_length_minValueByte)
            pointer += ipHeader.header_length - ipHeader_header_length_minValueByte;
    }
    else if(ipHeader.version == ipVersion::v6) {
        pointer += 3; // jump to payload length
        ipHeader.payload_length = toUint16(buffer, pointer);
        ipHeader.nextHeader_length = ipHeader.payload_length;
        ipHeader.nextHeader_protocol
                = static_cast<ipNextHeaderProtocol>(toUint8(buffer, pointer));
        pointer += 1;

        for(int i = 0; i < 8; ++i) {
            ipHeader.v6_src[i] = toUint16(buffer,pointer);
        }
        for(int i = 0; i < 8; ++i) {
            ipHeader.v6_dst[i] = toUint16(buffer,pointer);
        }
    }
    else
        return 0; // error

    ipHeader.size = pointer - pointerStartValue;
    return ipHeader.size;
}

void ipAddrPrint(uint8_t* ipAddr, bool printLine, bool numAlignment) {
    for(int i = 0; i < 4; i++){
        if(numAlignment)
            cout << setw(3) << setfill(' ');
        cout << static_cast<int>(ipAddr[i]);

        if(i != 3)
            cout << ".";
        else {
            if(printLine) {
                cout << endl;
            }
        }
    }
}

void ipAddrPrint(uint16_t* ipAddr, bool printLine) {
    for(int i = 0; i < 8; i++){
        cout << std::hex << setw(2) << setfill('0') << static_cast<uint16_t>(ipAddr[i]);

        if(i != 7)
            cout << ":";
        else {
            if(printLine) {
                cout << endl;
            }
            cout << std::dec;
        }
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
        cout << "Header length (byte): " << static_cast<int>(ipHeader.header_length) << endl;
        cout << "Total length (byte): " << ipHeader.total_length << endl;
        cout << "Next header length: " << decAndHexStr(ipHeader.nextHeader_length) << endl;
        cout << "Next header/protocol: "
             << ipNextHeaderProtocolGiveString(ipHeader.nextHeader_protocol) << endl;

        cout << "Src: ";
        ipAddrPrint(ipHeader.v4_src);
        cout << "Dst: ";
        ipAddrPrint(ipHeader.v4_dst);
    } else if (ipHeader.version == ipVersion::v6) {
        cout << "Header length: " << static_cast<int>(ipHeader.payload_length) << endl;
        cout << "Next header/protocol: "
             << ipNextHeaderProtocolGiveString(ipHeader.nextHeader_protocol) << endl;

        cout << "Src: ";
        ipAddrPrint(ipHeader.v6_src);
        cout << "Dst: ";
        ipAddrPrint(ipHeader.v6_dst);
    } else
        cerr << "Error: IP header - unknown version: " << ipHeader.version << endl;
}

int tcpUdpHeaderParse(pcap_packet_hdr_t& packetHeader, char* buffer, int& pointer) {
    tcp_udp_header_t & tcpUdpHeader = packetHeader.etherHeader.ipHeader.tcpUdpHeader;

    int pointerStartValue = pointer;

    tcpUdpHeader.src_port = toUint16(buffer,pointer);
    tcpUdpHeader.dst_port = toUint16(buffer,pointer);

    if(packetHeader.etherHeader.ipHeader.nextHeader_protocol == ipNextHeaderProtocol::TCP) {
        pointer += 8; // jump to data offser
        tcpUdpHeader.data_offset = static_cast<uint8_t>(((toUint8(buffer,pointer) & 0xF0) >> 4) * 4);
        //https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
        tcpUdpHeader.tcp_udp = ipNextHeaderProtocol::TCP;
        //return tcpUdpHeader.data_offset;
    } else if (packetHeader.etherHeader.ipHeader.nextHeader_protocol == ipNextHeaderProtocol::UDP) {
        tcpUdpHeader.length = toUint16(buffer,pointer);
        tcpUdpHeader.tcp_udp = ipNextHeaderProtocol::UDP;
    }
    else
        return 0; // error

    //TODO: ethernet padding // https://www.facebook.com/groups/fitbit2014/permalink/933249876779199/?comment_id=933253073445546&reply_comment_id=933346823436171&comment_tracking=%7B%22tn%22%3A%22R%22%7D
    if((packetHeader.etherHeader.ipHeader.nextHeader_length + packetHeader.etherHeader.size + packetHeader.etherHeader.ipHeader.size)
       < packetHeader.orig_len)
        return packetHeader.orig_len - packetHeader.etherHeader.size - packetHeader.etherHeader.ipHeader.size;
    else
        return packetHeader.etherHeader.ipHeader.nextHeader_length; //pointer - pointerStartValue;
}

void tcpUdpPrint(tcp_udp_header_t& tcpUdpHeader) {
    cout << "Src: " << tcpUdpHeader.src_port << endl;
    cout << "Dst: " << tcpUdpHeader.dst_port << endl;

    if(tcpUdpHeader.tcp_udp == ipNextHeaderProtocol::TCP) {
        cout << "Header length: " << decAndHexStr(static_cast<int>(tcpUdpHeader.data_offset)) << endl;
    } else if (tcpUdpHeader.tcp_udp == ipNextHeaderProtocol::UDP) {
        cout << "Header length: " << decAndHexStr(static_cast<int>(tcpUdpHeader.length)) << endl;
    } else
        cerr << "Error: TCP/UDP header - unknown version: " << tcpUdpHeader.tcp_udp << endl;
}

void packetPrint(pcap_packet_hdr_t& packetHeader, int packetNumber, int transferDataSizeByte) {
    ether_header_t & etherHeader = packetHeader.etherHeader;
    ip_header_t & ipHeader = packetHeader.etherHeader.ipHeader;
    tcp_udp_header_t & tcpUdpHeader = packetHeader.etherHeader.ipHeader.tcpUdpHeader;

    cout << setw(4) << setfill(' ') <<  packetNumber << ": ";
    macAddrPrint(etherHeader.ether_shost, false);
    cout << " -> ";
    macAddrPrint(etherHeader.ether_dhost, false);
    cout << "  ";

    if(ipHeader.version == ipVersion::v4) {
        ipAddrPrint(ipHeader.v4_src, false, true);
        cout << "  -> ";
        ipAddrPrint(ipHeader.v4_dst, false, true);
    }
    else if(ipHeader.version == ipVersion::v6) {
        ipAddrPrint(ipHeader.v6_src, false);
        cout << "  -> ";
        ipAddrPrint(ipHeader.v6_dst, false);
    }
    cout << "   " << ipNextHeaderProtocolGiveString(ipHeader.nextHeader_protocol);
    cout << "   ";

    cout << setw(4) << setfill(' ') << transferDataSizeByte;
    cout << "   ";

    cout << tcpUdpHeader.src_port << " -> " << tcpUdpHeader.dst_port;
    cout << endl;
}
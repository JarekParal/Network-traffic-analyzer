//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 14.11.2016.
//

#include "filter.h"
#include "packet.h"

void testFilter() {
    cout << " ----- Filter test" << endl;

    filter_t filter;
    filterTypeEnum testFilerType1 = filterTypeEnum::ipv4;
    filter.type.push_back(testFilerType1);


    mac_addr_t testMac1 = {0,0,0,0,0,1};
    mac_addr_t testMac2 = {0,0,0,0,0,2};
    mac_addr_t testMac3 = {0,0,0,0,0,1};

    macAddrPrint(testMac1.addr_bytes);
    filter.mac.push_back(testMac2);
    filter.mac.push_back(testMac3);
    macAddrPrint(filter.mac.at(0).addr_bytes);
    macAddrEqualPrint(testMac1.addr_bytes, filter.mac.at(0).addr_bytes);
    //cout << "macsAddrsCompare: " << vectorCompare(testMac1.addr_bytes, filter.mac) << endl;
    cout << "macsAddrsCompare: " << macsAddrsCompare(testMac1.addr_bytes, filter.mac) << endl;

    ipv4_addr_t testIPv4_1 = {10,10,10,2};
    ipv4_addr_t testIPv4_2 = {10,10,10,3};
    ipv4_addr_t testIPv4_3 = {10,10,10,3};

    ipAddrPrint(testIPv4_1.addr_bytes);
    filter.ipv4.push_back(testIPv4_2);
    filter.ipv4.push_back(testIPv4_3);
    ipAddrPrint(filter.ipv4.at(0).addr_bytes);
    ipAddrEqualPrint(testIPv4_1.addr_bytes, filter.ipv4.at(0).addr_bytes);
    //cout << "ipv4AddrsCompare: " << vectorCompare(testIPv4_1.addr_bytes, filter.ipv4) << endl;
    cout << "ipv4sAddrsCompare: " << ipsAddrsCompare(testIPv4_1.addr_bytes, filter.ipv4) << endl;

    ipv6_addr_t testIPv6_1 = {0xfd00,00,00,00,00,00,00,04};
    ipv6_addr_t testIPv6_2 = {0xfd00,00,00,00,00,00,00,05};
    ipv6_addr_t testIPv6_3 = {0xfd00,00,00,00,00,00,00,04};

    ipAddrPrint(testIPv6_1.addr_bytes);
    filter.ipv6.push_back(testIPv6_2);
    filter.ipv6.push_back(testIPv6_3);
    ipAddrPrint(filter.ipv6.at(0).addr_bytes);
    ipAddrEqualPrint(testIPv6_1.addr_bytes, filter.ipv6.at(0).addr_bytes);
    //cout << "ipv6AddrsCompare: " << vectorCompare(testIPv6_1.addr_bytes, filter.ipv6) << endl;
    cout << "ipv6sAddrsCompare: " << ipsAddrsCompare(testIPv6_1.addr_bytes, filter.ipv6) << endl;

    uint16_t testPort1 = 107;
    uint16_t testPort2 = 100;
    uint16_t testPort3 = 101;

    cout << testPort1 << endl << testPort2 << endl;
    filter.port.push_back(testPort2);
    filter.port.push_back(testPort3);
    portEqualPrint(testPort1, testPort2);
    cout << "portsCompare: " << portsCompare(testPort1, filter.port) << endl;

    cout << endl << endl;
}

void filterSimpleIpv4InitD(filter_t & filter) {
    filterTypeEnum testFilerType1 = filterTypeEnum::ipv4;
    filter.type.push_back(testFilerType1);

    ipv4_addr_t testIPv4_1 = {10,10,10,60};
    filter.ipv4.push_back(testIPv4_1);

    filter.applySrc = false;
    filter.applyDst = true;

    // resutl: 1132 860
}

void filterSimpleIpv4InitSD(filter_t & filter) {
    filterTypeEnum testFilerType1 = filterTypeEnum::ipv4;
    filter.type.push_back(testFilerType1);

    ipv4_addr_t testIPv4_1 = {10,10,10,100};
    filter.ipv4.push_back(testIPv4_1);

    filter.applySrc = true;
    filter.applyDst = true;

    // WS filter: ip.src == 10.10.10.100 or ip.dst == 10.10.10.100
    // param: -f ipv4 -v 10.10.10.100 -s -d
    // result: 354 184
}

void filterSimpleMacInit(filter_t & filter) {
    filterTypeEnum testFilerType1 = filterTypeEnum::mac;
    filter.type.push_back(testFilerType1);

    mac_addr_t testMac1 = {0,0,0,0,0,5};
    filter.mac.push_back(testMac1);
    filter.applySrc = true;
    filter.applyDst = false;

    // WS filter: eth.src == 00:00:00:00:00:05
    // param: f mac -v 00:00:00:00:00:05 -s
    // result: 11620 10606
}

const char* filterTypeGiveString(filterTypeEnum & filterType) {
    switch (filterType) {
        case filterTypeEnum::mac:
            return FILTERTYPE_MAC;
        case filterTypeEnum::ipv4:
            return FILTERTYPE_IPv4;
        case filterTypeEnum::ipv6:
            return FILTERTYPE_IPv6;
        case filterTypeEnum::tcp:
            return FILTERTYPE_TCP;
        case filterTypeEnum::udp:
            return FILTERTYPE_UDP;
    }
}


void filterPrint(filter_t filter) {
    if(filterTypeCompare(filterTypeEnum::mac, filter.type)) {
        cout << "Mac addr:" << endl;
        for(mac_addr_t macAddr : filter.mac)
            macAddrPrint(macAddr.addr_bytes);
    }
    if(filterTypeCompare(filterTypeEnum::ipv4, filter.type)) {
        cout << "IPv4 addr:" << endl;
        for(ipv4_addr_t ipv4Addr : filter.ipv4)
            ipAddrPrint(ipv4Addr.addr_bytes);
    }
    cout << "Src addr: " << printTrueOrFalse(filter.applySrc) << endl;
    cout << "Dst addr: " << printTrueOrFalse(filter.applyDst) << endl;
}

void filterInit(filter_t & filter) {
    filter.type.clear();
    filter.mac.clear();
    filter.ipv4.clear();
    filter.ipv6.clear();
    filter.port.clear();
    filter.applySrc = false;
    filter.applyDst = false;
}


bool filterChecker(filter_t& filter, filteredPacket_t& actualPacket, filterTypeEnum actualType,
                   vector<filteredPacket_t>& filteredPacketVec) {
    if(filterTypeCompare(actualType, filter.type)) {
        cout << actualPacket.packetNumber << ": Looking on this type of header: " << filterTypeGiveString(actualType) << endl;

        switch (actualType) {
            case filterTypeEnum::mac:
                if(macsChecker(actualPacket, filter))
                    filteredPacketVec.push_back(actualPacket);
                break;
            case filterTypeEnum::ipv4:
                if(ipv4Checker(actualPacket, filter))
                    filteredPacketVec.push_back(actualPacket);
                break;
            case filterTypeEnum::ipv6:
                break;
            case filterTypeEnum::tcp:
                break;
            case filterTypeEnum::udp:
                break;
        }
        return true;
    }
    return false;
}

//template < typename PacketInput, typename FilterInputVec >
//bool vectorCompare(PacketInput * packetInput, vector<FilterInputVec>& filterInputVec) {
//    for(FilterInputVec macAddr : filterInputVec) {
//        if(macAddrEqual(macAddr.addr_bytes, packetInput))
//            return true;
//    }
//    return false;
//}


bool filterTypeCompare(filterTypeEnum packetType, vector<filterTypeEnum>& filterTypeEnumVec) {
    for(filterTypeEnum filterType : filterTypeEnumVec) {
        if(filterTypeEqual(filterType, packetType))
            return true;
    }
    return false;
}

bool filterTypeEqual(filterTypeEnum & packetType, filterTypeEnum & filterType) {
    return packetType == filterType;
}

bool macsChecker(filteredPacket_t& actualPacket, filter_t& filter) {
    if(filter.applySrc)
        return macsAddrsCompare(actualPacket.mac_src.addr_bytes, filter.mac);
    if(filter.applyDst)
        return macsAddrsCompare(actualPacket.mac_dst.addr_bytes, filter.mac);
}

bool macsAddrsCompare(uint8_t * packetMac, vector<mac_addr_t>& macAddrVec) {
    for(mac_addr_t macAddr : macAddrVec) {
        if(macAddrEqual(macAddr.addr_bytes, packetMac))
            return true;
    }
    return false;
}

bool macAddrEqual(uint8_t * mac_addr1, uint8_t * mac_addr2) {
    for(int i = 0; i < 6; ++i) {
        if(mac_addr1[i] != mac_addr2[i])
            return false;
    }
    return true;
}

void macAddrEqualPrint(uint8_t * mac_addr1, uint8_t * mac_addr2) {
    macAddrPrint(mac_addr1, false);
    cout << " == ";
    macAddrPrint(mac_addr2, false);
    cout << " => " << (macAddrEqual(mac_addr1, mac_addr2) ? "true" : "false") << endl;
}


bool ipv4Checker(filteredPacket_t& actualPacket, filter_t& filter) {
    bool applySrcBool = false;
    bool applyDstBool = false;

    if(filter.applySrc)
        applySrcBool = ipsAddrsCompare(actualPacket.ipv4_src.addr_bytes, filter.ipv4);
    if(filter.applyDst)
        applyDstBool = ipsAddrsCompare(actualPacket.ipv4_dst.addr_bytes, filter.ipv4);

    return applySrcBool || applyDstBool;
}


template <typename T, typename V>
bool ipsAddrsCompare(T* packetIp, vector<V>& ipAddrVec) {
    for(V ipAddr : ipAddrVec) {
        if(ipAddrEqual(ipAddr.addr_bytes, packetIp))
            return true;
    }
    return false;
}

bool ipAddrEqual(uint8_t * ip_addr1, uint8_t * ip_addr2) {
    for(int i = 0; i < 4; ++i) {
        if(ip_addr1[i] != ip_addr2[i])
            return false;
    }
    return true;
}

bool ipAddrEqual(uint16_t * ip_addr1, uint16_t * ip_addr2) {
    for(int i = 0; i < 8; ++i) {
        if(ip_addr1[i] != ip_addr2[i])
            return false;
    }
    return true;
}

template <typename T>
void ipAddrEqualPrint(T* ip_addr1, T* ip_addr2) {
    ipAddrPrint(ip_addr1, false);
    cout << " == ";
    ipAddrPrint(ip_addr2, false);
    cout << " => " << (ipAddrEqual(ip_addr1, ip_addr2) ? "true" : "false") << endl;
}

bool portsCompare(uint16_t packetPort, vector<uint16_t>& portAddrVec) {
    for(uint16_t port : portAddrVec) {
        if(portEqual(port, packetPort))
            return true;
    }
    return false;
}

bool portEqual(uint16_t port1, uint16_t port2) {
    return  port1 == port2;
}

void portEqualPrint(uint16_t port1, uint16_t port2) {
    cout << port1 << " == " << port2 << " => " << (portEqual(port1, port2) ? "true" : "false") << endl;
}

void filteredPacketInit(filteredPacket_t & filteredPacket) {
    filteredPacket.packetNumber = 0;

    macAddrInit(filteredPacket.mac_dst.addr_bytes);
    macAddrInit(filteredPacket.mac_src.addr_bytes);
    filteredPacket.macPacketSize = 0;
    filteredPacket.macDataSize = 0;
    filteredPacket.macHeaderSize = 0;
    filteredPacket.mac_set = false;

    ipv4AddrInit(filteredPacket.ipv4_dst.addr_bytes);
    ipv4AddrInit(filteredPacket.ipv4_src.addr_bytes);
    filteredPacket.ipv4PacketSize = 0;
    filteredPacket.ipv4DataSize = 0;
    filteredPacket.ipv4_set = false;
    ipv6AddrInit(filteredPacket.ipv6_dst.addr_bytes);
    ipv6AddrInit(filteredPacket.ipv6_src.addr_bytes);
    filteredPacket.ipv6PacketSize = 0;
    filteredPacket.ipv6DataSize = 0;
    filteredPacket.ipv6_set = false;

    filteredPacket.next_prot = ipNextHeaderProtocol::unk;

    filteredPacket.port_dst = 0;
    filteredPacket.port_src = 0;
    filteredPacket.port_set = false;
}

void filteredPacketPrint(filteredPacket_t & filteredPacket)
{
    cout << setw(4) << setfill(' ') <<  filteredPacket.packetNumber << ": ";
    if(filteredPacket.mac_set) {
        macAddrPrint(filteredPacket.mac_src.addr_bytes, false);
        cout << " -> ";
        macAddrPrint(filteredPacket.mac_dst.addr_bytes, false);

        cout << " (" << filteredPacket.macPacketSize << "  "
             << filteredPacket.macDataSize << ")";
        cout << "  ";
    }

    if(filteredPacket.ipv4_set) {
        ipAddrPrint(filteredPacket.ipv4_src.addr_bytes, false, true);
        cout << "  -> ";
        ipAddrPrint(filteredPacket.ipv4_dst.addr_bytes, false, true);

        cout << " (" << filteredPacket.ipv4PacketSize << "  "
             << filteredPacket.ipv4DataSize << ")";
    }
    else if(filteredPacket.ipv6_set) {
        ipAddrPrint(filteredPacket.ipv6_src.addr_bytes, false);
        cout << "  -> ";
        ipAddrPrint(filteredPacket.ipv6_dst.addr_bytes, false);

        cout << " (" << filteredPacket.ipv6PacketSize << "  "
             << filteredPacket.ipv6DataSize << ")";
    }

    if(filteredPacket.ipv4_set || filteredPacket.ipv6_set) {
        cout << "   " << ipNextHeaderProtocolGiveString(filteredPacket.next_prot);
        cout << "   ";
    }

    if(filteredPacket.port_set)
        cout << filteredPacket.port_src << " -> " << filteredPacket.port_src;
    cout << endl;
}

void macAddrCopy(uint8_t* filteredPacketMac, uint8_t* packetHeaderMac) {
    memcpy(filteredPacketMac, packetHeaderMac, 6);
}

void macHeaderCopy(filteredPacket_t& filteredPacket, pcap_packet_hdr_t& packetHeader) {
    macAddrCopy(filteredPacket.mac_dst.addr_bytes, packetHeader.etherHeader.ether_dhost);
    macAddrCopy(filteredPacket.mac_src.addr_bytes, packetHeader.etherHeader.ether_shost);
    filteredPacket.macPacketSize = packetHeader.orig_len;
    filteredPacket.macDataSize = packetHeader.orig_len - packetHeader.etherHeader.size;
    filteredPacket.macHeaderSize = packetHeader.etherHeader.size;
    filteredPacket.mac_set = true;
}

void ipAddrCopy(uint8_t* filteredPacketIpv4, uint8_t* packetHeaderIpv4) {
    memcpy(filteredPacketIpv4, packetHeaderIpv4, 4);
}

void ipAddrCopy(uint16_t* filteredPacketIpv6, uint16_t* packetHeaderIpv6) {
    for(int i = 0; i < 8; ++i)
        filteredPacketIpv6[i] = packetHeaderIpv6[i];
}

void ipHeaderCopy(filteredPacket_t & filteredPacket, pcap_packet_hdr_t & packetHeader) {
    ip_header_t & ipHeader = packetHeader.etherHeader.ipHeader;

    if(ipHeader.version == ipVersion::v4) {
        ipAddrCopy(filteredPacket.ipv4_dst.addr_bytes, ipHeader.v4_dst);
        ipAddrCopy(filteredPacket.ipv4_src.addr_bytes, ipHeader.v4_src);
        filteredPacket.ipv4PacketSize = filteredPacket.macDataSize;
        filteredPacket.ipv4DataSize = filteredPacket.macDataSize - ipHeader.size;
        filteredPacket.ipv4_set = true;
    }else if(ipHeader.version == ipVersion::v6) {
        ipAddrCopy(filteredPacket.ipv6_dst.addr_bytes, ipHeader.v6_dst);
        ipAddrCopy(filteredPacket.ipv6_src.addr_bytes, ipHeader.v6_src);
        filteredPacket.ipv6PacketSize = filteredPacket.macDataSize;
        filteredPacket.ipv6DataSize = filteredPacket.macDataSize - ipHeader.size;
        filteredPacket.ipv6_set = true;
    }
    filteredPacket.next_prot = ipHeader.nextHeader_protocol;
}

void portCopy(uint16_t & filteredPacketPort, uint16_t & packetHeaderPort) {
    filteredPacketPort = packetHeaderPort;
}

void tcpUdpHeaderCopy(filteredPacket_t & filteredPacket, tcp_udp_header_t & tcpUdpHeader) {
    portCopy(filteredPacket.port_dst, tcpUdpHeader.dst_port);
    portCopy(filteredPacket.port_src, tcpUdpHeader.src_port);
    filteredPacket.port_set = true;
}

void filteredPacketPrintResult(vector<filteredPacket_t> & filteredPacketVec, filter_t filter) {
    filterTypeEnum actualType = filter.type.at(0);

    int macPacketSize = 0;
    int macDataSize = 0;

    int ipPacketSize = 0;
    int ipDataSize = 0;

    switch (actualType) {
        case filterTypeEnum::mac:
            for(filteredPacket_t actualPacket : filteredPacketVec) {
                filteredPacketPrint(actualPacket);
                macPacketSize += actualPacket.macPacketSize;
                macDataSize += actualPacket.macDataSize;

                cout << "  " << actualPacket.macPacketSize
                     << " (" << macPacketSize
                     << ") " << actualPacket.macDataSize
                     << " (" << macDataSize << ") " << endl;
            }

            cout << filteredPacketVec.size() << endl;
            cout << "macPacketSize: " << macPacketSize << endl;
            cout << "macDataSize: " << macDataSize << endl;
            break;
        case filterTypeEnum::ipv4:
            for(filteredPacket_t actualPacket : filteredPacketVec) {
                filteredPacketPrint(actualPacket);
                ipPacketSize += actualPacket.macPacketSize;
                ipDataSize += actualPacket.ipv4DataSize;

                cout << "  " << actualPacket.macPacketSize
                     << " (" << ipPacketSize
                     << ") " << actualPacket.ipv4DataSize
                     << " (" << ipDataSize << ") " << endl;
            }

            cout << filteredPacketVec.size() << endl;
            cout << "ipPacketSize: " << ipPacketSize << endl;
            cout << "ipDataSize: " << ipDataSize << endl;
            break;
        case filterTypeEnum::ipv6:
            break;
        case filterTypeEnum::tcp:
            break;
        case filterTypeEnum::udp:
            break;
    }
}
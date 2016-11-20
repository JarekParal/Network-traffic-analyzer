//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 14.11.2016.
//

#include "filter.h"
#include "packet.h"

void testFilter() {
    cout << " ----- Filter test" << endl;

    filter_t filter;
    filter.type = filterType::ipv4;

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

//template < typename PacketInput, typename FilterInputVec >
//bool vectorCompare(PacketInput * packetInput, vector<FilterInputVec>& filterInputVec) {
//    for(FilterInputVec macAddr : filterInputVec) {
//        if(macAddrEqual(macAddr.addr_bytes, packetInput))
//            return true;
//    }
//    return false;
//}

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
    filteredPacket.mac_set = false;

    ipv4AddrInit(filteredPacket.ipv4_dst.addr_bytes);
    ipv4AddrInit(filteredPacket.ipv4_src.addr_bytes);
    filteredPacket.ipv4_set = false;
    ipv6AddrInit(filteredPacket.ipv6_dst.addr_bytes);
    ipv6AddrInit(filteredPacket.ipv6_src.addr_bytes);
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
        cout << "  ";
    }

    if(filteredPacket.ipv4_set) {
        ipAddrPrint(filteredPacket.ipv4_src.addr_bytes, false, true);
        cout << "  -> ";
        ipAddrPrint(filteredPacket.ipv4_dst.addr_bytes, false, true);
    }
    else if(filteredPacket.ipv6_set) {
        ipAddrPrint(filteredPacket.ipv6_src.addr_bytes, false);
        cout << "  -> ";
        ipAddrPrint(filteredPacket.ipv6_dst.addr_bytes, false);
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

void macHeaderCopy(filteredPacket_t & filteredPacket, ether_header_t & etherHeader) {
    macAddrCopy(filteredPacket.mac_dst.addr_bytes, etherHeader.ether_dhost);
    macAddrCopy(filteredPacket.mac_src.addr_bytes, etherHeader.ether_shost);
    filteredPacket.mac_set = true;
}

void ipAddrCopy(uint8_t* filteredPacketIpv4, uint8_t* packetHeaderIpv4) {
    memcpy(filteredPacketIpv4, packetHeaderIpv4, 4);
}

void ipAddrCopy(uint16_t* filteredPacketIpv6, uint16_t* packetHeaderIpv6) {
    for(int i = 0; i < 8; ++i)
        filteredPacketIpv6[i] = packetHeaderIpv6[i];
}

void ipHeaderCopy(filteredPacket_t & filteredPacket, ip_header_t & ipHeader) {
    if(ipHeader.version == ipVersion::v4) {
        ipAddrCopy(filteredPacket.ipv4_dst.addr_bytes, ipHeader.v4_dst);
        ipAddrCopy(filteredPacket.ipv4_src.addr_bytes, ipHeader.v4_src);
        filteredPacket.ipv4_set = true;
    }else if(ipHeader.version == ipVersion::v6) {
        ipAddrCopy(filteredPacket.ipv6_dst.addr_bytes, ipHeader.v6_dst);
        ipAddrCopy(filteredPacket.ipv6_src.addr_bytes, ipHeader.v6_src);
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
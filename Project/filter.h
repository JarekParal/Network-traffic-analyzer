//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 14.11.2016.
//

#ifndef ISA_PROJECT_FILTER_H
#define ISA_PROJECT_FILTER_H

#include "packet.h"

#include <vector>
using std::vector;

// ----- Filter
enum class filterType {
    mac,
    ipv4,
    ipv6,
    tcp,
    udp
};

const char FILTERTYPE_MAC[] = "mac";
const char FILTERTYPE_IPv4[] = "ipv4";
const char FILTERTYPE_IPv6[] = "ipv6";
const char FILTERTYPE_TCP[] = "tcp";
const char FILTERTYPE_UDP[] = "udp";

typedef struct filter_s{
    filterType type;
    vector<mac_addr_t> mac;
    vector<ipv4_addr_t> ipv4;
    vector<ipv6_addr_t> ipv6;
    vector<uint16_t> port;
    bool applySrc;
    bool applyDst;
} filter_t;

void testFilter();

// ----- MAC
//template < typename PacketInput, typename FilterInputVec >
//bool vectorCompare(PacketInput * packetInput, vector<FilterInputVec>& filterInputVec);
bool macsAddrsCompare(uint8_t * packetMac, vector<mac_addr_t>& macAddrVec);

bool macAddrEqual(uint8_t * mac_addr1, uint8_t * mac_addr2);
void macAddrEqualPrint(uint8_t * mac_addr1, uint8_t * mac_addr2);

// ----- IP
template <typename T, typename V>
bool ipsAddrsCompare(T* packetIp, vector<V>& ipAddrVec);
//bool ipsAddrsCompare(uint8_t* packetIpv4, vector<ipv4_addr_t>& ipAddrVec)

bool ipAddrEqual(uint8_t * ip_addr1, uint8_t * ip_addr2);
bool ipAddrEqual(uint16_t * ip_addr1, uint16_t * ip_addr2);

template <typename T>
void ipAddrEqualPrint(T* ip_addr1, T* ip_addr2);
//void ipAddrEqualPrint(uint16_t * ip_addr1, uint16_t * ip_addr2);

// ----- Port
bool portsCompare(uint16_t packetPort, vector<uint16_t>& portAddrVec);
bool portEqual(uint16_t port1, uint16_t port2);
void portEqualPrint(uint16_t port1, uint16_t port2);

// ----- Filtered packet
typedef struct filteredPacket_s{
    int packetNumber;

    mac_addr_t mac_src;
    mac_addr_t mac_dst;
    bool mac_set;

    ipv4_addr_t ipv4_src;
    ipv4_addr_t ipv4_dst;
    bool ipv4_set;

    ipv6_addr_t ipv6_src;
    ipv6_addr_t ipv6_dst;
    bool ipv6_set;

    ipNextHeaderProtocol next_prot;

    uint16_t port_src;
    uint16_t port_dst;
    bool port_set;
} filteredPacket_t;

void filteredPacketInit(filteredPacket_t & filteredPacket);
void filteredPacketPrint(filteredPacket_t & filteredPacket);

void macAddrCopy(uint8_t* filteredPacketMac, uint8_t* packetHeaderMac);
void macHeaderCopy(filteredPacket_t & filteredPacket, ether_header_t & etherHeader);

void ipAddrCopy(uint8_t* filteredPacketIpv4, uint8_t* packetHeaderIpv4);
void ipAddrCopy(uint16_t* filteredPacketIpv6, uint16_t* packetHeaderIpv6);
void ipHeaderCopy(filteredPacket_t & filteredPacket, ip_header_t & ipHeader);

void portCopy(uint16_t & filteredPacketPort, uint16_t & packetHeaderPort);
void tcpUdpHeaderCopy(filteredPacket_t & filteredPacket, tcp_udp_header_t & tcpUdpHeader);

#endif //ISA_PROJECT_FILTER_H

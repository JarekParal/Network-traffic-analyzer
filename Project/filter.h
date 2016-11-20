//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 14.11.2016.
//

#ifndef ISA_PROJECT_FILTER_H
#define ISA_PROJECT_FILTER_H

#include "packet.h"

#include <vector>
using std::vector;

// ----- Filtered packet
typedef struct filteredPacket_s{
    int packetNumber;

    mac_addr_t mac_src;
    mac_addr_t mac_dst;
    int macPacketSize;
    int macDataSize;
    int macHeaderSize;

    ipVersion ipHeaderVersion;

    bool mac_set;
    ipv4_addr_t ipv4_src;
    ipv4_addr_t ipv4_dst;
    int ipv4PacketSize;
    int ipv4DataSize;

    bool ipv4_set;

    ipv6_addr_t ipv6_src;
    ipv6_addr_t ipv6_dst;
    int ipv6PacketSize;
    int ipv6DataSize;
    bool ipv6_set;

    ipNextHeaderProtocol next_prot;

    uint16_t port_src;
    uint16_t port_dst;
    int tcpPacketSize;
    int tcpDataSize;
    int udpPacketSize;
    int udpDataSize;
    bool port_set;
} filteredPacket_t;

// ----- Filter
enum class filterTypeEnum {
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
    vector<filterTypeEnum> type;
    vector<mac_addr_t> mac;
    vector<ipv4_addr_t> ipv4;
    vector<ipv6_addr_t> ipv6;
    vector<uint16_t> port;
    bool applySrc;
    bool applyDst;
} filter_t;

void testFilter();

void filterSimpleUdpInitS(filter_t & filter);
void filterSimpleTcpInitSD(filter_t & filter);
void filterSimpleTcpInitS(filter_t & filter);
void filterSimpleIpv4InitD(filter_t & filter);
void filterSimpleIpv4InitSD(filter_t & filter);
void filterSimpleMacInit(filter_t & filter);

const char* filterTypeGiveString(filterTypeEnum & filterType);

void filterPrint(filter_t& filter);

void filterInit(filter_t & filter);

bool filterChecker(filter_t& filter, filteredPacket_t& actualPacket, filterTypeEnum actualType,
                   vector<filteredPacket_t>& filteredPacketVec);

bool filterTypeCompare(filterTypeEnum packetType, vector<filterTypeEnum>& filterTypeEnumVec);
bool filterTypeEqual(filterTypeEnum & packetType, filterTypeEnum & filterType);

// ----- MAC
//template < typename PacketInput, typename FilterInputVec >
//bool vectorCompare(PacketInput * packetInput, vector<FilterInputVec>& filterInputVec);
bool macsChecker(filteredPacket_t& actualPacket, filter_t& filter);
bool macsAddrsCompare(uint8_t * packetMac, vector<mac_addr_t>& macAddrVec);

bool macAddrEqual(uint8_t * mac_addr1, uint8_t * mac_addr2);
void macAddrEqualPrint(uint8_t * mac_addr1, uint8_t * mac_addr2);

// ----- IP
bool ipv4Checker(filteredPacket_t& actualPacket, filter_t& filter);
bool ipv6Checker(filteredPacket_t& actualPacket, filter_t& filter);
template <typename T, typename V>
bool ipsAddrsCompare(T* packetIp, vector<V>& ipAddrVec);
//bool ipsAddrsCompare(uint8_t* packetIpv4, vector<ipv4_addr_t>& ipAddrVec)

bool ipAddrEqual(uint8_t * ip_addr1, uint8_t * ip_addr2);
bool ipAddrEqual(uint16_t * ip_addr1, uint16_t * ip_addr2);

template <typename T>
void ipAddrEqualPrint(T* ip_addr1, T* ip_addr2);
bool portChecker(filteredPacket_t& actualPacket, filter_t& filter);
//void ipAddrEqualPrint(uint16_t * ip_addr1, uint16_t * ip_addr2);

// ----- Port
bool portsCompare(uint16_t packetPort, vector<uint16_t>& portAddrVec);
bool portEqual(uint16_t port1, uint16_t port2);
void portEqualPrint(uint16_t port1, uint16_t port2);


// ----- Filtered packet function
void filteredPacketInit(filteredPacket_t & filteredPacket);
void filteredPacketPrint(filteredPacket_t & filteredPacket);

void macAddrCopy(uint8_t* filteredPacketMac, uint8_t* packetHeaderMac);
void macHeaderCopy(filteredPacket_t& filteredPacket, pcap_packet_hdr_t& packetHeader);

void ipAddrCopy(uint8_t* filteredPacketIpv4, uint8_t* packetHeaderIpv4);
void ipAddrCopy(uint16_t* filteredPacketIpv6, uint16_t* packetHeaderIpv6);
void ipHeaderCopy(filteredPacket_t & filteredPacket, pcap_packet_hdr_t & packetHeader);

void portCopy(uint16_t & filteredPacketPort, uint16_t & packetHeaderPort);
void tcpUdpHeaderCopy(filteredPacket_t & filteredPacket, pcap_packet_hdr_t & packetHeader);

void filteredPacketPrintResult(vector<filteredPacket_t>& filteredPacketVec, filter_t filter, bool debug = false);

#endif //ISA_PROJECT_FILTER_H

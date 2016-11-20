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

#endif //ISA_PROJECT_FILTER_H

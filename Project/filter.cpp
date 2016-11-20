//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 14.11.2016.
//

#include "filter.h"

void testFilter() {
    cout << " ----- Filter test" << endl;

    filter_t filter;
    filter.type = filterType::ipv4;

    mac_addr_t testMac1 = {0,0,0,0,0,1};
    mac_addr_t testMac2 = {0,0,0,0,0,2};

    macAddrPrint(testMac1.addr_bytes);
    filter.mac.push_back(testMac2);
    macAddrPrint(filter.mac.at(0).addr_bytes);
    macAddrEqualPrint(testMac1.addr_bytes, filter.mac.at(0).addr_bytes);

    ipv4_addr_t testIPv4_1 = {10,10,10,2};
    ipv4_addr_t testIPv4_2 = {10,10,10,3};

    ipAddrPrint(testIPv4_1.addr_bytes);
    filter.ipv4.push_back(testIPv4_2);
    ipAddrPrint(filter.ipv4.at(0).addr_bytes);
    ipAddrEqualPrint(testIPv4_1.addr_bytes, filter.ipv4.at(0).addr_bytes);

    ipv6_addr_t testIPv6_1 = {0xfd00,00,00,00,00,00,00,04};
    ipv6_addr_t testIPv6_2 = {0xfd00,00,00,00,00,00,00,05};

    ipAddrPrint(testIPv6_1.addr_bytes);
    filter.ipv6.push_back(testIPv6_2);
    ipAddrPrint(filter.ipv6.at(0).addr_bytes);
    ipAddrEqualPrint(testIPv6_1.addr_bytes, filter.ipv6.at(0).addr_bytes);

    uint16_t testPort1 = 100;
    uint16_t testPort2 = 100;

    cout << testPort1 << endl << testPort2 << endl;
    filter.port.push_back(testPort2);
    portEqualPrint(testPort1, testPort2);

    cout << endl << endl;
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

bool ipAddrEqual(uint8_t * ip_addr1, uint8_t * ip_addr2) {
    for(int i = 0; i < 4; ++i) {
        if(ip_addr1[i] != ip_addr2[i])
            return false;
    }
    return true;
}

void ipAddrEqualPrint(uint8_t * ip_addr1, uint8_t * ip_addr2) {
    ipAddrPrint(ip_addr1, false);
    cout << " == ";
    ipAddrPrint(ip_addr2, false);
    cout << " => " << (ipAddrEqual(ip_addr1, ip_addr2) ? "true" : "false") << endl;
}


bool ipAddrEqual(uint16_t * ip_addr1, uint16_t * ip_addr2) {
    for(int i = 0; i < 8; ++i) {
        if(ip_addr1[i] != ip_addr2[i])
            return false;
    }
    return true;
}

void ipAddrEqualPrint(uint16_t * ip_addr1, uint16_t * ip_addr2) {
    ipAddrPrint(ip_addr1, false);
    cout << " == ";
    ipAddrPrint(ip_addr2, false);
    cout << " => " << (ipAddrEqual(ip_addr1, ip_addr2) ? "true" : "false") << endl;
}


bool portEqual(uint16_t port1, uint16_t port2) {
    return  port1 == port2;
}

void portEqualPrint(uint16_t port1, uint16_t port2) {
    cout << port1 << " == " << port2 << " => " << (portEqual(port1, port2) ? "true" : "false") << endl;
}
#include <cstdint>
#include <iostream>
#include <fstream>
#include <cstring>

#include "structures.h"

using namespace std;

void transferDataPrint(int transferData) {
    cout << "\t TD: " << transferData << " (" << transferData*8 << ")" << endl;
}

int main() {
    //cout << " ----- Init variable << endl;
    int transferDataSizeByte = 0;
    pcap_glob_hdr_t globalHeader;
    pcap_packet_hdr_t packetHeader;
    ether_header_t etherHeader;
    ip_header_t ipHeader;

    cout << " ----- Open file" << endl;
    ifstream pcapFile;
    pcapFile.open("../data/isa.pcap",  ios::binary);

    if(!pcapFile.is_open()) {
        cerr << "Pcap file couldn't open!" << endl;
        return 0;
    } else {
        cout << "Pcap file successfully opened" << std::endl;
    }

    cout << " ----- Load file to array buffer[]" << endl;
    pcapFile.seekg(0, pcapFile.end);
    int sizeOfPcap = pcapFile.tellg();
    pcapFile.seekg(0, pcapFile.beg);

    cout << "Size of pcap file: " << sizeOfPcap << endl;
    int pcapPointer = 0;
    char * buffer;
    buffer = new char [sizeOfPcap];
    streamsize loadBites = pcapFile.readsome(buffer, sizeOfPcap);

    if(loadBites != sizeOfPcap) {
        cerr << "Loading data problem... expected: " << sizeOfPcap << "  stored: " << loadBites << endl;
        cerr.flush();
        return 0;
    } else {
        cout << "Pcap file successfully load" << std::endl;
    }

    //cout << " ----- Print file " << endl;

//    while(pcapFile)
//        cout << std::hex << pcapFile.get();

    cout << " ----- Work with buffer " << endl;
    uint32_t num = 0;
//  num = toUint32(buffer, pcapPointer);
    memcpy(&num, (buffer + 24), 4);

    cout << std::hex << num << endl;
    cout << std::dec << num << endl;

    cout << " ----- Work with global header" << endl;
    parsePcapGlobalHeader(globalHeader, buffer, pcapPointer);
    printPcapGlobalHeader(globalHeader);

    cout << " ----- Work with packet header" << endl;
    parsePcapPacketHeader(packetHeader, buffer, pcapPointer);
    printPcapPacketHeader(packetHeader);

    cout << " ----- Parse ethernet header" << endl;
    transferDataSizeByte += parseEthernetHeader(etherHeader, buffer, pcapPointer);
    printEthernetHeader(etherHeader);
    transferDataPrint(transferDataSizeByte);

    cout << " ----- Parse IP header" << endl;
    switch (etherHeader.ether_type) {
        case ETHERTYPE_IP:
        case ETHERTYPE_IP6:
            transferDataSizeByte += parseIpHeader(ipHeader, buffer, pcapPointer);
            printIpHeader(ipHeader);
            transferDataPrint(transferDataSizeByte);
            break;

        case ETHERTYPE_ARP:

            break;

        default:
            //802.3 length - https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_frame_types
            transferDataSizeByte += etherHeader.ether_type;
            break;
    }

    cout << " ----- Read counter" << endl;
    cout << "gcount: " << pcapFile.gcount() << endl;

    return 0;
}
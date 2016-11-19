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
    long sizeOfPcap = pcapFile.tellg();
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
    pcapGlobalHeaderParse(globalHeader, buffer, pcapPointer);
    pcapGlobalHeaderPrint(globalHeader);

    cout << " ----- Work with packet header" << endl;
    pcapPacketHeaderParse(packetHeader, buffer, pcapPointer);
    pcapPacketHeaderPrint(packetHeader);

    cout << " ----- Parse ethernet header" << endl;
    transferDataSizeByte += ethernetHeaderParse(etherHeader, buffer, pcapPointer);
    ethernetHeaderPrint(etherHeader);
    transferDataPrint(transferDataSizeByte);

    cout << " ----- Parse IP header" << endl;
    switch (etherHeader.ether_type) {
        case etherTypeEnum::IP:
        case etherTypeEnum::IP6:
            transferDataSizeByte += ipHeaderParse(ipHeader, buffer, pcapPointer);
            ipHeaderPrint(ipHeader);
            transferDataPrint(transferDataSizeByte);
            break;

        case etherTypeEnum::ARP:

            break;

        default:
            //802.3 length - https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_frame_types
            transferDataSizeByte += static_cast<int>(etherHeader.ether_type);
            transferDataPrint(transferDataSizeByte);
            break;
    }

    cout << " ----- Read counter" << endl;
    cout << "gcount: " << pcapFile.gcount() << endl;

    return 0;
}
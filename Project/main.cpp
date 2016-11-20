#include <cstdint>
#include <iostream>
#include <fstream>
#include <cstring>

#include "packet.h"
#include "filter.h"

using namespace std;

void transferDataPrint(int transferData) {
    cout << "\t TD: " << transferData << " (" << transferData*8 << ")" << endl;
}

int main() {
    //testFilter();

    cout << " ----- Init filter" << endl;
    filter_t filter;
    filterSimpleMacInit(filter);
    //filterSimpleIpv4InitSD(filter);
    filterPrint(filter);

    vector<filteredPacket_t> filteredPacketVec;
    filteredPacket_t filteredPacket;
    //filteredPacketInit(filteredPacket);

    ////cout << " ----- Init variable" << endl;
    int transferDataSizeByte = 0;
    int packetNumber = 0;
    pcap_glob_hdr_t globalHeader;
    pcap_packet_hdr_t packetHeader;
    //packetHeaderInit(packetHeader);

    ether_header_t etherHeader;
    etherHeaderInit(etherHeader);

    ip_header_t ipHeader;
    ipHeaderInit(ipHeader);

    tcp_udp_header_t tcpUdpHeader;
    tcpUdpHeaderInit(tcpUdpHeader);

//#define fullDebug
    ////cout << " ----- Debug setting << endl;
#ifdef fullDebug
    bool debugPcapGlobalHeader = true;
    bool debugPcapPacketHeader = true;
    bool debugEthernetHeader = true;
    bool debugIpHeader = true;
    bool debugTcpUdpHeader = true;
    bool debugInfo = true;
    bool debugPacket = true;
#else
    bool debugPcapGlobalHeader = false;
    bool debugPcapPacketHeader = false;
    bool debugEthernetHeader = false;
    bool debugIpHeader = false;
    bool debugTcpUdpHeader = false;
    bool debugInfo = false;
    bool debugPacket = false;
#endif
    bool debugFilteredPacket = false;
    bool debugFilteredPacketVec = true;

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
    int pcapPointerStart = 0;
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

////    cout << " ----- Print file " << endl;
//    while(pcapFile)
//        cout << std::hex << pcapFile.get();

////    cout << " ----- Work with buffer " << endl;
//    uint32_t num = 0;
//    num = toUint32(buffer, pcapPointer);
//    memcpy(&num, (buffer + 24), 4);
//
//    cout << std::hex << num << endl;
//    cout << std::dec << num << endl;

    pcapGlobalHeaderParse(globalHeader, buffer, pcapPointer);
    if(debugPcapGlobalHeader) {
        cout << " ----- Work with global header" << endl;
        pcapGlobalHeaderPrint(globalHeader);
    }

    while(pcapPointer < sizeOfPcap) {
        //packetHeader.etherHeader.ether_type = etherTypeEnum::unk;
        //packetHeader.etherHeader.ipHeader.nextHeader_protocol = ipNextHeaderProtocol::unk;
        packetHeaderInit(packetHeader);
        filteredPacketInit(filteredPacket);

        pcapPacketHeaderParse(packetHeader, buffer, pcapPointer);
        if (debugPcapPacketHeader) {
            cout << " ----- Work with packet header" << endl;
            pcapPacketHeaderPrint(packetHeader);
        }

        pcapPointerStart = pcapPointer;
        packetNumber++;
        filteredPacket.packetNumber = packetNumber;
        packetHeader.packetNumber = packetNumber;

        if(debugInfo) {
            cout << "-- Packet number: " << decAndHexStr(packetNumber) << endl;
            cout << "-- Pcap pointer: " << decAndHexStr(pcapPointer) << endl;
        }

        //// ----- Ethernet packet
        transferDataSizeByte += ethernetHeaderParse(packetHeader, buffer, pcapPointer);
        if (debugEthernetHeader) {
            cout << " ----- Parse ethernet header" << endl;
            ethernetHeaderPrint(packetHeader.etherHeader);
            transferDataPrint(transferDataSizeByte);
        }
        macHeaderCopy(filteredPacket, packetHeader);
        if(debugFilteredPacket)
            filteredPacketPrint(filteredPacket);

        (filterChecker(filter, filteredPacket, filterTypeEnum::mac, filteredPacketVec));
            //continue;

        switch (packetHeader.etherHeader.ether_type) {
            case etherTypeEnum::IP:
            case etherTypeEnum::IP6:
                //// ----- IP packet
                transferDataSizeByte += ipHeaderParse(packetHeader , buffer, pcapPointer);
                if (debugIpHeader) {
                    cout << " ----- Parse IP header" << endl;
                    ipHeaderPrint(packetHeader.etherHeader.ipHeader);
                    transferDataPrint(transferDataSizeByte);
                }
                ipHeaderCopy(filteredPacket, packetHeader);
                if(debugFilteredPacket)
                    filteredPacketPrint(filteredPacket);

                filterChecker(filter, filteredPacket, filterTypeEnum::ipv4, filteredPacketVec);


                //// ----- TCP/UDP packet
                if(packetHeader.etherHeader.ipHeader.nextHeader_protocol == ipNextHeaderProtocol::TCP ||
                    packetHeader.etherHeader.ipHeader.nextHeader_protocol == ipNextHeaderProtocol::UDP) {
                    transferDataSizeByte += tcpUdpHeaderParse(packetHeader, buffer, pcapPointer);

                    // Padding hack
                    if(packetHeader.etherHeader.ipHeader.nextHeader_length + packetHeader.etherHeader.ipHeader.size + packetHeader.etherHeader.size
                       < packetHeader.orig_len) {
                        filteredPacket_t & filteredPacketTemp = filteredPacketVec.back();
                        int value = filteredPacketTemp.macDataSize;
                        cerr << endl << value << " - " << packetHeader.packetNumber << endl;
                        filteredPacketTemp.macDataSize = packetHeader.orig_len - packetHeader.etherHeader.size;
                    }

                    if (debugTcpUdpHeader) {
                        cout << " ----- Parse TCP/UDP header" << endl;
                        tcpUdpPrint(packetHeader.etherHeader.ipHeader.tcpUdpHeader);
                        transferDataPrint(transferDataSizeByte);
                    }
                    tcpUdpHeaderCopy(filteredPacket, packetHeader.etherHeader.ipHeader.tcpUdpHeader);
                    if(debugFilteredPacket)
                        filteredPacketPrint(filteredPacket);
                } else {
                    transferDataSizeByte += packetHeader.etherHeader.ipHeader.nextHeader_length;
                }
                break;

            case etherTypeEnum::ARP:
                transferDataSizeByte = packetHeader.orig_len;
                break;

            default:
                //802.3 length - https://en.wikipedia.org/wiki/Ethernet_frame#
                transferDataSizeByte += static_cast<int>(packetHeader.etherHeader.ether_type);
                packetHeader.etherHeader.ether_type = etherTypeEnum::unk;
                transferDataPrint(transferDataSizeByte);
                break;
        }

        if (debugPacket)
            packetPrint(packetHeader, packetNumber, transferDataSizeByte);

        if(debugInfo) {
            cout << "-- pcapPointer: " << decAndHexStr(pcapPointer) << endl;
            cout << "-- pcapPointerStart: " << decAndHexStr(pcapPointerStart) << endl;
            cout << "-- transferDataSizeByte: " << decAndHexStr(transferDataSizeByte) << endl;
            cout << "-- pcapPointerStart + transferDataSizeByte: " << decAndHexStr(pcapPointerStart + transferDataSizeByte) << endl;
        }

        pcapPointer = pcapPointerStart + transferDataSizeByte;
        transferDataSizeByte = 0;
    }
    cout << " ----- Read counter" << endl;
    cout << "gcount: " << pcapFile.gcount() << endl;

    if(debugFilteredPacketVec) {
        filteredPacketPrintResult(filteredPacketVec, filter);
    }
    return 0;
}
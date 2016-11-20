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
    testFilter();

    ////cout << " ----- Init variable << endl;
    int transferDataSizeByte = 0;
    int packetNumber = 0;
    pcap_glob_hdr_t globalHeader;
    pcap_packet_hdr_t packetHeader;

    ether_header_t etherHeader;
    ip_header_t ipHeader;
    tcp_udp_header_t tcpUdpHeader;

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
    bool debugPacket = true;
#endif

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
        packetHeader.etherHeader.ether_type = etherTypeEnum::unk;
        packetHeader.etherHeader.ipHeader.nextHeader_protocol = ipNextHeaderProtocol::unk;

        pcapPacketHeaderParse(packetHeader, buffer, pcapPointer);
        if (debugPcapPacketHeader) {
            cout << " ----- Work with packet header" << endl;
            pcapPacketHeaderPrint(packetHeader);
        }

        pcapPointerStart = pcapPointer;
        packetNumber++;

        if(debugInfo) {
            cout << "-- Packet number: " << decAndHexStr(packetNumber) << endl;
            cout << "-- Pcap pointer: " << decAndHexStr(pcapPointer) << endl;
        }

        transferDataSizeByte += ethernetHeaderParse(packetHeader, buffer, pcapPointer);
        if (debugEthernetHeader) {
            cout << " ----- Parse ethernet header" << endl;
            ethernetHeaderPrint(packetHeader.etherHeader);
            transferDataPrint(transferDataSizeByte);
        }

        switch (packetHeader.etherHeader.ether_type) {
            case etherTypeEnum::IP:
            case etherTypeEnum::IP6:
                transferDataSizeByte += ipHeaderParse(packetHeader , buffer, pcapPointer);
                if (debugIpHeader) {
                    cout << " ----- Parse IP header" << endl;
                    ipHeaderPrint(packetHeader.etherHeader.ipHeader);
                    transferDataPrint(transferDataSizeByte);
                }

                if(packetHeader.etherHeader.ipHeader.nextHeader_protocol == ipNextHeaderProtocol::TCP ||
                    packetHeader.etherHeader.ipHeader.nextHeader_protocol == ipNextHeaderProtocol::UDP) {
                    transferDataSizeByte += tcpUdpHeaderParse(packetHeader, buffer, pcapPointer);

                    if (debugTcpUdpHeader) {
                        cout << " ----- Parse TCP/UDP header" << endl;
                        tcpUdpPrint(packetHeader.etherHeader.ipHeader.tcpUdpHeader);
                        transferDataPrint(transferDataSizeByte);
                    }
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

    return 0;
}
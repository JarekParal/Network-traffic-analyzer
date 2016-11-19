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
    ////cout << " ----- Init variable << endl;
    int transferDataSizeByte = 0;
    int packetNumber = 0;
    pcap_glob_hdr_t globalHeader;
    pcap_packet_hdr_t packetHeader;
    ether_header_t etherHeader;
    ip_header_t ipHeader;
    tcp_udp_header_t tcpUdpHeader;

    ////cout << " ----- Debug setting << endl;
    bool debugPcapGlobalHeader = false;
    bool debugPcapPacketHeader = false;
    bool debugEthernetHeader = false;
    bool debugIpHeader = false;
    bool debugTcpUdpHeader = false;
    bool debugInfo = false;
    bool debugPacket = true;

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
        etherHeader.ether_type = etherTypeEnum::unk;
        ipHeader.nextHeader_protocol = ipNextHeaderProtocol::unk;

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

        transferDataSizeByte += ethernetHeaderParse(etherHeader, buffer, pcapPointer);
        if (debugEthernetHeader) {
            cout << " ----- Parse ethernet header" << endl;
            ethernetHeaderPrint(etherHeader);
            transferDataPrint(transferDataSizeByte);
        }

        switch (etherHeader.ether_type) {
            case etherTypeEnum::IP:
            case etherTypeEnum::IP6:
                transferDataSizeByte += ipHeaderParse(ipHeader, buffer, pcapPointer);
                if (debugIpHeader) {
                    cout << " ----- Parse IP header" << endl;
                    ipHeaderPrint(ipHeader);
                    transferDataPrint(transferDataSizeByte);
                }

                transferDataSizeByte += tcpUdpHeaderParse
                        (tcpUdpHeader, buffer, pcapPointer, ipHeader.nextHeader_protocol);

                if (debugTcpUdpHeader) {
                    cout << " ----- Parse TCP/UDP header" << endl;
                    tcpUdpPrint(tcpUdpHeader);
                    transferDataPrint(transferDataSizeByte);
                }
                break;

            case etherTypeEnum::ARP:

                break;

            default:
                //802.3 length - https://en.wikipedia.org/wiki/Ethernet_frame#
                transferDataSizeByte += static_cast<int>(etherHeader.ether_type);
                etherHeader.ether_type = etherTypeEnum::unk;
                transferDataPrint(transferDataSizeByte);
                break;
        }

        if(debugInfo) {
            cout << "-- pcapPointer: " << decAndHexStr(pcapPointer) << endl;
            cout << "-- pcapPointerStart: " << decAndHexStr(pcapPointerStart) << endl;
            cout << "-- transferDataSizeByte: " << decAndHexStr(transferDataSizeByte) << endl;
            cout << "-- pcapPointerStart + transferDataSizeByte: " << decAndHexStr(pcapPointerStart + transferDataSizeByte) << endl;
        }

        if (debugPacket)
            packetPrint(packetNumber, packetHeader, etherHeader, ipHeader, tcpUdpHeader, transferDataSizeByte);

        pcapPointer = pcapPointerStart + transferDataSizeByte;
        transferDataSizeByte = 0;
    }
    cout << " ----- Read counter" << endl;
    cout << "gcount: " << pcapFile.gcount() << endl;

    return 0;
}
#include <cstdint>
#include <iostream>
#include <fstream>
#include <cstring>

#include "convert.h"
#include "structures.h"

using namespace std;

int main() {

    //cout << " ----- Init variable << endl;
    pcap_glob_hdr_t globalHeader;
    pcap_packet_hdr_t packetHeader;

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

    readPcapGlobalHeader(globalHeader, buffer, pcapPointer);
    printPcapGlobalHeader(globalHeader);

    cout << " ----- Work with packet header" << endl;

    readPcapPacketHeader(packetHeader, buffer, pcapPointer);
    printPcapPacketHeader(packetHeader);

    cout << " ----- Read counter" << endl;

    cout << "gcount: " << pcapFile.gcount() << endl;

    return 0;
}
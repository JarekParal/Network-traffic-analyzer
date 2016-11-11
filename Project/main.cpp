#include <cstdint>
#include <iostream>
#include <fstream>
#include <cstring>

#include "convert.h"

using namespace std;

int main() {
    std::cout << "Try to read pcap file" << std::endl;

    ifstream pcapFile;
    pcapFile.open("../data/isa.pcap",  ios::binary);

    if(!pcapFile.is_open()) {
        cerr << "Pcap file couldn't open!" << endl;
        return 0;
    }

    uint32_t pcap_pointer = 0;
    char * buffer;
    buffer = new char [4];
    pcapFile.readsome(buffer, 4);

//    while(pcapFile)
//        cout << std::hex << pcapFile.get();

    uint32_t num;
    num = toUint32(buffer, pcap_pointer);

    cout << std::hex << num << endl;
    cout << std::dec << num << endl;

    return 0;
}
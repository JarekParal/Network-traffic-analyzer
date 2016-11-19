//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 11.11.2016.
//

#include "convert.h"

int8_t toInt8(char* buffer, int& bufPointer, bool bigEndian)
{
    bufPointer++;
    return  static_cast<int8_t>(buffer[bufPointer - 1]);
}

uint8_t toUint8(char* buffer, int& bufPointer, bool bigEndian)
{
    return static_cast<uint8_t>(toInt8(buffer, bufPointer, bigEndian));
}


int16_t toInt16(char* buffer, int& bufPointer, bool bigEndian)
{
    bufPointer += 2;
    if(bigEndian) {
        return  (static_cast<int16_t>(buffer[bufPointer - 1]) << 8)  & 0xFF00 |
                (static_cast<int16_t>(buffer[bufPointer - 2]))       & 0x00FF;
    } else {
        return  (static_cast<int16_t>(buffer[bufPointer - 2]) << 8)  & 0xFF00 |
                (static_cast<int16_t>(buffer[bufPointer - 1]))       & 0x00FF;
    }
}

uint16_t toUint16(char* buffer, int& bufPointer, bool bigEndian)
{
    return static_cast<uint16_t>(toInt16(buffer, bufPointer, bigEndian));
}

int32_t toInt32(char* buffer, int& bufPointer, bool bigEndian)
{
    bufPointer += 4;

    if(bigEndian) {
        return (static_cast<int32_t>(buffer[bufPointer - 4]) << 24) & 0xFF000000 |
               (static_cast<int32_t>(buffer[bufPointer - 3]) << 16) & 0x00FF0000 |
               (static_cast<int32_t>(buffer[bufPointer - 2]) << 8)  & 0x0000FF00 |
                static_cast<int32_t>(buffer[bufPointer - 1])        & 0x000000FF;
    } else {
        return (static_cast<int32_t>(buffer[bufPointer - 1]) << 24) & 0xFF000000 |
               (static_cast<int32_t>(buffer[bufPointer - 2]) << 16) & 0x00FF0000 |
               (static_cast<int32_t>(buffer[bufPointer - 3]) << 8)  & 0x0000FF00 |
                static_cast<int32_t>(buffer[bufPointer - 4])        & 0x000000FF;
    }
}

uint32_t toUint32(char* buffer, int& bufPointer, bool bigEndian)
{
    return static_cast<uint32_t>(toInt32(buffer, bufPointer, bigEndian));
}
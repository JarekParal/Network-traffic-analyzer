//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 11.11.2016.
//

#include "convert.h"

int16_t toInt16(char * buffer, int bufPointer)
{
    return  (((int16_t)buffer[bufPointer + 0]) << 8)  & 0x0000FF00 |
            ((int16_t)buffer[bufPointer + 1])         & 0x000000FF;
}

uint16_t toUint16(char * buffer, int bufPointer)
{
    return uint16_t(toInt16(buffer, bufPointer));
}

int32_t toInt32(char * buffer, int bufPointer)
{
    return  (((int32_t)buffer[bufPointer + 0]) << 24) & 0xFF000000 |
            (((int32_t)buffer[bufPointer + 1]) << 16) & 0x00FF0000 |
            (((int32_t)buffer[bufPointer + 2]) << 8)  & 0x0000FF00 |
            ((int32_t)buffer[bufPointer + 3])         & 0x000000FF;
}

uint32_t toUint32(char * buffer, int bufPointer)
{
    return uint32_t(toInt32(buffer, bufPointer));
}
//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 11.11.2016.
//

#ifndef ISA_PROJECT_CONVERT_H
#define ISA_PROJECT_CONVERT_H

#include <cstdint>

int16_t toInt16(char* buffer, int& bufPointer, bool bigEndian = false);
uint16_t toUint16(char* buffer, int& bufPointer, bool bigEndian = false);
int32_t toInt32(char* buffer, int& bufPointer, bool bigEndian = false);
uint32_t toUint32(char* buffer, int& bufPointer, bool bigEndian = false);

#endif //ISA_PROJECT_CONVERT_H

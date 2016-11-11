//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 11.11.2016.
//

#ifndef ISA_PROJECT_CONVERT_H
#define ISA_PROJECT_CONVERT_H

#include <cstdint>

int16_t toInt16(char * buffer, int bufPointer);
uint16_t toUint16(char * buffer, int bufPointer);
int32_t toInt32(char * buffer, int bufPointer);
uint32_t toUint32(char * buffer, int bufPointer);

#endif //ISA_PROJECT_CONVERT_H

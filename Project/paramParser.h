//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 20.11.2016.
//

#ifndef ISA_PROJECT_PARAMPARSER_H
#define ISA_PROJECT_PARAMPARSER_H

#include <string>
#include <vector>
#include "filter.h"

typedef std::vector<std::string> warnings_t;

bool parseParameters(int argc, const char* argv[], std::string& inputFile, filter_t& filters, std::string* const error = nullptr, warnings_t* const warnings = nullptr);

#endif //ISA_PROJECT_PARAMPARSER_H

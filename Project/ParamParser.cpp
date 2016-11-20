//
// Created by JarekParal (xparal02@stud.fit.vutbr.cz) on 20.11.2016.
//

#include "ParamParser.h"
#include "packet.h"

#include <iostream>
//#include <libintl.h>    // This shoud be in cstdio, I don't know why it isn't there, but here
#include <cstdio>
#include <cctype>
#include <vector>
#include <unordered_map>
#include <utility>
#include <stdexcept>

using std::cout;
using std::endl;
using std::string;

#undef ERROR

// That's is nasty, but no time for dig a cleaner solution
#ifndef snprintf
#define snprintf _snprintf
#endif

#define TO_STRING(msg, ...)                             \
    const size_t maxSize = 1024;                        \
    char str[maxSize];                                  \
    snprintf(str, maxSize, msg, __VA_ARGS__)

#define WARNING(msg, ...)                               \
    if(warnings != nullptr) {                           \
        TO_STRING(msg, __VA_ARGS__);                    \
        warnings->push_back(string(str));               \
    }

#define ERROR(msg, ...) {                               \
    if(error != nullptr) {                              \
        TO_STRING(msg, __VA_ARGS__);                    \
        *error = str;                                   \
    }                                                   \
    return false;                                       \
}

const string SWITCHES_WITH_UNIQUE_DATA = "ifv";

const std::unordered_map<string, const filterTypeEnum> FILTER_TYPES = {
        { string(FILTERTYPE_MAC ),  filterTypeEnum::mac  },
        { string(FILTERTYPE_IPv4), filterTypeEnum::ipv4 },
        { string(FILTERTYPE_IPv6), filterTypeEnum::ipv6 },
        { string(FILTERTYPE_TCP ),  filterTypeEnum::tcp  },
        { string(FILTERTYPE_UDP ),  filterTypeEnum::udp  }
};

std::vector<string> split(const string& str, const char& sep = ' ') {
    std::vector<string> res;
    size_t i = 0;
    size_t j = 0;
    do {
        j = str.find(sep, i);
        res.push_back(str.substr(i, j == string::npos ? j : j - i));
        i = j + 1;
    } while(j != string::npos);
    return res;
}

bool hex2byte(const string& hex, uint8_t& res)
{
    if(hex.size() != 2)
        return false;
    res = 0;
    for(char c: hex) {
        res <<= 4;
        if(isdigit(c))
            res |= c - '0';
        else if(isxdigit(c))
            res |= tolower(c) - 'a' + 10;
        else
            return false;
    }
    return true;
}

bool dec2byte(const string& dec, uint8_t& res)
{
    if(dec.size() == 0 || dec.size() > 3)
        return false;
    res = 0;
    for(char c: dec) {
        if(!isdigit(c))
            return false;
        uint8_t last = res;
        res *= 10;
        if(res < last)
            return false;
        res += c - '0';
    }
    return true;
}

bool dec2word(const string& dec, uint16_t& res)
{
    if(dec.size() == 0 || dec.size() > 5)
        return false;
    res = 0;
    for(char c: dec) {
        if(!isdigit(c))
            return false;
        uint16_t last = res;
        res *= 10;
        if(res < last)
            return false;
        res += c - '0';
    }
    return true;
}

bool parseParameters(int argc, const char* argv[], std::string& inputFile, filter_t& filters, std::string* const error, warnings_t* const warnings) {
    for(auto kv: FILTER_TYPES)
        cout << '"' << kv.first << '"' << endl;
    cout << "Args:" << endl;
    inputFile.clear();
    bool filterTypeEnumPassed = false;
    bool filterValuePassed = false;
    string arg;
    char lastSwitch = 0;
    std::unordered_map<char, std::pair<int, int> > processedSwitches;
    for(int i = 1; i < argc; ++i) {
        arg = argv[i];
        if(arg.length() == 0)
            ERROR("It should not be possible, but argument with zero length encountered at position %d.", i);
        if(arg[0] == '-') {
            if(arg.length() == 1)
                ERROR("Switch statement introduced, but no identifier found at position %d.", i);
            for(int j = 1; j != arg.length(); ++j) {
                lastSwitch = arg[j];
                if(processedSwitches.count(lastSwitch) != 0) {
                    if(SWITCHES_WITH_UNIQUE_DATA.find_first_of(lastSwitch) != string::npos) {
                        ERROR("Switch %c redefined at position %d.%d (previous definition at %d.%d).",
                              lastSwitch, i, j, processedSwitches[lastSwitch].first, processedSwitches[lastSwitch].second);
                    }
                    else {
                        WARNING("Switch %c specified more than once (previous occurrence at position %d.%d, redefined at %d.%d).",
                                lastSwitch, processedSwitches[lastSwitch].first, processedSwitches[lastSwitch].second, i, j);
                    }
                }
                processedSwitches[lastSwitch] = std::make_pair(i, j);
                switch(lastSwitch) {
                    case 's':
                        filters.applySrc = true;
                        break;
                    case 'd':
                        filters.applyDst = true;
                        break;
                    case 'v':
                        if(processedSwitches.count('f') == 0)
                            ERROR("Filter type (switch f) has to be specified before filter values (switch v at position %d.%d).", i, j);
                    case 'i':
                    case 'f':
                        if(j != arg.length() - 1)
                            ERROR("Switch %c at position %d.%d require a value, but another switch found.", lastSwitch, i, j);
                        break;
                    default:
                        WARNING("Unknown option -%c at position %d.%d.", lastSwitch, i, j);
                        break;
                }
            }
        } else if(lastSwitch == 0) {
            ERROR("Encountered value without preceding identifier at position %d (%s)", i, arg.c_str());
        } else {
            switch(lastSwitch) {
                case 'i':
                    inputFile = arg;
                    break;
                case 'f':
                    for(auto v: split(arg, ';')) {
                        try {
                            filters.type.push_back(FILTER_TYPES.at(v));
                        } catch(std::out_of_range) {
                            ERROR("Unknown filter type '%s' at position %d.%d.", v.c_str(), i, filters.type.size() + 1);
                        }
                    }
                    filterTypeEnumPassed = true;
                    break;
                case 'v':
                    {
                        auto valuesPerFilter = split(arg, ';');
                        for(int j = 0; j != valuesPerFilter.size(); ++j)
                        {
                            for(auto v: split(valuesPerFilter[j], ',')) {
                                switch (filters.type[j]) {
                                    case filterTypeEnum::mac: {
                                            auto bytes = split(v, ':');
                                            if(bytes.size() != 6)
                                                ERROR("Invalid MAC address (too short) at position %d.%d.%d (%s).",
                                                    i, j, filters.mac.size() + 1, v.c_str());
                                            uint8_t k = 0;
                                            mac_addr_t addr;
                                            for(string& hex: bytes) {
                                                if(!hex2byte(hex, addr.addr_bytes[k++]))
                                                    ERROR("Invalid charracter in MAC address at position %d.%d.%d.%d (%s)",
                                                          i, j, filters.mac.size() + 1, k + 1, hex.c_str());
                                            }
                                            filters.mac.push_back(addr);
                                        }
                                        break;
                                    case filterTypeEnum::ipv4: {
                                            auto bytes = split(v, '.');
                                            if(bytes.size() != 4)
                                            ERROR("Invalid IPv4 address (too short) at position %d.%d.%d (%s).",
                                                  i, j, filters.mac.size() + 1, v.c_str());
                                            uint8_t k = 0;
                                            ipv4_addr_t addr;
                                            for(string& dec: bytes) {
                                                if(!dec2byte(dec, addr.addr_bytes[k++]))
                                                    ERROR("Invalid charracter in IPv4 address at position %d.%d.%d.%d (%s)",
                                                        i, j, filters.ipv4.size() + 1, k + 1, dec.c_str());
                                            }
                                            filters.ipv4.push_back(addr);
                                        }
                                        break;
                                    case filterTypeEnum::ipv6:

                                        break;
                                    case filterTypeEnum::tcp: {
                                            uint16_t port = 0;
                                            if (!dec2word(v, port))
                                            ERROR("Invalid charracter in TCP port at position %d.%d.%d (%s)",
                                                  i, j, filters.port.size() + 1, v.c_str());
                                            filters.port.push_back(port);
                                        }
                                        break;
                                    case filterTypeEnum::udp: {
                                            uint16_t port = 0;
                                            if (!dec2word(v, port))
                                            ERROR("Invalid charracter in TCP port at position %d.%d.%d (%s)",
                                                  i, j, filters.port.size() + 1, v.c_str());
                                            filters.port.push_back(port);
                                        }
                                        break;
                                }
                            }
                        }
                    }
                    filterValuePassed = true;
                    break;
                default:
                    ERROR("Switch %c at position %d.%d does not take any arguments, but one passed.",
                          lastSwitch, processedSwitches[lastSwitch].first, processedSwitches[lastSwitch].second);
                    break;
            }
            lastSwitch = 0;
        }
    }
    if(inputFile.empty())
        ERROR("No input file specified.", 0);
    if(!filterTypeEnumPassed)
        ERROR("No filter specified.", 0);
    if(!filterValuePassed)
        ERROR("No filter value specified.", 0);
    if(!(filters.applySrc || filters.applyDst))
        ERROR("Non of source or destination applied.", 0);
    cout << "Args parsing done."<<endl;
    return true;
};
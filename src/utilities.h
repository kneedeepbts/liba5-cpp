#ifndef LIBA5_UTILITIES_H
#define LIBA5_UTILITIES_H

#include <array>
#include <cstdint>
#include <string>

namespace kneedeepbts::crypto {
        uint8_t hextoint(char x);
        std::array<uint8_t, 16> convertSTR16ARR(std::string value);
        std::array<uint8_t, 4> convertSTR4ARR(std::string value);
    }

#endif //LIBA5_UTILITIES_H

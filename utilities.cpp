#include "utilities.h"
namespace kneedeepbts::crypto {
    uint8_t hextoint(char x) {
        x = static_cast<char>(std::toupper(static_cast<unsigned char>(x)));
        if (x >= 'A' && x <= 'F') {
            return x - 'A' + 10;
        }
        if (x >= '0' && x <= '9') {
            return x - '0';
        }
        return 255;
    }

    std::array<uint8_t, 16> convertSTR16ARR(std::string value) {
        std::array<uint8_t, 16> out{};

        if (value.length() == 32) { // 32 hex digits sans the '0x' -> 16 bytes
            for (uint8_t i = 0; i < 16; i++) {
                out[i] = hextoint(value[2 * i]) << 4 | hextoint(value[(2 * i) + 1]);
            }
        }
        return out;
    }

    std::array<uint8_t, 4> convertSTR4ARR(std::string value) {
        std::array<uint8_t, 4> out{};

        if (value.length() == 8) { // 32 hex digits sans the '0x' -> 16 bytes
            for (uint8_t i = 0; i < 4; i++) {
                out[i] = hextoint(value[2 * i]) << 4 | hextoint(value[(2 * i) + 1]);
            }
        }
        return out;
    }
}
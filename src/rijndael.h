#ifndef _RIJNDAEL_H
#define _RIJNDAEL_H

/*
 * Using spec at https://www.etsi.org/deliver/etsi_ts/135200_135299/135206/14.00.00_60/ts_135206v140000p.pdf
 */

#include <cstdint>
#include <array>

namespace kneedeepbts::crypto {
        typedef struct RijndaelKey { std::array<uint8_t, 16> value; } RijndaelKey;

        class Rijndael {
            public:
                explicit Rijndael(RijndaelKey key);
                //void setKey(std::array<uint8_t, 16> value);
                std::array<uint8_t, 16> encrypt(std::array<uint8_t, 16> value);

            private:
                RijndaelKey m_key{};

                std::array<uint8_t, 176> roundKeys{}; // 11*4*4, (x*16)+(y*4)+(z)
                std::array<uint8_t, 16> state{};

                void setup_round_keys();
                void KeyAdd(uint8_t round);
                void ByteSub();
                void ShiftRow();
                void MixColumn();
        };
    }

#endif // _RIJNDAEL_H

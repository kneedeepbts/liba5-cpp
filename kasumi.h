#ifndef LIBA5_KASUMI_H
#define LIBA5_KASUMI_H

#include <cstdint>

/* Kasumi block cipher
 * Algorithm written from Wikipedia: https://en.wikipedia.org/wiki/KASUMI
 * Fixed per the "3GPP TS 35.202 V17.0.0 (2022-03)" specification.
 * RangeNetworks code was available for reference when writing:
 *    https://github.com/RangeNetworks/liba53
 */

namespace kneedeepbts {
    typedef struct KasumiKey { uint16_t subkeys[8]; } KasumiKey;

    KasumiKey operator ^ (const KasumiKey& lhs, const KasumiKey& rhs);

    class Kasumi {
        public:
            explicit Kasumi(KasumiKey key);

            // Methods to run the cipher
            uint64_t run(uint64_t input);

        private:
            // Main Keys
            KasumiKey m_key{};
            KasumiKey m_key_prime{};

            // Magic Keys
            KasumiKey m_nums{0x0123, 0x4567, 0x89AB, 0xCDEF, 0xFEDC, 0xBA98, 0x7654, 0x3210};

            // Round Keys
            KasumiKey m_kl1{};
            KasumiKey m_kl2{};
            KasumiKey m_ko1{};
            KasumiKey m_ko2{};
            KasumiKey m_ko3{};
            KasumiKey m_ki1{};
            KasumiKey m_ki2{};
            KasumiKey m_ki3{};
            uint8_t m_subkey_index = 0;

            // Helper Methods
            void setup_round_keys();
            uint32_t func_fl(uint32_t input);
            uint16_t func_fi(uint16_t input, uint16_t ki_key);
            uint32_t func_fo(uint32_t input);
    };
}

#endif //LIBA5_KASUMI_H

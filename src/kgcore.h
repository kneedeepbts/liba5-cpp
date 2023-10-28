#ifndef LIBA5_KGCORE_H
#define LIBA5_KGCORE_H

#include <cstdint>

#include "kasumi.h"

/* Found a copy of "3GPP TS 55.216 V6.2.0 (2003-09)" online, so working from that.
 */

// FIXME: Add a logging library to this class.
// FIXME: Use smart pointers.

namespace kneedeepbts::crypto {
    class KGCore {
        public:
            KGCore(uint8_t ca, uint8_t cb, uint32_t cc, bool cd, uint16_t ce, KasumiKey ck, uint32_t cl);
            KGCore(uint8_t ca, uint8_t cb, uint32_t cc, bool cd, uint16_t ce, const uint8_t * ck, uint32_t cl);

            // Outputs
            uint8_t *m_co = nullptr;

            // Methods to run the cipher
            void run();

        private:
            // Inputs
            uint8_t m_ca = 0;
            uint8_t m_cb = 0;
            uint32_t m_cc = 0;
            bool m_cd = false;
            uint16_t m_ce = 0;
            KasumiKey m_ck{};
            uint32_t m_cl = 0;
            // Magic Key
            KasumiKey m_km{0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555};
    };
}

#endif //LIBA5_KGCORE_H

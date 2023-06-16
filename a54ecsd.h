#ifndef LIBA5_A54ECSD_H
#define LIBA5_A54ECSD_H

#include <cstdint>

#include "kgcore.h"

// FIXME: Use smart pointers.

namespace kneedeepbts {
    class A54ECSD {
        public:
            A54ECSD(uint8_t * kc, uint8_t klen, uint32_t count);

            // Outputs
            uint8_t *m_block1 = new uint8_t[44];
            uint8_t *m_block2 = new uint8_t[44];

            // Methods to run the cipher
            void run();

        private:
            // Inputs
            uint8_t *m_kc = nullptr;
            uint8_t m_klen = 0;
            uint32_t m_count = 0;
    };
}

#endif //LIBA5_A54ECSD_H

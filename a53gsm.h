#ifndef LIBA5_A53GSM_H
#define LIBA5_A53GSM_H

#include <cstdint>

#include "kgcore.h"

// FIXME: Add a logging library to this class.
// FIXME: Use smart pointers.

namespace kneedeepbts {
    class A53Gsm {
        public:
            A53Gsm(uint8_t* kc, uint8_t klen, uint32_t count);

            // Outputs
            uint8_t *m_block1 = new uint8_t[15];
            uint8_t *m_block2 = new uint8_t[15];

            // Methods to run the cipher
            void run();
        private:
            // Inputs
            uint8_t *m_kc = nullptr;
            uint8_t m_klen = 0;
            uint32_t m_count = 0;
    };
}

#endif //LIBA5_A53GSM_H

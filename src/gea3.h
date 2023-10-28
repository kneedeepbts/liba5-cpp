#ifndef LIBA5_GEA3_H
#define LIBA5_GEA3_H

#include <cstdint>

#include "kgcore.h"

// FIXME: Use smart pointers.

namespace kneedeepbts::crypto {
    class GEA3 {
        public:
            GEA3(uint32_t input, bool direction, uint8_t * kc, uint8_t klen, uint16_t m);

            // Output
            uint8_t * m_output = nullptr;

            // Methods to run the cipher
            void run();

        private:
            // Inputs
            uint32_t m_input = 0;
            bool m_dir = false;
            uint8_t * m_kc = nullptr;
            uint8_t m_klen = 0;
            uint16_t m_m = 0;
    };
}

#endif //LIBA5_GEA3_H

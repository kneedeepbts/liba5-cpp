#include "gea4.h"

#include <cassert>

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#include "spdlog/spdlog.h"

namespace kneedeepbts {
    GEA4::GEA4(uint32_t input, bool direction, uint8_t * kc, uint8_t klen, uint16_t m) {
        m_input = input;
        m_dir = direction;
        m_kc = kc;
        m_klen = klen;
        m_m = m;
    }

    void GEA4::run() {
        assert(m_klen == 128);
        SPDLOG_DEBUG("m_klen: {:d}, m_dir: {:d}, m_m: {:d}, m_input: 0x{:08X}", m_klen, m_dir, m_m, m_input);
        // NOTE: The GEA4 specification only allows KLEN to be 128 bits.
        m_output = new uint8_t[m_m * 8];
        KasumiKey ckk = KasumiKey{};
        for (int i = 0; i < 8; i++) {
            ckk.subkeys[i] = ((uint16_t)m_kc[i * 2] << 8) | (uint16_t)m_kc[(i * 2) + 1];
        }
        SPDLOG_TRACE("ckk[0]: 0x{:04X}, ckk[1]: 0x{:04X}, ckk[2]: 0x{:04X}, ckk[3]: 0x{:04X}, ckk[4]: 0x{:04X}, ckk[5]: 0x{:04X}, ckk[6]: 0x{:04X}, ckk[7]: 0x{:04X}", ckk.subkeys[0], ckk.subkeys[1], ckk.subkeys[2], ckk.subkeys[3], ckk.subkeys[4], ckk.subkeys[5], ckk.subkeys[6], ckk.subkeys[7]);
        KGCore kgc = KGCore(0xFF, 0x00, m_input, m_dir, 0x0000, ckk, m_m * 8);
        kgc.run();
        // Extract the blocks from the KGCORE output.
        for (int i = 0; i < (m_m * 8); i++) {
            m_output[i] = kgc.m_co[i];
        }
    }
}


#include "a54ecsd.h"

#include <cassert>

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#include "spdlog/spdlog.h"

namespace kneedeepbts {
    A54ECSD::A54ECSD(uint8_t* kc, uint8_t klen, uint32_t count) {
        m_kc = kc;
        m_klen = klen;
        m_count = count;
    }

    void A54ECSD::run() {
        assert(m_klen == 128);
        assert(m_count < 0x003FFFFF);
        SPDLOG_DEBUG("m_klen: {:d}, m_count: 0x{:X}", m_klen, m_count);
        // NOTE: The A5/4 specification only allows KLEN to be 128 bits.
        KasumiKey ckk = KasumiKey{};
        for (int i = 0; i < 8; i++) {
            ckk.subkeys[i] = ((uint16_t)m_kc[i * 2] << 8) | (uint16_t)m_kc[(i * 2) + 1];
        }
        SPDLOG_TRACE("ckk[0]: 0x{:04X}, ckk[1]: 0x{:04X}, ckk[2]: 0x{:04X}, ckk[3]: 0x{:04X}, ckk[4]: 0x{:04X}, ckk[5]: 0x{:04X}, ckk[6]: 0x{:04X}, ckk[7]: 0x{:04X}", ckk.subkeys[0], ckk.subkeys[1], ckk.subkeys[2], ckk.subkeys[3], ckk.subkeys[4], ckk.subkeys[5], ckk.subkeys[6], ckk.subkeys[7]);
        KGCore kgc = KGCore(0xF0, 0x00, m_count, false, 0x0000, ckk, 696);
        kgc.run();
        // Extract the two blocks from the KGCORE output.
        for (int i = 0; i < 44; i++) {
            // Block 1
            m_block1[i] = kgc.m_co[i];
            // Block 2
            m_block2[i] = ((kgc.m_co[i + 43] & 0x3F) << 4) | ((kgc.m_co[i + 44] & 0xF0) >> 4);
        }
        // Cleanup the end of both
        m_block1[43] = m_block1[43] & 0xF0;
        m_block2[43] = m_block2[43] & 0xF0;
    }
}

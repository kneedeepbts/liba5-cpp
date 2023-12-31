#include "a53gsm.h"

#include <cassert>

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#include "spdlog/spdlog.h"

namespace kneedeepbts::crypto {
    A53GSM::A53GSM(uint8_t* kc, uint8_t klen, uint32_t count) {
        m_kc = kc;
        m_klen = klen;
        m_count = count;
    }

    void A53GSM::run() {
        assert(m_klen == 64);
        assert(m_count < 0x003FFFFF);
        SPDLOG_DEBUG("m_klen: {:d}, m_count: 0x{:X}", m_klen, m_count);
        // NOTE: The A5/3 specification only allows KLEN to be 64 bits.
        KasumiKey ckk = KasumiKey{};
        for (int i = 0; i < 4; i++) {
            ckk.subkeys[i] = ((uint16_t)m_kc[i * 2] << 8) | (uint16_t)m_kc[(i * 2) + 1];
            ckk.subkeys[i + 4] = ((uint16_t)m_kc[i * 2] << 8) | (uint16_t)m_kc[(i * 2) + 1];
        }
        SPDLOG_TRACE("ckk[0]: 0x{:04X}, ckk[1]: 0x{:04X}, ckk[2]: 0x{:04X}, ckk[3]: 0x{:04X}, ckk[4]: 0x{:04X}, ckk[5]: 0x{:04X}, ckk[6]: 0x{:04X}, ckk[7]: 0x{:04X}", ckk.subkeys[0], ckk.subkeys[1], ckk.subkeys[2], ckk.subkeys[3], ckk.subkeys[4], ckk.subkeys[5], ckk.subkeys[6], ckk.subkeys[7]);
        KGCore kgc = KGCore(0x0F, 0x00, m_count, false, 0x0000, ckk, 228);
        kgc.run();
        // Extract the two blocks from the KGCORE output.
        // NOTE: The RangeNetworks (really OsmoCom under the hood) library runs the KGCORE twice, once with cl = 228 and
        //       again with cl = 114.  This seems to imply that the output of the second run is the same as the second
        //       half of the first run...
        for (int i = 0; i < 15; i++) {
            // Block 1
            m_block1[i] = kgc.m_co[i];
            // Block 2
            m_block2[i] = ((kgc.m_co[i + 14] & 0x3F) << 2) | ((kgc.m_co[i + 15] & 0xC0) >> 6);
        }
        // Cleanup the end of both
        m_block1[14] = m_block1[14] & 0xC0;
        m_block2[14] = m_block2[14] & 0xC0;
    }
}

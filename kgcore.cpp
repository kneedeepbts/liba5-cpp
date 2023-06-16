#include "kgcore.h"

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#include "spdlog/spdlog.h"

namespace kneedeepbts {
    KGCore::KGCore(uint8_t ca, uint8_t cb, uint32_t cc, bool cd, uint16_t ce, KasumiKey ck, uint32_t cl) {
        m_ca = ca;
        m_cb = cb;
        m_cc = cc;
        m_cd = cd;
        m_ce = ce;
        m_ck = ck;
        m_cl = cl;
        m_co = new uint8_t[cl];
    }

    KGCore::KGCore(uint8_t ca, uint8_t cb, uint32_t cc, bool cd, uint16_t ce, const uint8_t * ck, uint32_t cl) {
        m_ca = ca;
        m_cb = cb;
        m_cc = cc;
        m_cd = cd;
        m_ce = ce;
        // Pointer to array for uint8_t[16]
        for (int i = 0; i < 8; i++) {
            m_ck.subkeys[i] = ((uint16_t) ck[i * 2] << 8) | (uint16_t) ck[(i * 2) + 1];
        }
        m_cl = cl;
        m_co = new uint8_t[cl];
    }

    void KGCore::run() {
        Kasumi kasumi_init = Kasumi(m_ck ^ m_km);
        Kasumi kasumi_rounds = Kasumi(m_ck);
        uint16_t num_blocks = (m_cl / 64) + 1;
        SPDLOG_DEBUG("num_blocks: {:d}", num_blocks);

        // Initialize KGCore Algorithm
        uint64_t reg_a = ((uint64_t) m_cc << 32) | ((uint64_t) m_cb << 27) | ((uint64_t) m_cd << 26) | ((uint64_t) m_ca << 16) | ((uint64_t) m_ce);
        uint64_t * reg_ksb = new uint64_t[num_blocks + 1];
        reg_ksb[0] = 0;
        SPDLOG_TRACE("reg_a: 0x{:016X}", reg_a);
        reg_a = kasumi_init.run(reg_a);
        SPDLOG_TRACE("reg_a: 0x{:016X}", reg_a);

        // Generate Keystream
        for (uint64_t reg_blkcnt = 0; reg_blkcnt < num_blocks; reg_blkcnt++) {
            reg_ksb[reg_blkcnt + 1] = kasumi_rounds.run(reg_a ^ reg_blkcnt ^ reg_ksb[reg_blkcnt]);
            SPDLOG_TRACE("kasumi input: 0x{:016X}", reg_a ^ reg_blkcnt ^ reg_ksb[reg_blkcnt]);
            SPDLOG_TRACE("block: {:d}, reg_ksb: 0x{:016X}", reg_blkcnt + 1, reg_ksb[reg_blkcnt + 1]);
        }

        // Copy Blocks to Output
        m_co = new uint8_t[num_blocks * 8];
        for (int i = 0; i < num_blocks; i++) {
            uint64_t tmp_block = reg_ksb[i + 1];
            for (int j = 7; j >= 0; j--) {
                m_co[(i * 8) + j] = (uint8_t)(tmp_block & 0xFF);
                tmp_block = tmp_block >> 8;
            }
        }
    }
}

// 0x32109876 54321098 76543210 98765432  10987654 32109876 54321098 76543210
// 0x55555555 55555555 55555555 55555555
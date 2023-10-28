#include "doctest/doctest.h"

#include "spdlog/spdlog.h"

#include "../src/kgcore.h"

/*
 * Test Data has been pulled from "3GPP TS 55.217 V6.1.0 (2002-12)".
 */

TEST_CASE("Testing the KGCore class with (3.3) Test Set 1") {
    spdlog::set_level(spdlog::level::info);
    kneedeepbts::crypto::KasumiKey t_key{0x2BD6, 0x459F, 0x82C5, 0xBC00, 0x2BD6, 0x459F, 0x82C5, 0xBC00};
    uint8_t t_ca = 0x0F;
    uint8_t t_cb = 0;
    uint32_t t_cc = 0x0024F20F;
    bool t_cd = false;
    uint16_t t_ce = 0; // Not used, future use.
    uint32_t t_cl = 228;

    kneedeepbts::crypto::KGCore dut_kgcore(t_ca, t_cb, t_cc, t_cd, t_ce, t_key, t_cl);
    dut_kgcore.run();

    uint8_t expected[8 * 4] = {
            0x88, 0x9E, 0xEA, 0xAF, 0x9E, 0xD1, 0xBA, 0x1A,
            0xBB, 0xD8, 0x43, 0x62, 0x32, 0xE4, 0x57, 0x28,
            0xD0, 0x1A, 0xA8, 0x91, 0x33, 0xDA, 0x73, 0xC1,
            0x1E, 0xAB, 0x68, 0xB7, 0xD8, 0x9B, 0xC8, 0x41
    };
    for (int i = 0; i < (8 * 4); i++) {
        CHECK(expected[i] == dut_kgcore.m_co[i]);
    }
}

TEST_CASE("Testing the KGCore class with (3.4) Test Set 2") {
    spdlog::set_level(spdlog::level::info);
    kneedeepbts::crypto::KasumiKey t_key{0x952C, 0x4910, 0x4881, 0xFF48, 0x952C, 0x4910, 0x4881, 0xFF48};
    uint8_t t_ca = 0x0F;
    uint8_t t_cb = 0;
    uint32_t t_cc = 0x00061272;
    bool t_cd = false;
    uint16_t t_ce = 0; // Not used, future use.
    uint32_t t_cl = 228;

    kneedeepbts::crypto::KGCore dut_kgcore(t_ca, t_cb, t_cc, t_cd, t_ce, t_key, t_cl);
    dut_kgcore.run();

    uint8_t expected[8 * 4] = {
            0xFB, 0x4D, 0x5F, 0xBC, 0xEE, 0x13, 0xA3, 0x33,
            0x89, 0x28, 0x56, 0x86, 0xE9, 0xA5, 0xC9, 0x42,
            0x40, 0xDE, 0x38, 0x15, 0x01, 0x15, 0xF1, 0x5F,
            0x8D, 0x9D, 0x98, 0xB9, 0x1A, 0x94, 0xB2, 0x96
    };
    for (int i = 0; i < (8 * 4); i++) {
        CHECK(expected[i] == dut_kgcore.m_co[i]);
    }
}

TEST_CASE("Testing the KGCore class with (3.5) Test Set 3") {
    spdlog::set_level(spdlog::level::info);
    kneedeepbts::crypto::KasumiKey t_key{0xEFA8, 0xB222, 0x9E72, 0x0C2A, 0xEFA8, 0xB222, 0x9E72, 0x0C2A};
    uint8_t t_ca = 0x0F;
    uint8_t t_cb = 0;
    uint32_t t_cc = 0x0033FD3F;
    bool t_cd = false;
    uint16_t t_ce = 0; // Not used, future use.
    uint32_t t_cl = 228;

    kneedeepbts::crypto::KGCore dut_kgcore(t_ca, t_cb, t_cc, t_cd, t_ce, t_key, t_cl);
    dut_kgcore.run();

    uint8_t expected[8 * 4] = {
            0x0E, 0x40, 0x15, 0x75, 0x5A, 0x33, 0x64, 0x69,
            0xC3, 0xDD, 0x86, 0x80, 0xE3, 0x03, 0x5B, 0xC4,
            0x19, 0xA7, 0x8A, 0xD3, 0x86, 0x2C, 0x10, 0x90,
            0xC6, 0x8A, 0x39, 0x1F, 0xE8, 0xA6, 0xAD, 0xEB
    };
    for (int i = 0; i < (8 * 4); i++) {
        CHECK(expected[i] == dut_kgcore.m_co[i]);
    }
}

TEST_CASE("Testing the KGCore class with (3.6) Test Set 4") {
    spdlog::set_level(spdlog::level::info);
    kneedeepbts::crypto::KasumiKey t_key{0x5ACB, 0x1D64, 0x4C0D, 0x5120, 0x4EA5, 0x5ACB, 0x1D64, 0x4C0D};
    uint8_t t_ca = 0x0F;
    uint8_t t_cb = 0;
    uint32_t t_cc = 0x00156B26;
    bool t_cd = false;
    uint16_t t_ce = 0; // Not used, future use.
    uint32_t t_cl = 228;

    kneedeepbts::crypto::KGCore dut_kgcore(t_ca, t_cb, t_cc, t_cd, t_ce, t_key, t_cl);
    dut_kgcore.run();

    uint8_t expected[8 * 4] = {
            0xE0, 0x95, 0x30, 0x6A, 0xD5, 0x08, 0x6E, 0x2E,
            0xAC, 0x7F, 0x31, 0x07, 0xDE, 0x4F, 0xA2, 0x2D,
            0xC1, 0xDF, 0xC9, 0x7D, 0x5B, 0xC5, 0x66, 0x1D,
            0xD6, 0x09, 0x6F, 0x47, 0x6A, 0xED, 0xC6, 0x4B
    };
    for (int i = 0; i < (8 * 4); i++) {
        CHECK(expected[i] == dut_kgcore.m_co[i]);
    }
}

TEST_CASE("Testing the KGCore class with (3.7) Test Set 5") {
    spdlog::set_level(spdlog::level::info);
    kneedeepbts::crypto::KasumiKey t_key{0xD3C5, 0xD592, 0x327F, 0xB11C, 0x4035, 0xC668, 0x0AF8, 0xC6D1};
    uint8_t t_ca = 0x0F;
    uint8_t t_cb = 0;
    uint32_t t_cc = 0x000A59B4;
    bool t_cd = false;
    uint16_t t_ce = 0; // Not used, future use.
    uint32_t t_cl = 228;

    kneedeepbts::crypto::KGCore dut_kgcore(t_ca, t_cb, t_cc, t_cd, t_ce, t_key, t_cl);
    dut_kgcore.run();

    uint8_t expected[8 * 4] = {
            0xDC, 0xE6, 0x43, 0x62, 0xAB, 0x5F, 0x89, 0xC1,
            0x1E, 0xF0, 0xB3, 0x05, 0x16, 0x65, 0x70, 0xF4,
            0x88, 0x9D, 0x55, 0x11, 0xE9, 0xE3, 0x57, 0x5D,
            0x06, 0x2B, 0x5C, 0xED, 0x60, 0x39, 0x50, 0x6A
    };
    for (int i = 0; i < (8 * 4); i++) {
        CHECK(expected[i] == dut_kgcore.m_co[i]);
    }
}

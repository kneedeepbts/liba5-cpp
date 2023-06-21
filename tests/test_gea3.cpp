#include "doctest.h"

#include "spdlog/spdlog.h"

#include "../gea3.h"

/*
 * Test Data has been pulled from "3GPP TS 55.217 V6.1.0 (2002-12)".
 */

TEST_CASE("Testing the GEA3 class with (5.3) Test Set 1") {
    spdlog::set_level(spdlog::level::info);
    uint8_t t_kc[8] = {0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xBC, 0x00};
    uint8_t t_klen = 64;
    uint32_t t_input = 0x5124F20F;
    bool t_dir = true;
    uint16_t t_m = 51;

    kneedeepbts::crypto::GEA3 dut_gea3(t_input, t_dir, t_kc, t_klen, t_m);
    dut_gea3.run();

    uint8_t expected[51] = {
            0xF0, 0x27, 0x0A, 0xAF, 0x26, 0x85, 0x1D, 0x2A, 0x4E, 0x88, 0xCC, 0x48,
            0xCB, 0xFC, 0x74, 0x0D, 0x94, 0xAC, 0xAB, 0x84, 0x95, 0xD2, 0x7A, 0x7E,
            0x15, 0x4F, 0x5D, 0xA9, 0xE9, 0x91, 0xEF, 0x8A, 0x41, 0x98, 0xC7, 0x36,
            0x96, 0x55, 0xE5, 0xB9, 0x72, 0xDA, 0x2B, 0x05, 0xCF, 0x4C, 0xD3, 0x94,
            0xB1, 0x32, 0xEB
    };

    for (int i = 0; i < t_m; i++) {
        CHECK(expected[i] == dut_gea3.m_output[i]);
    }
}

TEST_CASE("Testing the GEA3 class with (5.4) Test Set 2") {
    spdlog::set_level(spdlog::level::info);
    uint8_t t_kc[8] = {0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48};
    uint8_t t_klen = 64;
    uint32_t t_input = 0xD3861272;
    bool t_dir = false;
    uint16_t t_m = 51;

    kneedeepbts::crypto::GEA3 dut_gea3(t_input, t_dir, t_kc, t_klen, t_m);
    dut_gea3.run();

    uint8_t expected[51] = {
            0x9B, 0x7B, 0x51, 0x6B, 0x15, 0xFB, 0x65, 0xE2, 0x83, 0xB7, 0x22, 0xDB,
            0xE3, 0xA2, 0xCF, 0xCB, 0x0B, 0x25, 0x5C, 0xFB, 0x38, 0xD5, 0x29, 0xB9,
            0x61, 0xBC, 0x04, 0x12, 0x9D, 0x5C, 0x65, 0x65, 0xAA, 0x25, 0xC3, 0x1E,
            0x63, 0xD1, 0x0A, 0x04, 0x81, 0x91, 0xBC, 0x1F, 0x17, 0xE6, 0x7E, 0xCA,
            0xAA, 0x50, 0x9A
    };

    for (int i = 0; i < t_m; i++) {
        CHECK(expected[i] == dut_gea3.m_output[i]);
    }
}

TEST_CASE("Testing the GEA3 class with (5.4) Test Set 3") {
    spdlog::set_level(spdlog::level::info);
    uint8_t t_kc[8] = {0xEF, 0xA8, 0xB2, 0x22, 0x9E, 0x72, 0x0C, 0x2A};
    uint8_t t_klen = 64;
    uint32_t t_input = 0x4AB3FD3F;
    bool t_dir = false;
    uint16_t t_m = 51;

    kneedeepbts::crypto::GEA3 dut_gea3(t_input, t_dir, t_kc, t_klen, t_m);
    dut_gea3.run();

    uint8_t expected[51] = {
            0x03, 0x06, 0xB1, 0xF1, 0xE6, 0x28, 0x6F, 0x27, 0x14, 0x8F, 0xF4, 0xF0,
            0x81, 0x16, 0x4E, 0xA3, 0x05, 0xE3, 0x29, 0x61, 0x21, 0xF5, 0x64, 0x91,
            0xA3, 0xBB, 0xEA, 0xB4, 0x8E, 0xF8, 0x24, 0xB3, 0x64, 0xD3, 0x04, 0x94,
            0x6D, 0xCA, 0x46, 0x77, 0x3F, 0x3A, 0x54, 0x86, 0x42, 0xC6, 0x85, 0x45,
            0xC0, 0xFE, 0xE0
    };

    for (int i = 0; i < t_m; i++) {
        CHECK(expected[i] == dut_gea3.m_output[i]);
    }
}

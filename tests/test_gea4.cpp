#include "doctest.h"

#include "spdlog/spdlog.h"

#include "../gea4.h"

/*
 * Test Data has been pulled from "3GPP TS 55.217 V6.1.0 (2002-12)".
 */

TEST_CASE("Testing the GEA4 class with (5.7) Test Set 5") {
    spdlog::set_level(spdlog::level::info);
    uint8_t t_kc[16] = {0xD3, 0xC5, 0xD5, 0x92, 0x32, 0x7F, 0xB1, 0x1C, 0x40, 0x35, 0xC6, 0x68, 0x0A, 0xF8, 0xC6, 0xD1};
    uint8_t t_klen = 128;
    uint32_t t_input = 0x0A3A59B4;
    bool t_dir = false;
    uint16_t t_m = 51;

    kneedeepbts::crypto::GEA4 dut_gea4(t_input, t_dir, t_kc, t_klen, t_m);
    dut_gea4.run();

    uint8_t expected[51] = {
            0x6E, 0x21, 0x7C, 0xE4, 0x1E, 0xBE, 0xFB, 0x5E, 0xC8, 0x09, 0x4C, 0x15,
            0x97, 0x42, 0x90, 0x06, 0x5E, 0x42, 0xBA, 0xBC, 0x9A, 0xE3, 0x56, 0x54,
            0xA5, 0x30, 0x85, 0xCE, 0x68, 0xDF, 0xA4, 0x42, 0x6A, 0x2F, 0xF0, 0xAD,
            0x4A, 0xF3, 0x34, 0x10, 0x06, 0xA3, 0xF8, 0x4B, 0x76, 0x13, 0xAC, 0xB4,
            0xFB, 0xDC, 0x34
    };

    for (int i = 0; i < t_m; i++) {
        CHECK(expected[i] == dut_gea4.m_output[i]);
    }
}

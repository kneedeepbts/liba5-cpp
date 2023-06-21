#include "doctest.h"

#include "spdlog/spdlog.h"

#include "../a54gsm.h"

/*
 * Test Data has been pulled from "3GPP TS 55.217 V6.1.0 (2002-12)".
 */

TEST_CASE("Testing the A54GSM class with (3.7) Test Set 5") {
    spdlog::set_level(spdlog::level::info);
    uint8_t t_kc[16] = {0xD3, 0xC5, 0xD5, 0x92, 0x32, 0x7F, 0xB1, 0x1C, 0x40, 0x35, 0xC6, 0x68, 0x0A, 0xF8, 0xC6, 0xD1};
    uint8_t t_klen = 128;
    uint32_t t_count = 0x000A59B4;

    kneedeepbts::crypto::A54GSM dut_a54gsm(t_kc, t_klen, t_count);
    dut_a54gsm.run();

    uint8_t expected_block1[15] = {0xDC, 0xE6, 0x43, 0x62, 0xAB, 0x5F, 0x89, 0xC1, 0x1E, 0xF0, 0xB3, 0x05, 0x16, 0x65, 0x40};
    uint8_t expected_block2[15] = {0xC3, 0xD2, 0x22, 0x75, 0x54, 0x47, 0xA7, 0x8D, 0x5D, 0x74, 0x18, 0xAD, 0x73, 0xB5, 0x80};

    for (int i = 0; i < 15; i++) {
        CHECK(expected_block1[i] == dut_a54gsm.m_block1[i]);
        CHECK(expected_block2[i] == dut_a54gsm.m_block2[i]);
    }
}

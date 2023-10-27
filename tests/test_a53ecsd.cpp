#include "doctest/doctest.h"

#include "spdlog/spdlog.h"

#include "../a53ecsd.h"

/*
 * Test Data has been pulled from "3GPP TS 55.217 V6.1.0 (2002-12)".
 */

TEST_CASE("Testing the A53ECSD class with (4.3) Test Set 1") {
    spdlog::set_level(spdlog::level::info);
    uint8_t t_kc[8] = {0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xBC, 0x00};
    uint8_t t_klen = 64;
    uint32_t t_count = 0x0024F20F;

    kneedeepbts::crypto::A53ECSD dut_a53ecsd(t_kc, t_klen, t_count);
    dut_a53ecsd.run();

    uint8_t expected_block1[44] = {
            0xF7, 0x5E, 0x66, 0x3A, 0xCE, 0xA2, 0x1E, 0xC9, 0xD0, 0xBD, 0xE9, 0x8B,
            0x6C, 0x33, 0xB8, 0x19, 0x29, 0x9E, 0x83, 0x0A, 0x1A, 0x2E, 0x2F, 0x91,
            0x43, 0x26, 0xBE, 0xF5, 0x15, 0x08, 0x9B, 0x6D, 0xB0, 0xF2, 0x71, 0xAF,
            0xB9, 0x60, 0x9F, 0x90, 0x52, 0x02, 0xCD, 0xC0
    };
    uint8_t expected_block2[44] = {
            0xF5, 0x14, 0x26, 0xD1, 0x72, 0xDB, 0x47, 0xBF, 0xED, 0x3E, 0x6D, 0x83,
            0xD1, 0x4F, 0x48, 0x76, 0x36, 0x6C, 0xCC, 0xD5, 0xBF, 0xAE, 0x85, 0xB2,
            0x7C, 0x9B, 0x49, 0xF2, 0xF7, 0x77, 0x5B, 0x0B, 0x50, 0x49, 0x05, 0xF2,
            0x7B, 0x5A, 0xE6, 0x2B, 0x82, 0x69, 0xEA, 0x90
    };

    for (int i = 0; i < 44; i++) {
        CHECK(expected_block1[i] == dut_a53ecsd.m_block1[i]);
        CHECK(expected_block2[i] == dut_a53ecsd.m_block2[i]);
    }
}

TEST_CASE("Testing the A53ECSD class with (4.4) Test Set 2") {
    spdlog::set_level(spdlog::level::info);
    uint8_t t_kc[8] = {0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48};
    uint8_t t_klen = 64;
    uint32_t t_count = 0x00061272;

    kneedeepbts::crypto::A53ECSD dut_a53ecsd(t_kc, t_klen, t_count);
    dut_a53ecsd.run();

    uint8_t expected_block1[44] = {
            0xE1, 0x87, 0x6A, 0xA5, 0xB2, 0x50, 0xB2, 0xB8, 0xD5, 0x8A, 0xDE, 0x52,
            0x84, 0x4E, 0x84, 0xE1, 0x09, 0xA3, 0x8F, 0xF6, 0xA8, 0x7F, 0xCC, 0x7B,
            0x72, 0xFC, 0x83, 0x87, 0x49, 0x40, 0x86, 0xDB, 0xA2, 0xD2, 0xA1, 0xEE,
            0x18, 0x9D, 0xB5, 0x69, 0xA9, 0x24, 0x51, 0x50
    };
    uint8_t expected_block2[44] = {
            0x7C, 0xDD, 0x32, 0x3E, 0xA3, 0x51, 0x82, 0x70, 0xA1, 0x62, 0xC0, 0x54,
            0xE1, 0x20, 0xF5, 0xC7, 0x03, 0xAE, 0x0A, 0xB3, 0x24, 0x49, 0x8D, 0x40,
            0xD5, 0x62, 0x68, 0x74, 0x5C, 0x41, 0xBC, 0x58, 0xD7, 0x1D, 0xD2, 0x55,
            0xCC, 0xAC, 0x6B, 0xDA, 0x3B, 0x24, 0x43, 0x90
    };

    for (int i = 0; i < 44; i++) {
        CHECK(expected_block1[i] == dut_a53ecsd.m_block1[i]);
        CHECK(expected_block2[i] == dut_a53ecsd.m_block2[i]);
    }
}

TEST_CASE("Testing the A53ECSD class with (4.5) Test Set 3") {
    spdlog::set_level(spdlog::level::info);
    uint8_t t_kc[8] = {0xEF, 0xA8, 0xB2, 0x22, 0x9E, 0x72, 0x0C, 0x2A};
    uint8_t t_klen = 64;
    uint32_t t_count = 0x0033FD3F;

    kneedeepbts::crypto::A53ECSD dut_a53ecsd(t_kc, t_klen, t_count);
    dut_a53ecsd.run();

    uint8_t expected_block1[44] = {
            0x09, 0xB4, 0x9C, 0xE6, 0x20, 0xE4, 0xA3, 0x6B, 0x79, 0x56, 0x18, 0x6C,
            0x8F, 0x24, 0x8B, 0x61, 0x50, 0xDC, 0x23, 0x62, 0xB3, 0xF4, 0x1F, 0x6F,
            0x28, 0xF4, 0x86, 0xD9, 0xA8, 0x0B, 0xB8, 0x79, 0xDA, 0x4F, 0xE3, 0x49,
            0xE7, 0x2E, 0xF9, 0x75, 0x5A, 0x50, 0x15, 0x90
    };
    uint8_t expected_block2[44] = {
            0x02, 0xB1, 0x7E, 0xE1, 0xDF, 0x32, 0xD9, 0x30, 0x25, 0x67, 0xE4, 0x70,
            0xEA, 0x3A, 0x26, 0xB0, 0xFF, 0xCD, 0xE6, 0x0D, 0xFB, 0x8A, 0x28, 0xC1,
            0x06, 0x09, 0xAE, 0xC7, 0x4C, 0xA1, 0xEE, 0xDF, 0x3B, 0xAA, 0x33, 0x34,
            0xC2, 0x8E, 0x7E, 0x4D, 0xDA, 0x38, 0xA4, 0xA0
    };

    for (int i = 0; i < 44; i++) {
        CHECK(expected_block1[i] == dut_a53ecsd.m_block1[i]);
        CHECK(expected_block2[i] == dut_a53ecsd.m_block2[i]);
    }
}

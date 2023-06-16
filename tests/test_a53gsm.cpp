#include "doctest.h"

#include "spdlog/spdlog.h"

#include "../a53gsm.h"

/*
 * Test Data has been pulled from "3GPP TS 55.217 V6.1.0 (2002-12)".
 */

TEST_CASE("Testing the A53Gsm class with (3.3) Test Set 1") {
    spdlog::set_level(spdlog::level::info);
    uint8_t t_kc[8] = {0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xBC, 0x00};
    uint8_t t_klen = 64;
    uint32_t t_count = 0x0024F20F;

    kneedeepbts::A53Gsm dut_a53gsm(t_kc, t_klen, t_count);
    dut_a53gsm.run();

    uint8_t expected_block1[15] = {0x88, 0x9E, 0xEA, 0xAF, 0x9E, 0xD1, 0xBA, 0x1A, 0xBB, 0xD8, 0x43, 0x62, 0x32, 0xE4, 0x40};
    uint8_t expected_block2[15] = {0x5C, 0xA3, 0x40, 0x6A, 0xA2, 0x44, 0xCF, 0x69, 0xCF, 0x04, 0x7A, 0xAD, 0xA2, 0xDF, 0x40};

    for (int i = 0; i < 15; i++) {
        CHECK(expected_block1[i] == dut_a53gsm.m_block1[i]);
        CHECK(expected_block2[i] == dut_a53gsm.m_block2[i]);
    }
}


TEST_CASE("Testing the A53Gsm class with (3.4) Test Set 2") {
    spdlog::set_level(spdlog::level::info);
    uint8_t t_kc[8] = {0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48};
    uint8_t t_klen = 64;
    uint32_t t_count = 0x00061272;

    kneedeepbts::A53Gsm dut_a53gsm(t_kc, t_klen, t_count);
    dut_a53gsm.run();

    uint8_t expected_block1[15] = {0xFB, 0x4D, 0x5F, 0xBC, 0xEE, 0x13, 0xA3, 0x33, 0x89, 0x28, 0x56, 0x86, 0xE9, 0xA5, 0xC0};
    uint8_t expected_block2[15] = {0x25, 0x09, 0x03, 0x78, 0xE0, 0x54, 0x04, 0x57, 0xC5, 0x7E, 0x36, 0x76, 0x62, 0xE4, 0x40};

    for (int i = 0; i < 15; i++) {
        CHECK(expected_block1[i] == dut_a53gsm.m_block1[i]);
        CHECK(expected_block2[i] == dut_a53gsm.m_block2[i]);
    }
}

TEST_CASE("Testing the A53Gsm class with (3.5) Test Set 3") {
    spdlog::set_level(spdlog::level::info);
    uint8_t t_kc[8] = {0xEF, 0xA8, 0xB2, 0x22, 0x9E, 0x72, 0x0C, 0x2A};
    uint8_t t_klen = 64;
    uint32_t t_count = 0x0033FD3F;

    kneedeepbts::A53Gsm dut_a53gsm(t_kc, t_klen, t_count);
    dut_a53gsm.run();

    uint8_t expected_block1[15] = {0x0E, 0x40, 0x15, 0x75, 0x5A, 0x33, 0x64, 0x69, 0xC3, 0xDD, 0x86, 0x80, 0xE3, 0x03, 0x40};
    uint8_t expected_block2[15] = {0x6F, 0x10, 0x66, 0x9E, 0x2B, 0x4E, 0x18, 0xB0, 0x42, 0x43, 0x1A, 0x28, 0xE4, 0x7F, 0x80};

    for (int i = 0; i < 15; i++) {
        CHECK(expected_block1[i] == dut_a53gsm.m_block1[i]);
        CHECK(expected_block2[i] == dut_a53gsm.m_block2[i]);
    }
}

// NOTE: The following test case is specified in "3GPP TS 55.217 V6.1.0 (2002-12)",
//       however "3GPP TS 55.216 V6.2.0 (2003-09)" states that the A5/3 specification
//       only allows KLEN of 64.  Therefore, this test is invalid.
//TEST_CASE("Testing the A53Gsm class with (3.6) Test Set 4") {
//    spdlog::set_level(spdlog::level::debug);
//    uint8_t t_kc[8] = {0x5A, 0xCB, 0x1D, 0x64, 0x4C, 0x0D, 0x51, 0x20};
//    uint8_t t_klen = 80;
//    uint32_t t_count = 0x00156B26;
//
//    kneedeepbts::A53Gsm dut_a53gsm(t_kc, t_klen, t_count);
//    dut_a53gsm.run();
//
//    uint8_t expected_block1[15] = {0xE0, 0x95, 0x30, 0x6A, 0xD5, 0x08, 0x6E, 0x2E, 0xAC, 0x7F, 0x31, 0x07, 0xDE, 0x4F, 0x80};
//    uint8_t expected_block2[15] = {0x88, 0xB7, 0x07, 0x7F, 0x25, 0xF5, 0x6F, 0x15, 0x98, 0x77, 0x58, 0x25, 0xBD, 0x1D, 0x80};
//
//    for (int i = 0; i < 15; i++) {
//        CHECK(expected_block1[i] == dut_a53gsm.m_block1[i]);
//        CHECK(expected_block2[i] == dut_a53gsm.m_block2[i]);
//    }
//}

// NOTE: The following test case is specified in "3GPP TS 55.217 V6.1.0 (2002-12)",
//       however "3GPP TS 55.216 V6.2.0 (2003-09)" states that the A5/3 specification
//       only allows KLEN of 64.  Therefore, this test is invalid.
//TEST_CASE("Testing the A53Gsm class with (3.7) Test Set 5") {
//    spdlog::set_level(spdlog::level::debug);
//    uint8_t t_kc[8] = {0xD3, 0xC5, 0xD5, 0x92, 0x32, 0x7F, 0xB1, 0x1C};
//    uint8_t t_klen = 128;
//    uint32_t t_count = 0x000A59B4;
//
//    kneedeepbts::A53Gsm dut_a53gsm(t_kc, t_klen, t_count);
//    dut_a53gsm.run();
//
//    uint8_t expected_block1[15] = {0xDC, 0xE6, 0x43, 0x62, 0xAB, 0x5F, 0x89, 0xC1, 0x1E, 0xF0, 0xB3, 0x05, 0x16, 0x65, 0x40};
//    uint8_t expected_block2[15] = {0xC3, 0xD2, 0x22, 0x75, 0x54, 0x47, 0xA7, 0x8D, 0x5D, 0x74, 0x18, 0xAD, 0x73, 0xB5, 0x80};
//
//    for (int i = 0; i < 15; i++) {
//        CHECK(expected_block1[i] == dut_a53gsm.m_block1[i]);
//        CHECK(expected_block2[i] == dut_a53gsm.m_block2[i]);
//    }
//}

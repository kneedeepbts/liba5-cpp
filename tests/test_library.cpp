#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"

#include "spdlog/spdlog.h"

#include "../library.h"

/*
 * Test Data has been pulled from "3GPP TS 55.217 V6.1.0 (2002-12)".
 */

TEST_CASE("Testing the A53_GSM function with (3.3) Test Set 1") {
    spdlog::set_level(spdlog::level::info);
    uint8_t t_kc[8] = {0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xBC, 0x00};
    uint8_t t_klen = 64;
    uint32_t t_count = 0x0024F20F;

    uint8_t block1[15] = {0};
    uint8_t block2[15] = {0};

    A53_GSM(t_kc, t_klen, t_count, block1, block2);

    uint8_t expected_block1[15] = {0x88, 0x9E, 0xEA, 0xAF, 0x9E, 0xD1, 0xBA, 0x1A, 0xBB, 0xD8, 0x43, 0x62, 0x32, 0xE4, 0x40};
    uint8_t expected_block2[15] = {0x5C, 0xA3, 0x40, 0x6A, 0xA2, 0x44, 0xCF, 0x69, 0xCF, 0x04, 0x7A, 0xAD, 0xA2, 0xDF, 0x40};

    for (int i = 0; i < 15; i++) {
        CHECK(expected_block1[i] == block1[i]);
        CHECK(expected_block2[i] == block2[i]);
    }
}


TEST_CASE("Testing the A53_GSM function with (3.4) Test Set 2") {
    spdlog::set_level(spdlog::level::info);
    uint8_t t_kc[8] = {0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48};
    uint8_t t_klen = 64;
    uint32_t t_count = 0x00061272;

    uint8_t block1[15] = {0};
    uint8_t block2[15] = {0};

    A53_GSM(t_kc, t_klen, t_count, block1, block2);

    uint8_t expected_block1[15] = {0xFB, 0x4D, 0x5F, 0xBC, 0xEE, 0x13, 0xA3, 0x33, 0x89, 0x28, 0x56, 0x86, 0xE9, 0xA5, 0xC0};
    uint8_t expected_block2[15] = {0x25, 0x09, 0x03, 0x78, 0xE0, 0x54, 0x04, 0x57, 0xC5, 0x7E, 0x36, 0x76, 0x62, 0xE4, 0x40};

    for (int i = 0; i < 15; i++) {
        CHECK(expected_block1[i] == block1[i]);
        CHECK(expected_block2[i] == block2[i]);
    }
}

TEST_CASE("Testing the A53_GSM function with (3.5) Test Set 3") {
    spdlog::set_level(spdlog::level::info);
    uint8_t t_kc[8] = {0xEF, 0xA8, 0xB2, 0x22, 0x9E, 0x72, 0x0C, 0x2A};
    uint8_t t_klen = 64;
    uint32_t t_count = 0x0033FD3F;

    uint8_t block1[15] = {0};
    uint8_t block2[15] = {0};

    A53_GSM(t_kc, t_klen, t_count, block1, block2);

    uint8_t expected_block1[15] = {0x0E, 0x40, 0x15, 0x75, 0x5A, 0x33, 0x64, 0x69, 0xC3, 0xDD, 0x86, 0x80, 0xE3, 0x03, 0x40};
    uint8_t expected_block2[15] = {0x6F, 0x10, 0x66, 0x9E, 0x2B, 0x4E, 0x18, 0xB0, 0x42, 0x43, 0x1A, 0x28, 0xE4, 0x7F, 0x80};

    for (int i = 0; i < 15; i++) {
        CHECK(expected_block1[i] == block1[i]);
        CHECK(expected_block2[i] == block2[i]);
    }
}

#include "doctest.h"

#include "spdlog/spdlog.h"

#include "../kasumi.h"

/*
 * Test Data has been pulled from "3GPP TS 35.203 V17.0.0 (2022-03)".
 */

TEST_CASE("Testing the Kasumi class with (3.3) Test Set 1") {
    spdlog::set_level(spdlog::level::info);

    kneedeepbts::KasumiKey key{0x2BD6, 0x459F, 0x82C5, 0xB300, 0x952C, 0x4910, 0x4881, 0xFF48};
    uint64_t input = 0xEA024714AD5C4D84;
    uint64_t expected = 0xDF1F9B251C0BF45F;

    kneedeepbts::Kasumi dut_kasumi = kneedeepbts::Kasumi(key);
    uint64_t output = dut_kasumi.run(input);

    CHECK(expected == output);
}

TEST_CASE("Testing the Kasumi class with (3.4) Test Set 2") {
    spdlog::set_level(spdlog::level::info);
    kneedeepbts::KasumiKey key{0x8CE3, 0x3E2C, 0xC3C0, 0xB5FC, 0x1F3D, 0xE8A6, 0xDC66, 0xB1F3};
    uint64_t input = 0xD3C5D592327FB11C;
    uint64_t expected = 0xDE551988CEB2F9B7;

    kneedeepbts::Kasumi dut_kasumi = kneedeepbts::Kasumi(key);
    uint64_t output = dut_kasumi.run(input);

    CHECK(expected == output);
}

TEST_CASE("Testing the Kasumi class with (3.5) Test Set 3") {
    spdlog::set_level(spdlog::level::info);
    kneedeepbts::KasumiKey key{0x4035, 0xC668, 0x0AF8, 0xC6D1, 0xA8FF, 0x8667, 0xB171, 0x4013};
    uint64_t input = 0x62A540981BA6F9B7;
    uint64_t expected = 0x4592B0E78690F71B;

    kneedeepbts::Kasumi dut_kasumi = kneedeepbts::Kasumi(key);
    uint64_t output = dut_kasumi.run(input);

    CHECK(expected == output);
}

TEST_CASE("Testing the Kasumi class with (3.6) Test Set 4 (50 iterations)") {
    spdlog::set_level(spdlog::level::info);
    kneedeepbts::KasumiKey key{0x3A3B, 0x39B5, 0xC3F2, 0x376D, 0x69F7, 0xD546, 0xE5F8, 0x5D43};
    uint64_t input = 0xCA49C1C75771AB0B;
    uint64_t expected = 0x738BAD4C4A690802;

    kneedeepbts::Kasumi dut_kasumi = kneedeepbts::Kasumi(key);
    uint64_t output = input;
    for (int i = 0; i < 50; i++) {
        output = dut_kasumi.run(output);
    }

    CHECK(expected == output);
}

#include "kasumi.h"

#include <bit>
#include <cassert>

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#include "spdlog/spdlog.h"

namespace kneedeepbts::crypto {
    uint16_t S7[128] = {
        54, 50, 62, 56, 22, 34, 94, 96, 38,  6, 63, 93,  2, 18,123, 33,
        55,113, 39,114, 21, 67, 65, 12, 47, 73, 46, 27, 25,111,124, 81,
        53,  9,121, 79, 52, 60, 58, 48,101,127, 40,120,104, 70, 71, 43,
        20,122, 72, 61, 23,109, 13,100, 77,  1, 16,  7, 82, 10,105, 98,
        117,116, 76, 11, 89,106,  0,125,118, 99, 86, 69, 30, 57,126, 87,
        112, 51, 17,  5, 95, 14, 90, 84, 91,  8, 35,103, 32, 97, 28, 66,
        102, 31, 26, 45, 75,  4, 85, 92, 37, 74, 80, 49, 68, 29,115, 44,
        64,107,108, 24,110, 83, 36, 78, 42, 19, 15, 41, 88,119, 59,  3
    };

    uint16_t S9[512] = {
        167,239,161,379,391,334,  9,338, 38,226, 48,358,452,385, 90,397,
        183,253,147,331,415,340, 51,362,306,500,262, 82,216,159,356,177,
        175,241,489, 37,206, 17,  0,333, 44,254,378, 58,143,220, 81,400,
        95,  3,315,245, 54,235,218,405,472,264,172,494,371,290,399, 76,
        165,197,395,121,257,480,423,212,240, 28,462,176,406,507,288,223,
        501,407,249,265, 89,186,221,428,164, 74,440,196,458,421,350,163,
        232,158,134,354, 13,250,491,142,191, 69,193,425,152,227,366,135,
        344,300,276,242,437,320,113,278, 11,243, 87,317, 36, 93,496, 27,

        487,446,482, 41, 68,156,457,131,326,403,339, 20, 39,115,442,124,
        475,384,508, 53,112,170,479,151,126,169, 73,268,279,321,168,364,
        363,292, 46,499,393,327,324, 24,456,267,157,460,488,426,309,229,
        439,506,208,271,349,401,434,236, 16,209,359, 52, 56,120,199,277,
        465,416,252,287,246,  6, 83,305,420,345,153,502, 65, 61,244,282,
        173,222,418, 67,386,368,261,101,476,291,195,430, 49, 79,166,330,
        280,383,373,128,382,408,155,495,367,388,274,107,459,417, 62,454,
        132,225,203,316,234, 14,301, 91,503,286,424,211,347,307,140,374,

        35,103,125,427, 19,214,453,146,498,314,444,230,256,329,198,285,
        50,116, 78,410, 10,205,510,171,231, 45,139,467, 29, 86,505, 32,
        72, 26,342,150,313,490,431,238,411,325,149,473, 40,119,174,355,
        185,233,389, 71,448,273,372, 55,110,178,322, 12,469,392,369,190,
        1,109,375,137,181, 88, 75,308,260,484, 98,272,370,275,412,111,
        336,318,  4,504,492,259,304, 77,337,435, 21,357,303,332,483, 18,
        47, 85, 25,497,474,289,100,269,296,478,270,106, 31,104,433, 84,
        414,486,394, 96, 99,154,511,148,413,361,409,255,162,215,302,201,

        266,351,343,144,441,365,108,298,251, 34,182,509,138,210,335,133,
        311,352,328,141,396,346,123,319,450,281,429,228,443,481, 92,404,
        485,422,248,297, 23,213,130,466, 22,217,283, 70,294,360,419,127,
        312,377,  7,468,194,  2,117,295,463,258,224,447,247,187, 80,398,
        284,353,105,390,299,471,470,184, 57,200,348, 63,204,188, 33,451,
        97, 30,310,219, 94,160,129,493, 64,179,263,102,189,207,114,402,
        438,477,387,122,192, 42,381,  5,145,118,180,449,293,323,136,380,
        43, 66, 60,455,341,445,202,432,  8,237, 15,376,436,464, 59,461
    };

    KasumiKey operator ^ (const KasumiKey& lhs, const KasumiKey& rhs) {
        KasumiKey result{};
        result.subkeys[0] = lhs.subkeys[0] ^ rhs.subkeys[0];
        result.subkeys[1] = lhs.subkeys[1] ^ rhs.subkeys[1];
        result.subkeys[2] = lhs.subkeys[2] ^ rhs.subkeys[2];
        result.subkeys[3] = lhs.subkeys[3] ^ rhs.subkeys[3];
        result.subkeys[4] = lhs.subkeys[4] ^ rhs.subkeys[4];
        result.subkeys[5] = lhs.subkeys[5] ^ rhs.subkeys[5];
        result.subkeys[6] = lhs.subkeys[6] ^ rhs.subkeys[6];
        result.subkeys[7] = lhs.subkeys[7] ^ rhs.subkeys[7];
        return result;
    }

    Kasumi::Kasumi(KasumiKey key) : m_key(key) {
        // Set up the round keys
        setup_round_keys();
    }

    uint64_t Kasumi::run(uint64_t input) {
        // Set up the round keys
        //setup_round_keys();

        // Run the eight rounds
        SPDLOG_DEBUG("input: 0x{:X}", input);
        uint32_t left_zero = (input >> 32);
        uint32_t right_zero = (input);
        SPDLOG_DEBUG("left_zero: 0x{:X}, right_zero: 0x{:X}", left_zero, right_zero);
        // Round 1: Odd Round
        m_subkey_index = 0;
        uint32_t left_one = func_fo(func_fl(left_zero)) ^ right_zero;
        uint32_t right_one = left_zero;
        SPDLOG_DEBUG("left_one: 0x{:X}, right_one: 0x{:X}", left_one, right_one);
        // Round 2: Even Round
        m_subkey_index = 1;
        uint32_t left_two = func_fl(func_fo(left_one)) ^ right_one;
        uint32_t right_two = left_one;
        SPDLOG_DEBUG("left_two: 0x{:X}, right_two: 0x{:X}", left_two, right_two);
        // Round 3: Odd Round
        m_subkey_index = 2;
        uint32_t left_three = func_fo(func_fl(left_two)) ^ right_two;
        uint32_t right_three = left_two;
        SPDLOG_DEBUG("left_three: 0x{:X}, right_three: 0x{:X}", left_three, right_three);
        // Round 4: Even Round
        m_subkey_index = 3;
        uint32_t left_four = func_fl(func_fo(left_three)) ^ right_three;
        uint32_t right_four = left_three;
        SPDLOG_DEBUG("left_four: 0x{:X}, right_four: 0x{:X}", left_four, right_four);
        // Round 5: Odd Round
        m_subkey_index = 4;
        uint32_t left_five = func_fo(func_fl(left_four)) ^ right_four;
        uint32_t right_five = left_four;
        SPDLOG_DEBUG("left_five: 0x{:X}, right_five: 0x{:X}", left_five, right_five);
        // Round 6: Even Round
        m_subkey_index = 5;
        uint32_t left_six = func_fl(func_fo(left_five)) ^ right_five;
        uint32_t right_six = left_five;
        SPDLOG_DEBUG("left_six: 0x{:X}, right_six: 0x{:X}", left_six, right_six);
        // Round 7: Odd Round
        m_subkey_index = 6;
        uint32_t left_seven = func_fo(func_fl(left_six)) ^ right_six;
        uint32_t right_seven = left_six;
        SPDLOG_DEBUG("left_seven: 0x{:X}, right_seven: 0x{:X}", left_seven, right_seven);
        // Round 8: Even Round
        m_subkey_index = 7;
        uint32_t left_eight = func_fl(func_fo(left_seven)) ^ right_seven;
        uint32_t right_eight = left_seven;
        SPDLOG_DEBUG("left_eight: 0x{:X}, right_eight: 0x{:X}", left_eight, right_eight);

        // Put the result together and return
        return (((uint64_t)left_eight << 32) | (uint64_t)right_eight);
    }

    void Kasumi::setup_round_keys() {
        KasumiKey magic_nums{0x0123, 0x4567, 0x89AB, 0xCDEF, 0xFEDC, 0xBA98, 0x7654, 0x3210};
        KasumiKey key_prime = m_key ^ magic_nums;
        for (int i = 0; i < 8; i++) {
            // Set each round key, one subkey at a time.
            m_kl1.subkeys[i] = std::rotl(m_key.subkeys[(i + 0) % 8], 1);
            m_kl2.subkeys[i] = key_prime.subkeys[(i + 2) % 8];
            m_ko1.subkeys[i] = std::rotl(m_key.subkeys[(i + 1) % 8], 5);
            m_ko2.subkeys[i] = std::rotl(m_key.subkeys[(i + 5) % 8], 8);
            m_ko3.subkeys[i] = std::rotl(m_key.subkeys[(i + 6) % 8], 13);
            m_ki1.subkeys[i] = key_prime.subkeys[(i + 4) % 8];
            m_ki2.subkeys[i] = key_prime.subkeys[(i + 3) % 8];
            m_ki3.subkeys[i] = key_prime.subkeys[(i + 7) % 8];
        }
        SPDLOG_TRACE("_KLi1_r[0] = 0x{:04X}; _KLi1_r[1] = 0x{:04X}; _KLi1_r[2] = 0x{:04X}; _KLi1_r[3] = 0x{:04X}; _KLi1_r[4] = 0x{:04X}; _KLi1_r[5] = 0x{:04X}; _KLi1_r[6] = 0x{:04X}; _KLi1_r[7] = 0x{:04X}", m_kl1.subkeys[0], m_kl1.subkeys[1], m_kl1.subkeys[2], m_kl1.subkeys[3], m_kl1.subkeys[4], m_kl1.subkeys[5], m_kl1.subkeys[6], m_kl1.subkeys[7]);
        SPDLOG_TRACE("_KLi2_r[0] = 0x{:04X}; _KLi2_r[1] = 0x{:04X}; _KLi2_r[2] = 0x{:04X}; _KLi2_r[3] = 0x{:04X}; _KLi2_r[4] = 0x{:04X}; _KLi2_r[5] = 0x{:04X}; _KLi2_r[6] = 0x{:04X}; _KLi2_r[7] = 0x{:04X}", m_kl2.subkeys[0], m_kl2.subkeys[1], m_kl2.subkeys[2], m_kl2.subkeys[3], m_kl2.subkeys[4], m_kl2.subkeys[5], m_kl2.subkeys[6], m_kl2.subkeys[7]);
        SPDLOG_TRACE("_KOi1_r[0] = 0x{:04X}; _KOi1_r[1] = 0x{:04X}; _KOi1_r[2] = 0x{:04X}; _KOi1_r[3] = 0x{:04X}; _KOi1_r[4] = 0x{:04X}; _KOi1_r[5] = 0x{:04X}; _KOi1_r[6] = 0x{:04X}; _KOi1_r[7] = 0x{:04X}", m_ko1.subkeys[0], m_ko1.subkeys[1], m_ko1.subkeys[2], m_ko1.subkeys[3], m_ko1.subkeys[4], m_ko1.subkeys[5], m_ko1.subkeys[6], m_ko1.subkeys[7]);
        SPDLOG_TRACE("_KOi2_r[0] = 0x{:04X}; _KOi2_r[1] = 0x{:04X}; _KOi2_r[2] = 0x{:04X}; _KOi2_r[3] = 0x{:04X}; _KOi2_r[4] = 0x{:04X}; _KOi2_r[5] = 0x{:04X}; _KOi2_r[6] = 0x{:04X}; _KOi2_r[7] = 0x{:04X}", m_ko2.subkeys[0], m_ko2.subkeys[1], m_ko2.subkeys[2], m_ko2.subkeys[3], m_ko2.subkeys[4], m_ko2.subkeys[5], m_ko2.subkeys[6], m_ko2.subkeys[7]);
        SPDLOG_TRACE("_KOi3_r[0] = 0x{:04X}; _KOi3_r[1] = 0x{:04X}; _KOi3_r[2] = 0x{:04X}; _KOi3_r[3] = 0x{:04X}; _KOi3_r[4] = 0x{:04X}; _KOi3_r[5] = 0x{:04X}; _KOi3_r[6] = 0x{:04X}; _KOi3_r[7] = 0x{:04X}", m_ko3.subkeys[0], m_ko3.subkeys[1], m_ko3.subkeys[2], m_ko3.subkeys[3], m_ko3.subkeys[4], m_ko3.subkeys[5], m_ko3.subkeys[6], m_ko3.subkeys[7]);
        SPDLOG_TRACE("_KIi1_r[0] = 0x{:04X}; _KIi1_r[1] = 0x{:04X}; _KIi1_r[2] = 0x{:04X}; _KIi1_r[3] = 0x{:04X}; _KIi1_r[4] = 0x{:04X}; _KIi1_r[5] = 0x{:04X}; _KIi1_r[6] = 0x{:04X}; _KIi1_r[7] = 0x{:04X}", m_ki1.subkeys[0], m_ki1.subkeys[1], m_ki1.subkeys[2], m_ki1.subkeys[3], m_ki1.subkeys[4], m_ki1.subkeys[5], m_ki1.subkeys[6], m_ki1.subkeys[7]);
        SPDLOG_TRACE("_KIi2_r[0] = 0x{:04X}; _KIi2_r[1] = 0x{:04X}; _KIi2_r[2] = 0x{:04X}; _KIi2_r[3] = 0x{:04X}; _KIi2_r[4] = 0x{:04X}; _KIi2_r[5] = 0x{:04X}; _KIi2_r[6] = 0x{:04X}; _KIi2_r[7] = 0x{:04X}", m_ki2.subkeys[0], m_ki2.subkeys[1], m_ki2.subkeys[2], m_ki2.subkeys[3], m_ki2.subkeys[4], m_ki2.subkeys[5], m_ki2.subkeys[6], m_ki2.subkeys[7]);
        SPDLOG_TRACE("_KIi3_r[0] = 0x{:04X}; _KIi3_r[1] = 0x{:04X}; _KIi3_r[2] = 0x{:04X}; _KIi3_r[3] = 0x{:04X}; _KIi3_r[4] = 0x{:04X}; _KIi3_r[5] = 0x{:04X}; _KIi3_r[6] = 0x{:04X}; _KIi3_r[7] = 0x{:04X}", m_ki3.subkeys[0], m_ki3.subkeys[1], m_ki3.subkeys[2], m_ki3.subkeys[3], m_ki3.subkeys[4], m_ki3.subkeys[5], m_ki3.subkeys[6], m_ki3.subkeys[7]);
    }

    uint32_t Kasumi::func_fl(uint32_t input) {
        assert(m_subkey_index < 8);
        SPDLOG_TRACE("FL: input: 0x{:X}, subkey: {:d}", input, m_subkey_index);
        uint16_t left_zero = (input >> 16);
        uint16_t right_zero = (input);
        SPDLOG_TRACE("FL: left_zero: 0x{:X}, right_zero: 0x{:X}", left_zero, right_zero);
        // NOTE: The round number is being passed in as the keys change each round.
        //       Could the key generation be pushed inline and the values supplied here instead?
        uint16_t right_one = std::rotl((uint16_t)(left_zero & m_kl1.subkeys[m_subkey_index]), 1) ^ right_zero;
        uint16_t left_one = std::rotl((uint16_t)(right_one | m_kl2.subkeys[m_subkey_index]), 1) ^ left_zero;
        SPDLOG_TRACE("FL: left_one: 0x{:X}, right_one: 0x{:X}", left_one, right_one);
        return (((uint32_t)left_one << 16) | (uint32_t)right_one);
    }

    // Rewriting this function per "3GPP TS 35.202 V17.0.0 (2022-03)"
    uint16_t Kasumi::func_fi(uint16_t input, uint16_t ki_key) { // NOLINT(readability-convert-member-functions-to-static)
        SPDLOG_TRACE("FI: input: 0x{:X}, ki_key: 0x{:X}", input, ki_key);
        // NOTE: "left_?" is the 9 bit component, "right_?" is the 7 bit component
        uint16_t left_zero = ((input >> 7) & 0x01FF);
        uint16_t right_zero = (input & 0x007F);
        SPDLOG_TRACE("FI: left_zero: 0x{:X}, right_zero: 0x{:X}", left_zero, right_zero);
        uint16_t ki_7 = ((ki_key >> 9) & 0x007F);
        uint16_t ki_9 = (ki_key & 0x01FF);
        SPDLOG_TRACE("FI: ki_7: 0x{:X}, ki_9: 0x{:X}", ki_7, ki_9);
        uint16_t left_one = right_zero;
        uint16_t right_one = S9[left_zero] ^ right_zero;
        SPDLOG_TRACE("FI: left_one: 0x{:X}, right_one: 0x{:X}", left_one, right_one);
        uint16_t left_two = (right_one ^ ki_9) & 0x01FF; // Mask to make sure 9 bits;
        uint16_t right_two = S7[left_one & 0x007F] ^ (right_one & 0x007F) ^ ki_7;
        SPDLOG_TRACE("FI: left_two: 0x{:X}, right_two: 0x{:X}", left_two, right_two);
        uint16_t left_three = right_two;
        uint16_t right_three = S9[left_two] ^ right_two;
        SPDLOG_TRACE("FI: left_three: 0x{:X}, right_three: 0x{:X}", left_three, right_three);
        uint16_t left_four = S7[left_three & 0x007F] ^ (right_three & 0x007F);
        uint16_t right_four = right_three;
        SPDLOG_TRACE("FI: output: 0x{:X}", (((uint16_t)left_four << 9) | (uint16_t)right_four));
        return (((uint16_t)left_four << 9) | (uint16_t)right_four);
    }

    uint32_t Kasumi::func_fo(uint32_t input) {
        assert(m_subkey_index < 8);
        SPDLOG_TRACE("FO: input: 0x{:X}", input);
        uint16_t left_zero = (input >> 16);
        uint16_t right_zero = (input);
        SPDLOG_TRACE("FO: left_zero: 0x{:X}, right_zero: 0x{:X}", left_zero, right_zero);
        // NOTE: The round number is being passed in as the keys change each round.
        //       Could the key generation be pushed inline and the values supplied here instead?
        uint16_t right_one = func_fi(left_zero ^ m_ko1.subkeys[m_subkey_index], m_ki1.subkeys[m_subkey_index]) ^ right_zero;
        uint16_t left_one = right_zero;
        SPDLOG_TRACE("FO: left_one: 0x{:X}, right_one: 0x{:X}", left_one, right_one);
        uint16_t right_two = func_fi(left_one ^ m_ko2.subkeys[m_subkey_index], m_ki2.subkeys[m_subkey_index]) ^ right_one;
        uint16_t left_two = right_one;
        SPDLOG_TRACE("FO: left_two: 0x{:X}, right_two: 0x{:X}", left_two, right_two);
        uint16_t right_three = func_fi(left_two ^ m_ko3.subkeys[m_subkey_index], m_ki3.subkeys[m_subkey_index]) ^ right_two;
        uint16_t left_three = right_two;
        SPDLOG_TRACE("FO: left_three: 0x{:X}, right_three: 0x{:X}", left_three, right_three);
        return (((uint32_t)left_three << 16) | (uint32_t)right_three);
    }
}
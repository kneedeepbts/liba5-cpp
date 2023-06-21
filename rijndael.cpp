/*
 * Using spec at https://www.etsi.org/deliver/etsi_ts/135200_135299/135206/14.00.00_60/ts_135206v140000p.pdf
 */

#include "rijndael.h"

namespace kneedeepbts::crypto {
/*--------------------- Rijndael S box table ----------------------*/
    static uint8_t S[256] = {
            99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
            202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
            183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
            4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
            9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
            83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
            208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
            81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
            205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
            96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
            224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
            231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
            186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
            112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
            225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
            140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22,
    };
/*------- This array does the multiplication by x in GF(2^8) ------*/
    static uint8_t Xtime[256] = {
            0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30,
            32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62,
            64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94,
            96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126,
            128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158,
            160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190,
            192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222,
            224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254,
            27, 25, 31, 29, 19, 17, 23, 21, 11, 9, 15, 13, 3, 1, 7, 5,
            59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37,
            91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69,
            123, 121, 127, 125, 115, 113, 119, 117, 107, 105, 111, 109, 99, 97, 103, 101,
            155, 153, 159, 157, 147, 145, 151, 149, 139, 137, 143, 141, 131, 129, 135, 133,
            187, 185, 191, 189, 179, 177, 183, 181, 171, 169, 175, 173, 163, 161, 167, 165,
            219, 217, 223, 221, 211, 209, 215, 213, 203, 201, 207, 205, 195, 193, 199, 197,
            251, 249, 255, 253, 243, 241, 247, 245, 235, 233, 239, 237, 227, 225, 231, 229
    };

    Rijndael::Rijndael(RijndaelKey key) : m_key(key) {}

    // FIXME: The round keys can be calculated on the fly.  Move these calcs to the encrypt method.
    void Rijndael::setup_round_keys() {
        //std::array<uint8_t, 16> value
        uint8_t roundConst;

        /* first round key equals key */
        for (uint8_t i = 0; i < 16; i++) {
            //roundKeys[0][i & 0x03][i>>2] = key[i];
            // roundKeys is [11][4][4], which works to [(x*16) + (y*4) + z]
            roundKeys[(0 * 16) + ((i & 0x03) * 4) + (i >> 2)] = m_key.value[i];
        }
        roundConst = 1;

        /* now calculate round keys */
        for (uint8_t i = 1; i < 11; i++) {
            roundKeys[(i * 16) + (0 * 4) + (0)] = S[roundKeys[((i - 1) * 16) + (1 * 4) + (3)]] ^ roundKeys[((i - 1) * 16) + (0 * 4) + (0)] ^ roundConst;
            roundKeys[(i * 16) + (1 * 4) + (0)] = S[roundKeys[((i - 1) * 16) + (2 * 4) + (3)]] ^ roundKeys[((i - 1) * 16) + (1 * 4) + (0)];
            roundKeys[(i * 16) + (2 * 4) + (0)] = S[roundKeys[((i - 1) * 16) + (3 * 4) + (3)]] ^ roundKeys[((i - 1) * 16) + (2 * 4) + (0)];
            roundKeys[(i * 16) + (3 * 4) + (0)] = S[roundKeys[((i - 1) * 16) + (0 * 4) + (3)]] ^ roundKeys[((i - 1) * 16) + (3 * 4) + (0)];
            for (uint8_t j = 0; j < 4; j++) {
                roundKeys[(i * 16) + (j * 4) + (1)] = roundKeys[((i - 1) * 16) + (j * 4) + (1)] ^ roundKeys[(i * 16) + (j * 4) + (0)];
                roundKeys[(i * 16) + (j * 4) + (2)] = roundKeys[((i - 1) * 16) + (j * 4) + (2)] ^ roundKeys[(i * 16) + (j * 4) + (1)];
                roundKeys[(i * 16) + (j * 4) + (3)] = roundKeys[((i - 1) * 16) + (j * 4) + (3)] ^ roundKeys[(i * 16) + (j * 4) + (2)];
            }
            /* update round constant */
            roundConst = Xtime[roundConst];
        }
    }

    std::array<uint8_t, 16> kneedeepbts::crypto::Rijndael::encrypt(std::array<uint8_t, 16> value) {
        std::array<uint8_t, 16> output{};

        /* initialize state array from input byte string */
        for (uint8_t i = 0; i < 16; i++) {
            state[((i & 0x3) * 4) + (i >> 2)] = value[i];
        }

        /* add first round_key */
        KeyAdd(0);

        /* do lots of full rounds */
        for (uint8_t r = 1; r <= 9; r++) {
            ByteSub();
            ShiftRow();
            MixColumn();
            KeyAdd(r);
        }

        /* final round */
        ByteSub();
        ShiftRow();
        KeyAdd(10);

        /* produce output byte string from state array */
        for (uint8_t i = 0; i < 16; i++) {
            output[i] = state[((i & 0x3) * 4) + (i >> 2)];
        }
        return output;
    }

    void kneedeepbts::crypto::Rijndael::KeyAdd(uint8_t round) {
        for (uint8_t i = 0; i < 4; i++) {
            for (uint8_t j = 0; j < 4; j++) {
                state[(i * 4) + j] ^= roundKeys[(round * 16) + (i * 4) + (j)];
            }
        }
    }

    void kneedeepbts::crypto::Rijndael::ByteSub() {
        for (uint8_t i = 0; i < 4; i++) {
            for (uint8_t j = 0; j < 4; j++) {
                state[(i * 4) + j] = S[state[(i * 4) + j]];
            }
        }
    }

    void kneedeepbts::crypto::Rijndael::ShiftRow() {
        uint8_t temp;
        /* left rotate row 1 by 1 */
        temp = state[4]; // temp = state[1][0]; // 1*4 + 0
        state[4] = state[5]; // state[1][0] = state[1][1];
        state[5] = state[6]; // state[1][1] = state[1][2];
        state[6] = state[7]; // state[1][2] = state[1][3];
        state[7] = temp; // state[1][3] = temp;

        /* left rotate row 2 by 2 */
        temp = state[8]; // temp = state[2][0];
        state[8] = state[10]; // state[2][0] = state[2][2];
        state[10] = temp; // state[2][2] = temp;

        temp = state[9]; // temp = state[2][1];
        state[9] = state[11]; // state[2][1] = state[2][3];
        state[11] = temp; // state[2][3] = temp;

        /* left rotate row 3 by 3 */
        temp = state[12]; // temp = state[3][0];
        state[12] = state[15]; // state[3][0] = state[3][3];
        state[15] = state[14]; // state[3][3] = state[3][2];
        state[14] = state[13]; // state[3][2] = state[3][1];
        state[13] = temp; // state[3][1] = temp;
    }

    void kneedeepbts::crypto::Rijndael::MixColumn() {
        uint8_t temp, tmp, tmp0;

        /* do one column at a time */
        for (uint8_t i = 0; i < 4; i++) {
            temp = state[0 + i] ^ state[4 + i] ^ state[8 + i] ^ state[12 + i]; // temp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
            tmp0 = state[0 + i];
            /* Xtime array does multiply by x in GF2^8 */
            tmp = Xtime[state[0 + i] ^ state[4 + i]];
            state[0 + i] ^= temp ^ tmp;
            tmp = Xtime[state[4 + i] ^ state[8 + i]];
            state[4 + i] ^= temp ^ tmp;
            tmp = Xtime[state[8 + i] ^ state[12 + i]];
            state[8 + i] ^= temp ^ tmp;
            tmp = Xtime[state[12 + i] ^ tmp0];
            state[12 + i] ^= temp ^ tmp;
        }
    }
}

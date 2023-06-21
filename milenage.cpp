/*
 * Using spec at https://www.etsi.org/deliver/etsi_ts/135200_135299/135206/14.00.00_60/ts_135206v140000p.pdf
 */

#include "milenage.h"

namespace kneedeepbts::crypto {
    MilenageKey operator ^ (const MilenageKey& lhs, const MilenageKey& rhs) {
        MilenageKey result{};
        for (int i = 0; i < 16; i++) {
            result.value[i] = lhs.value[i] ^ rhs.value[i];
        }
        return result;
    }

    Milenage::Milenage(MilenageKey key, MilenageKey rand) : m_key(key), m_rand(rand) {}

    void Milenage::setOp(std::array<uint8_t, 16> op) {
        std::array<uint8_t, 16> tmpOut{};
        Rijndael encryptor{RijndaelKey{m_key.value}};

        tmpOut = encryptor.encrypt(op);

        setOpc(tmpOut);
    }

    void Milenage::setOpc(std::array<uint8_t, 16> op_c) {
        m_opc = MilenageKey{op_c};
    }

    void Milenage::runF1(std::array<uint8_t, 6> sqn, std::array<uint8_t, 2> amf) {
        std::array<uint8_t, 16> rijndaelInput{};
        std::array<uint8_t, 16> in1{};
        std::array<uint8_t, 16> temp{};
        std::array<uint8_t, 16> out{};

        rijndaelInput = (m_rand ^ m_opc).value;

        Rijndael encryptor{RijndaelKey{m_key.value}};
        temp = encryptor.encrypt(rijndaelInput);

        for (uint8_t i = 0; i < 6; i++) {
            in1[i] = sqn[i];
            in1[i + 8] = sqn[i];
        }

        for (uint8_t i = 0; i < 2; i++) {
            in1[i + 6] = amf[i];
            in1[i + 14] = amf[i];
        }

        /* XOR op_c and in1, rotate by r1=64, and XOR *
        * on the constant c1 (which is all zeroes) */
        for (uint8_t i = 0; i < 16; i++) {
            rijndaelInput[(i + 8) % 16] = in1[i] ^ m_opc.value[i];
        }

        /* XOR on the value temp computed before */
        for (uint8_t i = 0; i < 16; i++) {
            rijndaelInput[i] ^= temp[i];
        }

        out = encryptor.encrypt(rijndaelInput);

        for (uint8_t i = 0; i < 16; i++) {
            out[i] ^= m_opc.value[i];
        }

        for (uint8_t i = 0; i < 8; i++) {
            mac_a[i] = out[i];
            mac_s[i] = out[i + 8];
        }
    }

    void Milenage::runF2345() {
        std::array<uint8_t, 16> rijndaelInput{};
        std::array<uint8_t, 16> temp{};
        std::array<uint8_t, 16> out{};

        rijndaelInput = (m_rand ^ m_opc).value;

        Rijndael encryptor{RijndaelKey{m_key.value}};
        temp = encryptor.encrypt(rijndaelInput);

        /* To obtain output block OUT2: XOR OPc and TEMP,    *
         * rotate by r2=0, and XOR on the constant c2 (which *
         * is all zeroes except that the last bit is 1).     */
        for (uint8_t i = 0; i < 16; i++) {
            rijndaelInput[i] = temp[i] ^ m_opc.value[i];
        }

        rijndaelInput[15] ^= 1;

        out = encryptor.encrypt(rijndaelInput);

        for (uint8_t i = 0; i < 16; i++) {
            out[i] ^= m_opc.value[i];
        }

        for (uint8_t i = 0; i < 8; i++) {
            res[i] = out[i + 8];
        }

        for (uint8_t i = 0; i < 6; i++) {
            ak[i] = out[i];
        }

        /* To obtain output block OUT3: XOR OPc and TEMP, *
        * rotate by r3=32, and XOR on the constant c3 (which *
        * is all zeroes except that the next to last bit is 1). */
        for (uint8_t i = 0; i < 16; i++) {
            rijndaelInput[(i + 12) % 16] = temp[i] ^ m_opc.value[i];
        }

        rijndaelInput[15] ^= 2;

        out = encryptor.encrypt(rijndaelInput);

        for (uint8_t i = 0; i < 16; i++) {
            out[i] ^= m_opc.value[i];
        }

        for (uint8_t i = 0; i < 16; i++) {
            ck[i] = out[i];
        }

        /* To obtain output block OUT4: XOR OPc and TEMP, *
        * rotate by r4=64, and XOR on the constant c4 (which *
        * is all zeroes except that the 2nd from last bit is 1). */
        for (uint8_t i = 0; i < 16; i++) {
            rijndaelInput[(i + 8) % 16] = temp[i] ^ m_opc.value[i];
        }

        rijndaelInput[15] ^= 4;

        out = encryptor.encrypt(rijndaelInput);

        for (uint8_t i = 0; i < 16; i++) {
            out[i] ^= m_opc.value[i];
        }

        for (uint8_t i = 0; i < 16; i++) {
            ik[i] = out[i];
        }

        /* To obtain output block OUT5: XOR OPc and TEMP, *
        * rotate by r5=96, and XOR on the constant c5 (which *
        * is all zeroes except that the 3rd from last bit is 1). */
        for (uint8_t i = 0; i < 16; i++) {
            rijndaelInput[(i + 4) % 16] = temp[i] ^ m_opc.value[i];
        }

        rijndaelInput[15] ^= 8;

        out = encryptor.encrypt(rijndaelInput);

        for (uint8_t i = 0; i < 16; i++) {
            out[i] ^= m_opc.value[i];
        }

        for (uint8_t i = 0; i < 6; i++) {
            akr[i] = out[i];
        }
    }

    std::array<uint8_t, 8> Milenage::getMACA() {
        return mac_a;
    }

    std::array<uint8_t, 8> Milenage::getMACS() {
        return mac_s;
    }

    std::array<uint8_t, 8> Milenage::getRES() {
        return res;
    }

    std::array<uint8_t, 16> Milenage::getCK() {
        return ck;
    }

    std::array<uint8_t, 16> Milenage::getIK() {
        return ik;
    }

    std::array<uint8_t, 6> Milenage::getAK() {
        return ak;
    }

    std::array<uint8_t, 6> Milenage::getAKR() {
        return akr;
    }

    std::array<uint8_t, 8> Milenage::getGsmKc() {
        std::array<uint8_t, 8> out{};
        for (uint8_t i = 0; i < 8; i++) {
            out[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];
        }
        return out;
    }

    std::array<uint8_t, 4> Milenage::getGsmSRES() {
        std::array<uint8_t, 4> out{};
        for (uint8_t i = 0; i < 4; i++) {
            out[i] = res[i] ^ res[i + 4];
        }
        return out;
    }
}

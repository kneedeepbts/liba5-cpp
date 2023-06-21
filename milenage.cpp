#include "milenage.h"

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include "spdlog/spdlog.h"

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
        Rijndael encryptor{RijndaelKey{m_key.value}};

        std::array<uint8_t, 16> tmpOut = encryptor.encrypt(op);
        std::array<uint8_t, 16> result{};
        for (int i = 0; i < 16; i++) {
            result[i] = op[i] ^ tmpOut[i];
        }

        setOpc(result);
    }

    void Milenage::setOpc(std::array<uint8_t, 16> op_c) {
        m_opc = MilenageKey{op_c};

        SPDLOG_TRACE(
                "opc: {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X}",
                m_opc.value[0], m_opc.value[1], m_opc.value[2], m_opc.value[3], m_opc.value[4], m_opc.value[5], m_opc.value[6], m_opc.value[7],
                m_opc.value[8], m_opc.value[9], m_opc.value[10], m_opc.value[11], m_opc.value[12], m_opc.value[13], m_opc.value[14], m_opc.value[15]
        );
    }

    void Milenage::runF1(std::array<uint8_t, 6> sqn, std::array<uint8_t, 2> amf) {
        std::array<uint8_t, 16> rijndaelInput = (m_rand ^ m_opc).value;

        Rijndael encryptor{RijndaelKey{m_key.value}};
        std::array<uint8_t, 16> temp = encryptor.encrypt(rijndaelInput);

        SPDLOG_TRACE(
                "after 1st encryption: {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X}",
                temp[0], temp[1], temp[2], temp[3], temp[4], temp[5], temp[6], temp[7],
                temp[8], temp[9], temp[10], temp[11], temp[12], temp[13], temp[14], temp[15]
        );

        std::array<uint8_t, 16> in1{};
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

        SPDLOG_TRACE(
                "after fancy footwork: {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X}",
                rijndaelInput[0], rijndaelInput[1], rijndaelInput[2], rijndaelInput[3], rijndaelInput[4], rijndaelInput[5], rijndaelInput[6], rijndaelInput[7],
                rijndaelInput[8], rijndaelInput[9], rijndaelInput[10], rijndaelInput[11], rijndaelInput[12], rijndaelInput[13], rijndaelInput[14], rijndaelInput[15]
        );

        /* XOR on the value temp computed before */
        for (uint8_t i = 0; i < 16; i++) {
            rijndaelInput[i] ^= temp[i];
        }

        SPDLOG_TRACE(
                "before 2nd encryption: {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X}",
                rijndaelInput[0], rijndaelInput[1], rijndaelInput[2], rijndaelInput[3], rijndaelInput[4], rijndaelInput[5], rijndaelInput[6], rijndaelInput[7],
                rijndaelInput[8], rijndaelInput[9], rijndaelInput[10], rijndaelInput[11], rijndaelInput[12], rijndaelInput[13], rijndaelInput[14], rijndaelInput[15]
        );

        std::array<uint8_t, 16> out = encryptor.encrypt(rijndaelInput);

        SPDLOG_TRACE(
                "after 2nd encryption: {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X}",
                out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7],
                out[8], out[9], out[10], out[11], out[12], out[13], out[14], out[15]
        );

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

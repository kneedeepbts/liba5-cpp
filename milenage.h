#ifndef _MILENAGE_H
#define _MILENAGE_H

/*
 * Using spec at https://www.etsi.org/deliver/etsi_ts/135200_135299/135206/14.00.00_60/ts_135206v140000p.pdf
 */

/*** Includes ***/
#include <cstdint>
#include <array>
#include "rijndael.h"

/*** Global Variables ***/

/*** Functions ***/

/*** Classes ***/
namespace kneedeepbts::crypto {
    typedef struct MilenageKey { std::array<uint8_t, 16> value; } MilenageKey;

    MilenageKey operator ^ (const MilenageKey& lhs, const MilenageKey& rhs);

    class Milenage {
        public:
            explicit Milenage(MilenageKey key, MilenageKey rand);

            void setOp(std::array<uint8_t, 16> op);
            void setOpc(std::array<uint8_t, 16> op_c);

            void runF1(std::array<uint8_t, 6> sqn, std::array<uint8_t, 2> amf);
            void runF2345();

            std::array<uint8_t, 8> getMACA();
            std::array<uint8_t, 8> getMACS();
            std::array<uint8_t, 8> getRES();
            std::array<uint8_t, 16> getCK();
            std::array<uint8_t, 16> getIK();
            std::array<uint8_t, 6> getAK();
            std::array<uint8_t, 6> getAKR();

            std::array<uint8_t, 8> getGsmKc();
            std::array<uint8_t, 4> getGsmSRES();

        private:
            MilenageKey m_key;
            MilenageKey m_opc;
            MilenageKey m_rand;

            std::array<uint8_t, 8> mac_a;
            std::array<uint8_t, 8> mac_s;
            std::array<uint8_t, 8> res;
            std::array<uint8_t, 16> ck;
            std::array<uint8_t, 16> ik;
            std::array<uint8_t, 6> ak;
            std::array<uint8_t, 6> akr;
    };
}

#endif // _MILENAGE_H


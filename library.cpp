#include "library.h"
#include "a53gsm.h"

void A53_GSM(uint8_t *key, uint32_t klen, uint32_t count, uint8_t *block1, uint8_t *block2 ) {
    kneedeepbts::A53Gsm ag = kneedeepbts::A53Gsm(key, klen, count);
    ag.run();
    // FIXME: There's probably a better way to hand ownership of the arrays back without the copy...
    for (int i = 0; i < 15; i++) {
        block1[i] = ag.m_block1[i];
        block2[i] = ag.m_block2[i];
    }
}

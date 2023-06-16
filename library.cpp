#include "library.h"
#include "a53gsm.h"

void A53_GSM(uint8_t *key, uint32_t klen, uint32_t count, uint8_t *block1, uint8_t *block2 ) {
    kneedeepbts::A53GSM a53 = kneedeepbts::A53GSM(key, klen, count);
    a53.run();
    // FIXME: There's probably a better way to hand ownership of the arrays back without the copy...
    for (int i = 0; i < 15; i++) {
        block1[i] = a53.m_block1[i];
        block2[i] = a53.m_block2[i];
    }
}

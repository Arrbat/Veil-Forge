#ifndef SALSA20_H
#define SALSA20_H

#include <stdint.h>

void salsa20_crypt
(
    uint8_t *data, 
    uint32_t length,
    const uint8_t key[32],
    const uint8_t nonce[8],
    uint32_t counter
);

#endif // SALSA20_H

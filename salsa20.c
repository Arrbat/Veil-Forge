#include "salsa20.h"

static inline uint32_t rotl(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static void salsa20_block(uint32_t output[16], const uint32_t input[16])
{
    int i;
    uint32_t x[16];
    for (i = 0; i < 16; i++)
        x[i] = input[i];
    for (i = 0; i < 10; i++)
    {   // 20 rounds: 2 per loop
        x[ 4] ^= rotl(x[ 0] + x[12], 7);
        x[ 8] ^= rotl(x[ 4] + x[ 0], 9);
        x[12] ^= rotl(x[ 8] + x[ 4],13);
        x[ 0] ^= rotl(x[12] + x[ 8],18);
        x[ 9] ^= rotl(x[ 5] + x[ 1], 7);
        x[13] ^= rotl(x[ 9] + x[ 5], 9);
        x[ 1] ^= rotl(x[13] + x[ 9],13);
        x[ 5] ^= rotl(x[ 1] + x[13],18);
        x[14] ^= rotl(x[10] + x[ 6], 7);
        x[ 2] ^= rotl(x[14] + x[10], 9);
        x[ 6] ^= rotl(x[ 2] + x[14],13);
        x[10] ^= rotl(x[ 6] + x[ 2],18);
        x[ 3] ^= rotl(x[15] + x[11], 7);
        x[ 7] ^= rotl(x[ 3] + x[15], 9);
        x[11] ^= rotl(x[ 7] + x[ 3],13);
        x[15] ^= rotl(x[11] + x[ 7],18);
        x[ 1] ^= rotl(x[ 0] + x[ 3], 7);
        x[ 2] ^= rotl(x[ 1] + x[ 0], 9);
        x[ 3] ^= rotl(x[ 2] + x[ 1],13);
        x[ 0] ^= rotl(x[ 3] + x[ 2],18);
        x[ 6] ^= rotl(x[ 5] + x[ 4], 7);
        x[ 7] ^= rotl(x[ 6] + x[ 5], 9);
        x[ 4] ^= rotl(x[ 7] + x[ 6],13);
        x[ 5] ^= rotl(x[ 4] + x[ 7],18);
        x[11] ^= rotl(x[10] + x[ 9], 7);
        x[ 8] ^= rotl(x[11] + x[10], 9);
        x[ 9] ^= rotl(x[ 8] + x[11],13);
        x[10] ^= rotl(x[ 9] + x[ 8],18);
        x[12] ^= rotl(x[15] + x[14], 7);
        x[13] ^= rotl(x[12] + x[15], 9);
        x[14] ^= rotl(x[13] + x[12],13);
        x[15] ^= rotl(x[14] + x[13],18);
    }
    for (i = 0; i < 16; i++)
        output[i] = x[i] + input[i];
}

static const uint8_t sigma[16] = "expand 32-byte k";

void salsa20_crypt(
    uint8_t *data, uint32_t length,
    const uint8_t key[32],
    const uint8_t nonce[8],
    uint32_t counter)
{
    uint32_t state[16];
    uint32_t keystream[16];
    uint8_t block[64];
    uint32_t i, j, bytes_to_process;

    // Setup state
    state[0]  = ((uint32_t)sigma[0]) | ((uint32_t)sigma[1] << 8) | ((uint32_t)sigma[2] << 16) | ((uint32_t)sigma[3] << 24);
    state[1]  = ((uint32_t)key[0])   | ((uint32_t)key[1] << 8)   | ((uint32_t)key[2] << 16)   | ((uint32_t)key[3] << 24);
    state[2]  = ((uint32_t)key[4])   | ((uint32_t)key[5] << 8)   | ((uint32_t)key[6] << 16)   | ((uint32_t)key[7] << 24);
    state[3]  = ((uint32_t)key[8])   | ((uint32_t)key[9] << 8)   | ((uint32_t)key[10] << 16)  | ((uint32_t)key[11] << 24);
    state[4]  = ((uint32_t)key[12])  | ((uint32_t)key[13] << 8)  | ((uint32_t)key[14] << 16)  | ((uint32_t)key[15] << 24);
    state[5]  = ((uint32_t)sigma[4]) | ((uint32_t)sigma[5] << 8) | ((uint32_t)sigma[6] << 16) | ((uint32_t)sigma[7] << 24);
    state[6]  = ((uint32_t)nonce[0]) | ((uint32_t)nonce[1] << 8) | ((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);
    state[7]  = ((uint32_t)nonce[4]) | ((uint32_t)nonce[5] << 8) | ((uint32_t)nonce[6] << 16) | ((uint32_t)nonce[7] << 24);
    state[8]  = counter;
    state[9]  = 0;
    state[10] = ((uint32_t)sigma[8])  | ((uint32_t)sigma[9] << 8)  | ((uint32_t)sigma[10] << 16) | ((uint32_t)sigma[11] << 24);
    state[11] = ((uint32_t)key[16])  | ((uint32_t)key[17] << 8)  | ((uint32_t)key[18] << 16)  | ((uint32_t)key[19] << 24);
    state[12] = ((uint32_t)key[20])  | ((uint32_t)key[21] << 8)  | ((uint32_t)key[22] << 16)  | ((uint32_t)key[23] << 24);
    state[13] = ((uint32_t)key[24])  | ((uint32_t)key[25] << 8)  | ((uint32_t)key[26] << 16)  | ((uint32_t)key[27] << 24);
    state[14] = ((uint32_t)key[28])  | ((uint32_t)key[29] << 8)  | ((uint32_t)key[30] << 16)  | ((uint32_t)key[31] << 24);
    state[15] = ((uint32_t)sigma[12]) | ((uint32_t)sigma[13] << 8) | ((uint32_t)sigma[14] << 16) | ((uint32_t)sigma[15] << 24);

    for (i = 0; i < length; i += 64, counter++)
    {
        state[8] = counter;
        salsa20_block(keystream, state);
        for (j = 0; j < 64 && i + j < length; j++)
        {
            ((uint8_t*)data)[i + j] ^= ((uint8_t*)keystream)[j];
        }
    }
}

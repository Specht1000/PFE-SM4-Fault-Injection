#ifndef PFE_SM4_H
#define PFE_SM4_H
#include <stdint.h>
/* Snapshots: input, 32 rolling states, final word reversal. */
typedef struct { uint8_t round, word, byte, mask; } sm4_fault;
void sm4_expand(const uint8_t key[16], uint32_t rk[32]);
void sm4_block(const uint8_t input[16], uint8_t output[16],
               const uint32_t rk[32], int decrypt,
               uint8_t snapshots[34][16], const sm4_fault *fault,
               uint8_t event[2]);
#endif

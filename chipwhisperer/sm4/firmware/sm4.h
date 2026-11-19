/* Portable SM4 core for the STM32F303 teaching target. */
#ifndef PFE_SM4_H
#define PFE_SM4_H

#include <stdint.h>

#define SM4_BLOCK_SIZE 16
#define SM4_ROUNDS 32

typedef struct {
    uint32_t rk[SM4_ROUNDS];
} sm4_context;

/* The callback marks entry/exit of a round; it never changes cipher data. */
typedef void (*sm4_round_hook)(uint8_t round, uint8_t entering);

void sm4_set_key(sm4_context *context, const uint8_t key[SM4_BLOCK_SIZE]);
void sm4_crypt_block(const sm4_context *context, const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE], uint8_t decrypt, sm4_round_hook hook);

#endif

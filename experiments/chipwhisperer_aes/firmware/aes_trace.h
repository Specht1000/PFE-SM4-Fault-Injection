/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Interface for the instrumented (traced) AES path used by commands 't', 's',
 * 'd', and 'f' in main.c. Implementation and details are in aes_trace.c.
 */
#ifndef PFE_AES_TRACE_H
#define PFE_AES_TRACE_H
#include <stdint.h>
/* One AES-128 encryption produces 41 recorded states:
 *   Input + round-0 AddRoundKey                       = 2
 *   rounds 1..9, four operations each                 = 36
 *   round 10: SubBytes, ShiftRows, AddRoundKey        = 3           */
#define AES_TRACE_STEPS 41
/* Each snapshot packet: [index, round, operation] + 16 state bytes = 19. */
#define AES_TRACE_PACKET_SIZE 19

void trace_set_key(uint8_t *key);            /* load/expand the key, clear trace */
void trace_clear(void);                      /* discard recorded states */
void trace_encrypt(uint8_t *block);          /* encrypt in place, record states */
/* Encrypt while injecting one fault; returns 0 on success or 5 for a bad model.
 * Parameters: round, operation, row, column, nonzero XOR mask. */
uint8_t trace_encrypt_fault(uint8_t *block, const uint8_t *parameters, uint8_t *event);
void target_decrypt(uint8_t *block);         /* decrypt in place */
uint8_t trace_read(uint8_t index, uint8_t *packet); /* copy out one snapshot */
#endif

/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef PFE_AES_TRACE_H
#define PFE_AES_TRACE_H
#include <stdint.h>
#define AES_TRACE_STEPS 41
#define AES_TRACE_PACKET_SIZE 19
void trace_set_key(uint8_t *key);
void trace_clear(void);
void trace_encrypt(uint8_t *block);
uint8_t trace_read(uint8_t index, uint8_t *packet);
#endif

/* SPDX-License-Identifier: GPL-3.0-or-later
 * Instrumented educational path, separate from the baseline AES backend.
 * Reuse the pinned TinyAES primitives without editing upstream files.
 * Including the implementation exposes its static round primitives here.
 */
#include "aes_trace.h"
#include <string.h>
#define AES_CONST_VAR static const
#define AES128_ECB_encrypt trace_backend_encrypt
#define AES128_ECB_decrypt trace_backend_decrypt
#define AES128_ECB_indp_setkey trace_backend_setkey
#define AES128_ECB_indp_crypto trace_backend_crypto
#include "aes.c"

static uint8_t snapshots[AES_TRACE_STEPS][AES_TRACE_PACKET_SIZE];
static uint8_t snapshot_count;

void trace_clear(void) { snapshot_count = 0; }

void trace_set_key(uint8_t *key)
{
    trace_clear();
    trace_backend_setkey(key);
}

static void save_state(uint8_t round, uint8_t operation)
{
    uint8_t *packet = snapshots[snapshot_count];
    packet[0] = snapshot_count;
    packet[1] = round;
    packet[2] = operation;
    memcpy(packet + 3, (uint8_t *)state, 16);
    snapshot_count++;
}

void trace_encrypt(uint8_t *block)
{
    trace_clear();
    state = (state_t *)block;
    save_state(0, 0); /* Input */
    AddRoundKey(0);
    save_state(0, 4);
    for (uint8_t round = 1; round < 10; round++) {
        SubBytes();     save_state(round, 1);
        ShiftRows();    save_state(round, 2);
        MixColumns();   save_state(round, 3);
        AddRoundKey(round); save_state(round, 4);
    }
    SubBytes();      save_state(10, 1);
    ShiftRows();     save_state(10, 2);
    AddRoundKey(10); save_state(10, 4);
}

uint8_t trace_read(uint8_t index, uint8_t *packet)
{
    if (snapshot_count != AES_TRACE_STEPS) return 3;
    if (index >= AES_TRACE_STEPS) return 4;
    memcpy(packet, snapshots[index], AES_TRACE_PACKET_SIZE);
    return 0;
}

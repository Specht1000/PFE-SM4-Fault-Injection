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

static void execute_operation(uint8_t round, uint8_t operation,
                              const uint8_t *fault, uint8_t *event)
{
    if (fault && round == fault[0] && operation == fault[1]) {
        /* Apply exactly one transient XOR immediately BEFORE the operation. */
        uint8_t *byte = &(*state)[fault[3]][fault[2]];
        event[0] = *byte;
        *byte ^= fault[4];
        event[1] = *byte;
    }
    switch (operation) {
        case 1: SubBytes(); break;
        case 2: ShiftRows(); break;
        case 3: MixColumns(); break;
        case 4: AddRoundKey(round); break;
    }
    save_state(round, operation);
}

static void encrypt_with_snapshots(uint8_t *block, const uint8_t *fault, uint8_t *event)
{
    trace_clear();
    state = (state_t *)block;
    save_state(0, 0); /* Input */
    AddRoundKey(0);
    save_state(0, 4);
    for (uint8_t round = 1; round < 10; round++) {
        for (uint8_t operation = 1; operation <= 4; operation++)
            execute_operation(round, operation, fault, event);
    }
    execute_operation(10, 1, fault, event);
    execute_operation(10, 2, fault, event);
    execute_operation(10, 4, fault, event);
}

void trace_encrypt(uint8_t *block)
{
    encrypt_with_snapshots(block, NULL, NULL);
}

uint8_t trace_encrypt_fault(uint8_t *block, const uint8_t *parameters, uint8_t *event)
{
    trace_clear();
    if (parameters[0] < 1 || parameters[0] > 10 ||
        parameters[1] < 1 || parameters[1] > 4 ||
        (parameters[0] == 10 && parameters[1] == 3) ||
        parameters[2] > 3 || parameters[3] > 3 || parameters[4] == 0)
        return 5;
    encrypt_with_snapshots(block, parameters, event);
    return 0;
}

uint8_t trace_read(uint8_t index, uint8_t *packet)
{
    if (snapshot_count != AES_TRACE_STEPS) return 3;
    if (index >= AES_TRACE_STEPS) return 4;
    memcpy(packet, snapshots[index], AES_TRACE_PACKET_SIZE);
    return 0;
}

void target_decrypt(uint8_t *block)
{
    trace_clear();
    state = (state_t *)block;
    /* Use the expanded key, not a pointer into a previous UART request. */
    InvCipher();
}

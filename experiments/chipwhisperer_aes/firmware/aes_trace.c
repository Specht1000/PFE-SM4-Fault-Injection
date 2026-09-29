/* SPDX-License-Identifier: GPL-3.0-or-later
 * Instrumented educational path, separate from the baseline AES backend.
 * Reuse the pinned TinyAES primitives without editing upstream files.
 * Including the implementation exposes its static round primitives here.
 *
 * WHAT THIS FILE DOES
 * -------------------
 * TinyAES normally runs the ten AES rounds internally and only hands back the
 * final ciphertext. For teaching and fault research we need to (a) see every
 * intermediate state and (b) disturb one state byte at a precise step. Rather
 * than fork TinyAES, we #include its .c file below so its otherwise-private
 * round functions (SubBytes, ShiftRows, MixColumns, AddRoundKey) and the shared
 * `state` pointer become visible here, and we re-run the round schedule
 * ourselves in encrypt_with_snapshots().
 *
 * A "snapshot" is a 19-byte record: [index, round, operation, 16 state bytes].
 * There are 41 of them for one encryption (see AES_TRACE_STEPS).
 */
#include "aes_trace.h"
#include <string.h>
/* Rename TinyAES's public entry points so they do not clash with the baseline
 * AES backend that main.c also links (aes_indep_*). We only want the round
 * primitives from the included file, not its public API. */
#define AES_CONST_VAR static const
#define AES128_ECB_encrypt trace_backend_encrypt
#define AES128_ECB_decrypt trace_backend_decrypt
#define AES128_ECB_indp_setkey trace_backend_setkey
#define AES128_ECB_indp_crypto trace_backend_crypto
#include "aes.c"

/* Storage for the recorded states of the most recent encryption. */
static uint8_t snapshots[AES_TRACE_STEPS][AES_TRACE_PACKET_SIZE];
static uint8_t snapshot_count;

/* Discard any previously recorded states. */
void trace_clear(void) { snapshot_count = 0; }

/* Load the key into the traced backend (and reset the snapshot buffer). */
void trace_set_key(uint8_t *key)
{
    trace_clear();
    trace_backend_setkey(key);
}

/* Append the current AES `state` as one snapshot, tagged with the round number
 * and which operation just ran. `state` is TinyAES's global 4x4 byte matrix. */
static void save_state(uint8_t round, uint8_t operation)
{
    uint8_t *packet = snapshots[snapshot_count];
    packet[0] = snapshot_count;              /* sequential index 0..40 */
    packet[1] = round;                       /* AES round 0..10 */
    packet[2] = operation;                   /* 0=Input,1=SubBytes,2=ShiftRows,3=MixColumns,4=AddRoundKey */
    memcpy(packet + 3, (uint8_t *)state, 16);
    snapshot_count++;
}

/* Run one AES operation, optionally injecting the fault just before it, then
 * save the resulting state. `fault` is NULL for a normal traced encryption. */
static void execute_operation(uint8_t round, uint8_t operation,
                              const uint8_t *fault, uint8_t *event)
{
    if (fault && round == fault[0] && operation == fault[1]) {
        /* Apply exactly one transient XOR immediately BEFORE the operation.
         * fault = {round, operation, row, column, mask}. The AES state is
         * addressed as [row][column]; here [fault[3]][fault[2]] = [column][row]
         * because TinyAES stores the state column-major. `event` records the
         * byte value before and after so the caller can prove the fault hit. */
        uint8_t *byte = &(*state)[fault[3]][fault[2]];
        event[0] = *byte;                    /* value before the fault */
        *byte ^= fault[4];                   /* flip the bits selected by the mask */
        event[1] = *byte;                    /* value after the fault */
    }
    switch (operation) {
        case 1: SubBytes(); break;
        case 2: ShiftRows(); break;
        case 3: MixColumns(); break;
        case 4: AddRoundKey(round); break;
    }
    save_state(round, operation);
}

/* Re-implement the AES-128 encryption schedule so every step is recorded.
 * This mirrors the standard structure: an initial AddRoundKey, nine full
 * rounds (SubBytes, ShiftRows, MixColumns, AddRoundKey), then a final round
 * without MixColumns. Encryption happens in place on `block`. */
static void encrypt_with_snapshots(uint8_t *block, const uint8_t *fault, uint8_t *event)
{
    trace_clear();
    state = (state_t *)block;                /* point TinyAES's state at our block */
    save_state(0, 0); /* Input */            /* snapshot 0: the plaintext */
    AddRoundKey(0);                           /* initial key whitening (round 0) */
    save_state(0, 4);
    for (uint8_t round = 1; round < 10; round++) {   /* rounds 1..9: full rounds */
        for (uint8_t operation = 1; operation <= 4; operation++)
            execute_operation(round, operation, fault, event);
    }
    /* Round 10: SubBytes, ShiftRows, AddRoundKey — no MixColumns. */
    execute_operation(10, 1, fault, event);
    execute_operation(10, 2, fault, event);
    execute_operation(10, 4, fault, event);
}

/* Public: traced encryption with no fault. */
void trace_encrypt(uint8_t *block)
{
    encrypt_with_snapshots(block, NULL, NULL);
}

/* Public: traced encryption with one injected fault.
 * `parameters` = {round, operation, row, column, mask}. Returns 5 if the fault
 * model is invalid, else 0. `event` receives the before/after byte values. */
uint8_t trace_encrypt_fault(uint8_t *block, const uint8_t *parameters, uint8_t *event)
{
    trace_clear();
    /* Reject impossible fault models before touching the AES state:
     * round 1..10, operation 1..4, no MixColumns in round 10, row/column 0..3,
     * and a non-zero mask (a zero mask would change nothing). */
    if (parameters[0] < 1 || parameters[0] > 10 ||
        parameters[1] < 1 || parameters[1] > 4 ||
        (parameters[0] == 10 && parameters[1] == 3) ||
        parameters[2] > 3 || parameters[3] > 3 || parameters[4] == 0)
        return 5;
    encrypt_with_snapshots(block, parameters, event);
    return 0;
}

/* Public: copy one recorded snapshot to `packet`. Returns 3 if no full trace is
 * available, 4 if the index is out of range, else 0. */
uint8_t trace_read(uint8_t index, uint8_t *packet)
{
    if (snapshot_count != AES_TRACE_STEPS) return 3;   /* trace incomplete */
    if (index >= AES_TRACE_STEPS) return 4;            /* bad index */
    memcpy(packet, snapshots[index], AES_TRACE_PACKET_SIZE);
    return 0;
}

/* Public: decrypt one block in place using TinyAES's inverse cipher. */
void target_decrypt(uint8_t *block)
{
    trace_clear();
    state = (state_t *)block;
    /* Use the expanded key, not a pointer into a previous UART request. */
    InvCipher();
}

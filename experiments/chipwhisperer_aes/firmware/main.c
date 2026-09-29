/* SPDX-License-Identifier: GPL-3.0-or-later
 * Educational AES-128 target for CWLITEARM / STM32F303.
 * Uses the ChipWhisperer HAL, SimpleSerial, and TinyAES backend.
 *
 * OVERVIEW
 * --------
 * This firmware turns the STM32 into an AES-128 "target" that a host PC drives
 * over UART using the SimpleSerial V1.1 protocol. The PC sends a one-letter
 * command plus a payload; this firmware runs the requested AES operation and
 * replies. Nothing here is secret-safe: it is deliberately unprotected so it
 * can be measured (power traces) and faulted for study.
 *
 * Each command below is registered in main() with simpleserial_addcmd(). The
 * SimpleSerial library handles the hex-over-UART framing, calls our handler
 * with the decoded bytes, and turns the handler's return value into a 'z'
 * acknowledgement: 0 = success, non-zero = error code the host can read.
 *
 * Command summary (see README "Firmware protocol" for the full table):
 *   'i' identity   -> "AES\3"        (lets the host confirm the right firmware)
 *   'k' set key    -> expand the 16-byte AES key
 *   'p' encrypt    -> ciphertext (the plain path used for power captures)
 *   't' trace      -> encrypt and record all 41 intermediate states in RAM
 *   's' snapshot   -> return one recorded state by index
 *   'd' decrypt    -> plaintext
 *   'f' fault      -> encrypt while injecting one software fault, then trace
 */
#include <stdint.h>
#include <string.h>
#include "hal.h"
#include "simpleserial.h"
#include "aes-independant.h"
#include "aes_trace.h"

/* This code only speaks SimpleSerial V1.1; fail the build on any other. */
#if SS_VER != SS_VER_1_1
#error "This firmware requires SimpleSerial V1.1."
#endif

/* Guard so encrypt/decrypt cannot run before a key is loaded. */
static uint8_t key_loaded = 0;

/* Command 'k': load and expand the 16-byte AES key. */
static uint8_t handle_key(uint8_t *key, uint8_t length)
{
    if (length != 16) return 1;              /* wrong payload length */
    /* Key expansion is outside the measurement trigger window. */
    aes_indep_key(key);                      /* expand key in the AES backend */
    trace_set_key(key);                      /* mirror it into the traced path */
    key_loaded = 1;
    return 0;
}

/* Command 'p': plain AES encryption, in place. This is the baseline path used
 * for power captures because it has no extra memory traffic to disturb timing. */
static uint8_t handle_plaintext(uint8_t *block, uint8_t length)
{
    if (length != 16) return 1;
    if (!key_loaded) return 2;               /* no key loaded yet */

    trace_clear();

    aes_indep_enc_pretrigger(block);
    /* TIO4 marks the encryption region for capture and future FI experiments.
     * The scope watches this pin; raising it high tells the capture where the
     * AES computation starts, and lowering it marks the end. */
    trigger_high();
    aes_indep_enc(block);                    /* block is overwritten with the ciphertext */
    trigger_low();
    aes_indep_enc_posttrigger(block);

    /* One raw AES block: no padding, IV, or multi-block mode. */
    simpleserial_put('r', 16, block);
    return 0;
}

/* Command 't': encrypt AND record every intermediate state so the host can
 * inspect the algorithm step by step. Slower and noisier than 'p'. */
static uint8_t handle_trace(uint8_t *block, uint8_t length)
{
    if (length != 16) return 1;
    if (!key_loaded) return 2;
    /* Snapshot copies change timing. Use command 'p' for baseline captures. */
    trigger_high();
    trace_encrypt(block);                    /* fills the snapshot buffer, see aes_trace.c */
    trigger_low();
    simpleserial_put('r', 16, block);        /* reply with the ciphertext only */
    return 0;
}

/* Command 's': return one recorded state. The host asks for indices 0..40 one
 * at a time (a single 19-byte packet each) to avoid overflowing UART buffers. */
static uint8_t handle_snapshot(uint8_t *data, uint8_t length)
{
    uint8_t packet[AES_TRACE_PACKET_SIZE];
    uint8_t status;
    if (length != 1) return 1;
    status = trace_read(data[0], packet);    /* status 3 = nothing traced, 4 = bad index */
    if (status != 0) return status;
    /* Fetch one snapshot per request to avoid overflowing USB/UART buffers. */
    simpleserial_put('r', sizeof(packet), packet);
    return 0;
}

/* Command 'd': decrypt one block in place using the currently loaded key. */
static uint8_t handle_ciphertext(uint8_t *block, uint8_t length)
{
    if (length != 16) return 1;
    if (!key_loaded) return 2;
    trigger_high();
    target_decrypt(block);                   /* block is overwritten with the plaintext */
    trigger_low();
    simpleserial_put('r', 16, block);
    return 0;
}

/* Command 'i': identity string, so the host can verify it is talking to this
 * exact firmware revision (3) before running the trace/fault commands. */
static uint8_t handle_identity(uint8_t *data, uint8_t length)
{
    uint8_t identity[4] = {'A', 'E', 'S', 3}; /* revision 3 */
    (void)data;                               /* command takes no payload */
    if (length != 0) return 1;
    simpleserial_put('r', sizeof(identity), identity);
    return 0;
}

/* Command 'f': encrypt while injecting a single software fault, then record the
 * states like 't'. This is a *simulated* fault (a controlled bug), not a
 * physical glitch: it XORs one chosen state byte at one chosen step.
 *
 * Payload layout (21 bytes): 5 fault parameters followed by the 16-byte block.
 *   data[0..4] = round, operation, row, column, XOR mask   (the fault model)
 *   data[5..20] = plaintext block
 * Reply (18 bytes): 16-byte faulty ciphertext, then the byte value before and
 * after the XOR (so the host can confirm the fault took effect). */
static uint8_t handle_fault(uint8_t *data, uint8_t length)
{
    uint8_t response[18], status;
    if (length != 21) return 1;
    if (!key_loaded) return 2;
    /* Request contains its own fault model: nothing remains armed afterward.
     * Every 'f' call is self-contained; the next 'p'/'t' runs fault-free. */
    trigger_high();
    status = trace_encrypt_fault(data + 5, data, response + 16); /* block, params, before/after */
    trigger_low();
    if (status != 0) return status;          /* status 5 = invalid fault model */
    memcpy(response, data + 5, 16);          /* faulty ciphertext (block was encrypted in place) */
    simpleserial_put('r', sizeof(response), response);
    return 0;
}

int main(void)
{
    /* Bring up the board: clocks/pins, UART, and the scope trigger pin. */
    platform_init();
    init_uart();
    trigger_setup();
    trigger_low();
    aes_indep_init();
    simpleserial_init();
    /* Register each command with its fixed payload length and handler. */
    simpleserial_addcmd('i', 0, handle_identity);
    simpleserial_addcmd('k', 16, handle_key);
    simpleserial_addcmd('p', 16, handle_plaintext);
    simpleserial_addcmd('t', 16, handle_trace);
    simpleserial_addcmd('s', 1, handle_snapshot);
    simpleserial_addcmd('d', 16, handle_ciphertext);
    simpleserial_addcmd('f', 21, handle_fault);
    /* Main loop: read one command from UART and dispatch it, forever. */
    while (1) simpleserial_get();
}

/* SPDX-License-Identifier: GPL-3.0-or-later
 * Educational AES-128 target for CWLITEARM / STM32F303.
 * Uses the ChipWhisperer HAL, SimpleSerial, and TinyAES backend.
 */
#include <stdint.h>
#include <string.h>
#include "hal.h"
#include "simpleserial.h"
#include "aes-independant.h"
#include "aes_trace.h"

#if SS_VER != SS_VER_1_1
#error "This firmware requires SimpleSerial V1.1."
#endif

static uint8_t key_loaded = 0;

static uint8_t handle_key(uint8_t *key, uint8_t length)
{
    if (length != 16) return 1;
    /* Key expansion is outside the measurement trigger window. */
    aes_indep_key(key);
    trace_set_key(key);
    key_loaded = 1;
    return 0;
}

static uint8_t handle_plaintext(uint8_t *block, uint8_t length)
{
    if (length != 16) return 1;
    if (!key_loaded) return 2;

    trace_clear();

    aes_indep_enc_pretrigger(block);
    /* TIO4 marks the encryption region for capture and future FI experiments. */
    trigger_high();
    aes_indep_enc(block);
    trigger_low();
    aes_indep_enc_posttrigger(block);

    /* One raw AES block: no padding, IV, or multi-block mode. */
    simpleserial_put('r', 16, block);
    return 0;
}

static uint8_t handle_trace(uint8_t *block, uint8_t length)
{
    if (length != 16) return 1;
    if (!key_loaded) return 2;
    /* Snapshot copies change timing. Use command 'p' for baseline captures. */
    trigger_high();
    trace_encrypt(block);
    trigger_low();
    simpleserial_put('r', 16, block);
    return 0;
}

static uint8_t handle_snapshot(uint8_t *data, uint8_t length)
{
    uint8_t packet[AES_TRACE_PACKET_SIZE];
    uint8_t status;
    if (length != 1) return 1;
    status = trace_read(data[0], packet);
    if (status != 0) return status;
    /* Fetch one snapshot per request to avoid overflowing USB/UART buffers. */
    simpleserial_put('r', sizeof(packet), packet);
    return 0;
}

static uint8_t handle_ciphertext(uint8_t *block, uint8_t length)
{
    if (length != 16) return 1;
    if (!key_loaded) return 2;
    trigger_high();
    target_decrypt(block);
    trigger_low();
    simpleserial_put('r', 16, block);
    return 0;
}

static uint8_t handle_identity(uint8_t *data, uint8_t length)
{
    uint8_t identity[4] = {'A', 'E', 'S', 3};
    (void)data;
    if (length != 0) return 1;
    simpleserial_put('r', sizeof(identity), identity);
    return 0;
}

static uint8_t handle_fault(uint8_t *data, uint8_t length)
{
    uint8_t response[18], status;
    if (length != 21) return 1;
    if (!key_loaded) return 2;
    /* Request contains its own fault model: nothing remains armed afterward. */
    trigger_high();
    status = trace_encrypt_fault(data + 5, data, response + 16);
    trigger_low();
    if (status != 0) return status;
    memcpy(response, data + 5, 16);
    simpleserial_put('r', sizeof(response), response);
    return 0;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();
    trigger_low();
    aes_indep_init();
    simpleserial_init();
    simpleserial_addcmd('i', 0, handle_identity);
    simpleserial_addcmd('k', 16, handle_key);
    simpleserial_addcmd('p', 16, handle_plaintext);
    simpleserial_addcmd('t', 16, handle_trace);
    simpleserial_addcmd('s', 1, handle_snapshot);
    simpleserial_addcmd('d', 16, handle_ciphertext);
    simpleserial_addcmd('f', 21, handle_fault);
    while (1) simpleserial_get();
}

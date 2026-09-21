/* SPDX-License-Identifier: GPL-3.0-or-later
 * Educational AES-128 target for CWLITEARM / STM32F303.
 * Uses the ChipWhisperer HAL, SimpleSerial, and TinyAES backend.
 */
#include <stdint.h>
#include "hal.h"
#include "simpleserial.h"
#include "aes-independant.h"

#if SS_VER != SS_VER_1_1
#error "This firmware requires SimpleSerial V1.1."
#endif

static uint8_t key_loaded = 0;

static uint8_t handle_key(uint8_t *key, uint8_t length)
{
    if (length != 16) return 1;
    /* Key expansion is outside the measurement trigger window. */
    aes_indep_key(key);
    key_loaded = 1;
    return 0;
}

static uint8_t handle_plaintext(uint8_t *block, uint8_t length)
{
    if (length != 16) return 1;
    if (!key_loaded) return 2;

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

static uint8_t handle_identity(uint8_t *data, uint8_t length)
{
    uint8_t identity[4] = {'A', 'E', 'S', 1};
    (void)data;
    if (length != 0) return 1;
    simpleserial_put('r', sizeof(identity), identity);
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
    while (1) simpleserial_get();
}

/* SimpleSerial 1.1 SM4 target for CWLITEARM / STM32F303. */
#include "hal.h"
#include "simpleserial.h"
#include "sm4.h"

#if SS_VER != SS_VER_1_1
#error "This firmware requires SS_VER=SS_VER_1_1."
#endif

static sm4_context context;
static uint8_t key_ready = 0;
static uint8_t trigger_round = 255; /* 255 = entire cipher, 0..31 = one round. */

static void mark_round(uint8_t round, uint8_t entering)
{
    if (round == trigger_round) {
        if (entering) {
            trigger_high();
        } else {
            trigger_low();
        }
    }
}

static uint8_t set_key(uint8_t *data, uint8_t length)
{
    if (length != SM4_BLOCK_SIZE) {
        return 2;
    }

    /* Key expansion is outside the encryption/decryption trigger window. */
    sm4_set_key(&context, data);
    key_ready = 1;
    return 0;
}

static uint8_t process_block(uint8_t *data, uint8_t length, uint8_t decrypt)
{
    uint8_t output[SM4_BLOCK_SIZE];

    if (!key_ready) {
        return 1;
    }

    if (length != SM4_BLOCK_SIZE) {
        return 2;
    }

    trigger_low();

    if (trigger_round == 255) {
        trigger_high();
    }

    sm4_crypt_block(&context, data, output, decrypt, mark_round);
    trigger_low();

    /* UART transmission happens only AFTER the trigger goes low. */
    simpleserial_put('r', SM4_BLOCK_SIZE, output);
    return 0;
}

static uint8_t encrypt_block(uint8_t *data, uint8_t length)
{
    return process_block(data, length, 0);
}

static uint8_t decrypt_block(uint8_t *data, uint8_t length)
{
    /* Decryption runs the same round function with reversed subkey order. */
    return process_block(data, length, 1);
}

static uint8_t set_trigger(uint8_t *data, uint8_t length)
{
    if (length != 1 || (data[0] > 31 && data[0] != 255)) {
        return 2;
    }

    trigger_round = data[0];
    return 0;
}

static uint8_t identify(uint8_t *data, uint8_t length)
{
    uint8_t identity[4] = {'S', 'M', '4', 1};
    (void)data;
    (void)length;
    simpleserial_put('r', sizeof(identity), identity);
    return 0;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();
    trigger_low();
    simpleserial_init();

    /* SimpleSerial appends a zXX acknowledgement to every command. */
    simpleserial_addcmd('i', 0, identify);
    simpleserial_addcmd('k', 16, set_key);
    simpleserial_addcmd('p', 16, encrypt_block);
    simpleserial_addcmd('d', 16, decrypt_block);
    simpleserial_addcmd('t', 1, set_trigger);

    while (1) {
        simpleserial_get();
    }
}

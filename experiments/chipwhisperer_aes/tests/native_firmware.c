/* Exercise the real firmware callbacks and upstream AES on the host CPU.
 * GPIO/UART are stubbed; this does not validate physical hardware timing.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define main firmware_main
#include "../firmware/main.c"
#undef main

static int trigger_level, rising_edges, falling_edges, response_count;
static uint8_t response[16], response_length;
void platform_init(void) {}
void init_uart(void) {}
void trigger_setup(void) {}
void trigger_high(void) { assert(!trigger_level); trigger_level = 1; rising_edges++; }
void trigger_low(void) { assert(trigger_level); trigger_level = 0; falling_edges++; }
void simpleserial_init(void) {}
void simpleserial_get(void) {}
int simpleserial_addcmd(char command, unsigned int length,
                       uint8_t (*callback)(uint8_t *, uint8_t))
{ (void)command; (void)length; (void)callback; return 0; }
void simpleserial_put(char command, uint8_t length, uint8_t *data)
{
    assert(command == 'r' && length <= 16 && trigger_level == 0);
    memcpy(response, data, length);
    response_length = length;
    response_count++;
}
static void decode(const char *text, uint8_t *bytes)
{
    unsigned int value;
    assert(strlen(text) == 32);
    for (int i = 0; i < 16; i++) {
        assert(sscanf(text + 2 * i, "%2x", &value) == 1);
        bytes[i] = (uint8_t)value;
    }
}
int main(int argc, char **argv)
{
    uint8_t key[16], block[16];
    if (argc != 3) return 1;
    decode(argv[1], key);
    decode(argv[2], block);
    aes_indep_init();
    assert(handle_identity(NULL, 0) == 0);
    assert(response_length == 4 && memcmp(response, "AES\x01", 4) == 0);
    assert(handle_plaintext(block, 16) == 2);
    assert(rising_edges == 0 && response_count == 1);
    assert(handle_key(key, 15) == 1);
    assert(handle_key(key, 16) == 0);
    assert(handle_plaintext(block, 15) == 1);
    assert(handle_plaintext(block, 16) == 0);
    assert(rising_edges == 1 && falling_edges == 1);
    assert(response_count == 2 && response_length == 16);
    for (int i = 0; i < 16; i++) printf("%02x", response[i]);
    puts("");
    return 0;
}

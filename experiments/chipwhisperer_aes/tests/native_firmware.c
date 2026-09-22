/* Exercise the real firmware callbacks and upstream AES on the host CPU.
 * GPIO/UART are stubbed; this does not validate physical hardware timing.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define main firmware_main
#include "../firmware/main.c"
#undef main

static int trigger_level, rising_edges, falling_edges, response_count;
static uint8_t response[AES_TRACE_PACKET_SIZE], response_length;
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
    assert(command == 'r' && length <= AES_TRACE_PACKET_SIZE && trigger_level == 0);
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
    uint8_t key[16], block[16], plaintext[16], ciphertext[16], index;
    if (argc != 3 && argc != 4 && argc != 9) return 1;
    decode(argv[1], key);
    decode(argv[2], block);
    memcpy(plaintext, block, 16);
    aes_indep_init();
    assert(handle_identity(NULL, 0) == 0);
    assert(response_length == 4 && memcmp(response, "AES\x03", 4) == 0);
    index = 0;
    assert(handle_snapshot(&index, 1) == 3);
    uint8_t request[21] = {0};
    assert(handle_fault(request, 20) == 1);
    assert(handle_fault(request, 21) == 2);
    assert(handle_trace(block, 16) == 2);
    assert(handle_ciphertext(block, 16) == 2);
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
    memcpy(ciphertext, response, 16);
    memcpy(block, plaintext, 16);
    assert(handle_trace(block, 15) == 1);
    assert(handle_trace(block, 16) == 0);
    assert(memcmp(response, ciphertext, 16) == 0);
    assert(rising_edges == 2 && falling_edges == 2);
    assert(handle_snapshot(&index, 0) == 1);
    for (index = 0; index < AES_TRACE_STEPS; index++) {
        assert(handle_snapshot(&index, 1) == 0);
        assert(response_length == AES_TRACE_PACKET_SIZE && response[0] == index);
        if (index == 0) assert(memcmp(response + 3, plaintext, 16) == 0);
        if (index == 40) assert(memcmp(response + 3, ciphertext, 16) == 0);
        if (argc == 4) {
            for (int i = 0; i < AES_TRACE_PACKET_SIZE; i++) printf("%02x", response[i]);
            puts("");
        }
    }
    assert(handle_snapshot(&index, 1) == 4);
    memcpy(block, ciphertext, 16);
    assert(handle_ciphertext(block, 15) == 1);
    assert(handle_ciphertext(block, 16) == 0);
    assert(memcmp(response, plaintext, 16) == 0);
    assert(rising_edges == 3 && falling_edges == 3);
    index = 0;
    assert(handle_snapshot(&index, 1) == 3);
    assert(handle_key(key, 16) == 0);
    index = 0;
    assert(handle_snapshot(&index, 1) == 3);
    if (argc == 9) {
        for (int i = 0; i < 5; i++) request[i] = (uint8_t)strtoul(argv[4 + i], NULL, 0);
        memcpy(request + 5, plaintext, 16);
        assert(handle_fault(request, 21) == 0);
        assert(response_length == 18);
        memcpy(ciphertext, response, 16);
        for (int i = 0; i < 16; i++) printf("%02x", response[i]);
        puts("");
        printf("%02x%02x\n", response[16], response[17]);
        for (index = 0; index < AES_TRACE_STEPS; index++) {
            assert(handle_snapshot(&index, 1) == 0);
            for (int i = 0; i < AES_TRACE_PACKET_SIZE; i++) printf("%02x", response[i]);
            puts("");
        }
        assert(handle_ciphertext(ciphertext, 16) == 0);
        for (int i = 0; i < 16; i++) printf("%02x", response[i]);
        puts("");
        memcpy(block, plaintext, 16);
        assert(handle_plaintext(block, 16) == 0);
        for (int i = 0; i < 16; i++) printf("%02x", response[i]);
        puts("");
    }
    /* Invalid fault models are rejected by the target, independently of Python. */
    const uint8_t invalid[][5] = {{0,3,0,0,1},{11,3,0,0,1},{10,3,0,0,1},
        {9,0,0,0,1},{9,5,0,0,1},{9,3,4,0,1},{9,3,0,4,1},{9,3,0,0,0}};
    for (unsigned int i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        memcpy(request, invalid[i], 5);
        memcpy(request + 5, plaintext, 16);
        assert(handle_fault(request, 21) == 5);
        assert(memcmp(request + 5, plaintext, 16) == 0);
        index = 0;
        assert(handle_snapshot(&index, 1) == 3);
    }
    return 0;
}

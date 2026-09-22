#ifndef TEST_SIMPLESERIAL_H
#define TEST_SIMPLESERIAL_H
#include <stdint.h>
#define SS_VER_1_1 1
#define SS_VER SS_VER_1_1
void simpleserial_init(void);
int simpleserial_addcmd(char command, unsigned int length,
                       uint8_t (*callback)(uint8_t *, uint8_t));
void simpleserial_get(void);
void simpleserial_put(char command, uint8_t length, uint8_t *data);
#endif

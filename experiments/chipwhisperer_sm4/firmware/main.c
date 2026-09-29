#include "hal.h"
#include "simpleserial.h"
#include "sm4.h"
#include <stddef.h>
#include <string.h>
static uint32_t keys[32];
static uint8_t states[34][16], key_ready, trace_ready;
static uint8_t identity(uint8_t *data, uint8_t len) {
    uint8_t id[4]={'S','M','4',1}; (void)data;
    if(len) return 1;
    simpleserial_put('r',4,id); return 0;
}
static uint8_t key(uint8_t *data, uint8_t len) {
    if(len!=16) return 1;
    sm4_expand(data,keys); key_ready=1; trace_ready=0; return 0;
}
static uint8_t run(uint8_t *data, uint8_t len, int decrypt, int trace, int faulty) {
    uint8_t reply[18]; sm4_fault fault; const uint8_t *input=data;
    trace_ready=0;
    if(len!=(faulty?20:16)) return 1;
    if(!key_ready) return 2;
    if(faulty) {
        fault.round=data[0]; fault.word=data[1]; fault.byte=data[2]; fault.mask=data[3];
        if(fault.round<1 || fault.round>32 || fault.word>3 || fault.byte>3 || !fault.mask) return 5;
        input=data+4;
    }
    /* UART transfer is outside the measured interval. Trace mode adds memory writes. */
    trigger_high();
    sm4_block(input,reply,keys,decrypt,trace?states:NULL,faulty?&fault:NULL,reply+16);
    trigger_low(); trace_ready=(uint8_t)trace;
    simpleserial_put('r',faulty?18:16,reply); return 0;
}
static uint8_t enc(uint8_t *d,uint8_t n) { return run(d,n,0,0,0); }
static uint8_t dec(uint8_t *d,uint8_t n) { return run(d,n,1,0,0); }
static uint8_t trace_enc(uint8_t *d,uint8_t n) { return run(d,n,0,1,0); }
static uint8_t trace_dec(uint8_t *d,uint8_t n) { return run(d,n,1,1,0); }
static uint8_t inject(uint8_t *d,uint8_t n) { return run(d,n,0,1,1); }
static uint8_t snapshot(uint8_t *d,uint8_t n) {
    uint8_t reply[19],i;
    if(n!=1) return 1;
    if(!trace_ready) return 3;
    i=d[0];
    if(i>=34) return 4;
    reply[0]=i; reply[1]=(i==33)?32:i; reply[2]=(i==0)?0:((i==33)?2:1);
    memcpy(reply+3,states[i],16); simpleserial_put('r',19,reply); return 0;
}
int main(void) {
    platform_init(); init_uart(); trigger_setup(); simpleserial_init();
    simpleserial_addcmd('i',0,identity); simpleserial_addcmd('k',16,key);
    simpleserial_addcmd('p',16,enc); simpleserial_addcmd('d',16,dec);
    simpleserial_addcmd('t',16,trace_enc); simpleserial_addcmd('u',16,trace_dec);
    simpleserial_addcmd('f',20,inject); simpleserial_addcmd('s',1,snapshot);
    while(1) simpleserial_get();
}

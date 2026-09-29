/* Native test adapter: the exact firmware cipher, without MCU peripherals. */
#include "sm4.h"
#include <stdio.h>
#include <stdlib.h>
static void parse(const char *s,uint8_t *out) {
    unsigned i,v; for(i=0;i<16;i++) { sscanf(s+2*i,"%2x",&v); out[i]=(uint8_t)v; }
}
static void print_bytes(const uint8_t *p,unsigned n) {
    unsigned i; for(i=0;i<n;i++) printf("%02x",p[i]); puts("");
}
int main(int argc,char **argv) {
    uint8_t key[16],block[16],out[16],states[34][16],event[2]={0};
    uint32_t rk[32]; sm4_fault fault; unsigned i;
    if(argc!=4 && argc!=8) return 2;
    parse(argv[1],key); parse(argv[2],block); sm4_expand(key,rk);
    if(argc==8) {
        fault.round=(uint8_t)atoi(argv[4]); fault.word=(uint8_t)atoi(argv[5]);
        fault.byte=(uint8_t)atoi(argv[6]); fault.mask=(uint8_t)atoi(argv[7]);
    }
    sm4_block(block,out,rk,atoi(argv[3]),states,argc==8?&fault:NULL,event);
    print_bytes(out,16); print_bytes(event,2);
    for(i=0;i<34;i++) print_bytes(states[i],16);
    return 0;
}

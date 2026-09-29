#include "sm4.h"
#include <stddef.h>
static const uint8_t sbox[256] = {
#include "sbox.inc"
};
static uint32_t rol(uint32_t v, unsigned n) { return (v << n) | (v >> (32-n)); }
static uint32_t load(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static void save(uint8_t *p, const uint32_t x[4]) {
    unsigned i,j;
    for(i=0;i<4;i++) for(j=0;j<4;j++) p[4*i+j]=(uint8_t)(x[i]>>(24-8*j));
}
static uint32_t tau(uint32_t v) {
    return ((uint32_t)sbox[v>>24]<<24)|((uint32_t)sbox[(v>>16)&255]<<16)|
           ((uint32_t)sbox[(v>>8)&255]<<8)|sbox[v&255];
}
void sm4_expand(const uint8_t key[16], uint32_t rk[32]) {
    const uint32_t fk[4]={0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc};
    uint32_t k[4],ck,b,next; unsigned i,j;
    for(i=0;i<4;i++) k[i]=load(key+4*i)^fk[i];
    for(i=0;i<32;i++) {
        ck=0; for(j=0;j<4;j++) ck=(ck<<8)|(((4*i+j)*7)&255);
        b=tau(k[1]^k[2]^k[3]^ck);
        next=k[0]^b^rol(b,13)^rol(b,23); rk[i]=next;
        k[0]=k[1]; k[1]=k[2]; k[2]=k[3]; k[3]=next;
    }
}
void sm4_block(const uint8_t input[16], uint8_t output[16],
               const uint32_t rk[32], int decrypt,
               uint8_t snapshots[34][16], const sm4_fault *fault,
               uint8_t event[2]) {
    uint32_t x[4],b,next,tmp; unsigned i,shift;
    for(i=0;i<4;i++) x[i]=load(input+4*i);
    if(snapshots) save(snapshots[0],x);
    for(i=0;i<32;i++) {
        if(fault && fault->round==i+1 && fault->word<4 && fault->byte<4) {
            shift=24-8*fault->byte;
            if(event) event[0]=(uint8_t)(x[fault->word]>>shift);
            x[fault->word]^=(uint32_t)fault->mask<<shift;
            if(event) event[1]=(uint8_t)(x[fault->word]>>shift);
        }
        b=tau(x[1]^x[2]^x[3]^rk[decrypt ? 31-i : i]);
        next=x[0]^b^rol(b,2)^rol(b,10)^rol(b,18)^rol(b,24);
        x[0]=x[1]; x[1]=x[2]; x[2]=x[3]; x[3]=next;
        if(snapshots) save(snapshots[i+1],x);
    }
    tmp=x[0]; x[0]=x[3]; x[3]=tmp; tmp=x[1]; x[1]=x[2]; x[2]=tmp;
    save(output,x); if(snapshots) save(snapshots[33],x);
}

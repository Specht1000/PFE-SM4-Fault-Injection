# Build after staging this directory under ChipWhisperer firmware/mcu/pfe-aes.
TARGET = pfe-aes
SRC += main.c aes_trace.c
PLATFORM = CWLITEARM
CRYPTO_TARGET = TINYAES128C
SS_VER = SS_VER_1_1
OPT = s
FIRMWAREPATH = ..
include $(FIRMWAREPATH)/Makefile.inc

# The Giraud Differential Fault Attack on AES-128

This note explains the Giraud fault attack and demonstrates it against this
project's own AES-128. The runnable demonstration is
[`fault_injection/giraud_attack/giraud.py`](../../fault_injection/giraud_attack/giraud.py);
it recovers the full 128-bit key from correct/faulty ciphertext pairs using
only the Python standard library.

The related demo in
[`fault_injection/aes_fi_demo`](../../fault_injection/aes_fi_demo/README.md)
shows how a fault *propagates* through the rounds but stops before key
recovery. This note supplies the missing step: turning faulty outputs into the
key. It is an educational, defensive study — it motivates why unprotected AES
implementations need fault countermeasures.

## Two kinds of activity

- **Fault injection (FI):** physically or logically disturbing a computation so
  one operation produces a wrong result (a flipped bit, a skipped instruction).
- **Differential fault analysis (DFA):** the mathematics that compares a correct
  output with a faulty one and solves for secret material. Giraud's attack is
  a DFA; the fault injection is only its input.

## AES-128 background needed for the attack

AES-128 encrypts a 16-byte block over ten rounds. Each round applies SubBytes
(a fixed byte substitution, the S-box), ShiftRows (a byte permutation),
MixColumns (a linear mix of each column), and AddRoundKey (XOR with a round
key). The **last round has no MixColumns**:

```
last round:  SubBytes  ->  ShiftRows  ->  AddRoundKey(K10)
```

Write the state entering the last round as `S`. Because ShiftRows only moves
bytes and AddRoundKey and SubBytes act byte-by-byte, each ciphertext byte is:

```
C[j] = SBOX( S[i] ) XOR K10[j]
```

where byte `i` of `S` is sent to output position `j` by ShiftRows. `K10` is the
round-10 key. If we learn all 16 bytes of `K10`, the AES key schedule is
invertible, so we recover the original key.

## The fault model

Giraud's Attack 1 (the bit-fault variant, the one demonstrated here) assumes:

- The attacker can run the same encryption twice on the same input, once
  correctly and once with a fault.
- The fault flips **one bit** of **one byte** of the state at the **input of the
  last round** — that is, immediately *before* the final SubBytes.

Under this model the disturbed byte value becomes `S[i] XOR e`, where `e` has a
single set bit. Because SubBytes, ShiftRows, and AddRoundKey are all byte-local
after that point, **exactly one ciphertext byte changes**. In this project the
same disturbance is produced by:

- Software model: `Fault(round=10, stage='SubBytes', row, column, mask)` in the
  fault demo (`mask = 0x01, 0x02, 0x04, ...` selects the flipped bit).
- On hardware: the firmware `f` command, e.g. the terminal input
  `/fault 10 SubBytes 0 0 0x01`
  (see [`experiments/chipwhisperer_aes`](../../experiments/chipwhisperer_aes/README.md)).

## Recovering one key byte

Fix an output position `j` that the fault reaches. The attacker knows the
correct byte `C[j]` and the faulty byte `C'[j]`, and guesses the key byte `k`:

```
a       = INV_SBOX( C[j]  XOR k )     # correct value entering SubBytes
a_prime = INV_SBOX( C'[j] XOR k )     # faulty value entering SubBytes
e_guess = a XOR a_prime               # the fault this guess implies
```

For the **true** key byte, `a` is the real `S[i]` and `a_prime` is `S[i] XOR e`,
so `e_guess` is the real single-bit fault: its Hamming weight is 1. A wrong `k`
generally implies a fault with a different Hamming weight. So the rule is:

> Keep every key-byte guess `k` whose implied fault `e_guess` flips exactly one
> bit.

A single fault usually leaves a small handful of surviving candidates.
Injecting a few more single-bit faults **on the same input byte** (different bit
positions) and intersecting the candidate sets isolates a unique key byte.

## Recovering the whole key

Repeat for every one of the 16 state-byte positions at the input of the last
round. ShiftRows sends each to a distinct output byte, so the 16 campaigns yield
all 16 bytes of `K10`. Finally, invert the AES-128 key schedule to turn `K10`
back into the master key (implemented in `invert_key_schedule`).

## Running it on our AES

```powershell
python fault_injection/giraud_attack/giraud.py --verbose
```

Output (public FIPS 197 key and plaintext):

```
Plaintext:         00112233445566778899aabbccddeeff
Correct ciphertext:69c4e0d86a7b0430d8cdb78070b4c55a
Recovering the round-10 key from single-bit last-round faults...
  input (0,0) -> output byte  0: 0x13
  input (1,0) -> output byte 13: 0x2b
  ...
  input (3,3) -> output byte  3: 0x7f
Recovered K10:     13111d7fe3944a17f307a78b4d2b30c5
Recovered key:     000102030405060708090a0b0c0d0e0f
Actual key:        000102030405060708090a0b0c0d0e0f
Key recovery:      SUCCESS
```

The `input (row,column) -> output byte` lines make the ShiftRows permutation of
the last round visible: neighbouring input bytes land on scattered output bytes.

Try any key or block; the attack recovers the key it was never told:

```powershell
python fault_injection/giraud_attack/giraud.py --key 2b7e151628aed2a6abf7158809cf4f3c --plaintext 6bc1bee22e409f96e93d7e117393172a
```

Tests (known-answer, key-schedule inversion, and full attack on random keys):

```powershell
python -m unittest discover -s fault_injection/giraud_attack -p test_giraud.py -v
```

## What this shows, and does not

- It shows that a **single-bit fault at the last round of unprotected AES leaks
  the key**, needing only a few faults per key byte and no plaintext control.
- The software model computes ciphertexts directly; it does not drive glitching
  hardware. The intermediate states are used only to construct the faulty
  ciphertexts an attacker would collect, not as extra attacker knowledge.

## Countermeasures (why this matters for defence)

- **Redundancy:** encrypt twice (or verify by decrypting the result) and refuse
  to output a block if the two disagree — a single fault is then caught.
- **Infection:** propagate any detected difference so a faulty ciphertext
  carries no usable information instead of the clean single-byte difference the
  attack depends on.
- **Sensors and detectors:** clock, voltage, and light sensors that reset the
  device when a glitch is attempted.

The [`countermeasures/`](../../countermeasures/) directory is reserved for this
project's defence experiments against attacks like this one.

## References

- C. Giraud, *DFA on AES*, Advanced Encryption Standard – AES (LNCS 3373), 2004.
- FIPS 197, *Advanced Encryption Standard*:
  https://csrc.nist.gov/pubs/fips/197/final
- P. Dusart, G. Letourneux, O. Vivolo, *Differential Fault Analysis on AES*, 2003
  (the related byte-fault DFA).

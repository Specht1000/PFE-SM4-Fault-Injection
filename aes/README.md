# AES-128: a readable Python lesson

Run from the repository root with Python 3.9 or newer. No packages or board are required.

```powershell
python aes/src/aes.py
python aes/src/aes.py --step
python aes/src/aes.py --quiet
```

`--step` waits for Enter after each state. The program prints eleven round keys,
each encryption transformation, every inverse decryption transformation, and a
round-trip check. Default inputs reproduce the AES example:

```text
Key:        000102030405060708090a0b0c0d0e0f
Plaintext:  00112233445566778899aabbccddeeff
Ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
```

Change inputs with `--key HEX --plaintext HEX`, each exactly 16 bytes. This lesson
implements one raw AES-128 block, without text encoding, padding or a block mode.

## Suggested reading order

1. `encrypt_block`: read the overall round sequence first. There is an initial
   AddRoundKey, nine complete rounds and a final round without MixColumns.
2. `add_round_key`: XOR the key bytes into the state.
3. `sub_bytes`: replace each byte using the S-box; this introduces nonlinearity.
4. `shift_rows`: move bytes between columns by rotating rows.
5. `mix_columns`: mix four bytes within each column using finite-field arithmetic.
6. `expand_key`: derive K0 through K10 with RotWord, SubWord and Rcon.
7. `decrypt_block`: undo the operations in reverse order.
8. `gf_mul` and `make_sbox`: inspect the mathematics behind multiplication and
   the S-box. Tables are generated once at import, not during each round.

The flat storage order is **column-major**: byte index = `4*column + row`. The
printed grid displays rows, so consecutive input bytes appear vertically.
All core transformations are implemented visibly in this file, without hiding
encryption inside a cryptography package. `trace` is an optional observer; it
receives immutable copies, and importing the module runs no demonstration.

The `Fault` hook and `reverse_key_schedule` support the next lesson:
[Piret-style differential fault analysis](../fault_injection/piret_attack/README.md).

This is instructional code, not a constant-time production implementation.
Algorithm reference: [NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf).

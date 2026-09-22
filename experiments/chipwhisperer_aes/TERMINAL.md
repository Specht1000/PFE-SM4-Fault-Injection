# Interactive AES terminal: PC -> STM32 -> PC

The STM32 performs both encryption and decryption. The PC handles user input,
displays target responses, and independently verifies results using PyCryptodome.
There is no simulation fallback when hardware is absent.

## Start

Run from the workspace root. Reflash the updated firmware first: this terminal
supports normal operation with revision 2 or 3; software fault injection requires
revision 3 (`AES\x03`). All use SimpleSerial V1.1.
The updated HEX file is already compiled. All commands are also in `commands.txt`.

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_capture.py flash
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_terminal.py
```

Examples at the prompt:

```text
AES> Hello STM32!
AES> hex:00112233445566778899aabbccddeeff
AES> decrypt:69c4e0d86a7b0430d8cdb78070b4c55a
AES> /quit
```

The known-answer example uses the public key `000102030405060708090a0b0c0d0e0f`.
It encrypts `00112233445566778899aabbccddeeff` into
`69c4e0d86a7b0430d8cdb78070b4c55a` and recovers the original block by decryption.

## What the terminal displays

1. Input format, original bytes, padding, and key.
2. Each block sent from the PC to the STM32.
3. The 41 snapshots recorded on the STM32: input, initial AddRoundKey, four
   operations per round for rounds 1–9, and three operations in round 10.
4. The returned ciphertext, checked against an independent AES implementation.
5. A decryption request carrying that ciphertext back to the STM32.
6. Recovered plaintext, checked byte-for-byte against the original block.
7. Concatenated ciphertext and recovered original message, with a final PASS.

The snapshots come from the firmware, not a reconstruction on the PC. The MCU
stores them in RAM during encryption and returns one snapshot per subsequent
request. Operation IDs are 0=input, 1=SubBytes, 2=ShiftRows, 3=MixColumns,
4=AddRoundKey. New keys, normal encryption, and decryption invalidate saved states.
UART requests are sequential, avoiding a large unsolicited stream of snapshots.

## Input and padding

- Plain text or `text:<message>`: encode as UTF-8, add PKCS#7 padding on the PC,
  and split into independent AES blocks. An aligned message gets a full padding
  block. Empty text is supported.
- `hex:<blocks>`: a nonempty multiple of 16 bytes, with no padding added.
- `decrypt:<hex>`: raw block decryption; no padding removed.
- `decrypt-text:<hex>`: decrypt, validate and remove PKCS#7 padding, then display
  UTF-8 if the recovered bytes form valid text.
- `--key <32 hex digits>`: select a different AES-128 key for the session.

Every encryption automatically checks a hardware encrypt/decrypt round trip.
Multi-block messages use ECB for teaching; this is not an authenticated message
format. The independent known-answer/reference checks complement the round trip:
an invertible implementation alone would not prove that it implements AES correctly.

## One-shot commands

```powershell
# Encrypt one raw block and show 4x4 state matrices.
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_terminal.py --hex 00112233445566778899aabbccddeeff --matrix

# Encrypt a text message and verify target-side decryption.
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_terminal.py --text 'Hello STM32!'

# Decrypt one raw ciphertext block on the target.
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_terminal.py --decrypt 69c4e0d86a7b0430d8cdb78070b4c55a
```

For padded text ciphertext, add `--unpad` to `--decrypt`.
`--step` pauses the display of each recorded state; it does not halt the MCU.
`--no-trace` selects normal encryption and still verifies decryption on the STM32.

## Measurement distinction

### Software fault injection on the STM32

Reflash the latest HEX using the `flash` command above, then enable FI:

```text
AES> /fault on
AES> hex:00112233445566778899aabbccddeeff
AES> /fault 9 MixColumns 0 0 0x55
AES> Hello STM32!
AES> /fault off
```

Configuration syntax: `/fault ROUND STAGE ROW COLUMN MASK [BLOCK]`.
Stages: `SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey` (case-sensitive).
Defaults: round 9, before MixColumns, row 0, column 0, mask `0x01`, message block 1.
The optional block index starts at 1; rows and columns start at 0.
Round 10 has no MixColumns. Mask zero and invalid indices are rejected on both
the PC and the STM32. The mask is an XOR difference, not a replacement byte.

One-shot example:

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_terminal.py --hex 00112233445566778899aabbccddeeff --fault --fault-round 9 --fault-stage MixColumns --fault-row 0 --fault-column 0 --fault-mask 0x01
```

For each input message, the terminal obtains a fault-free result and validates
it with an independent AES reference and target-side decryption. It then sends
a separate `f` request for the selected block, carrying the fault parameters and
the same plaintext. The MCU performs `state[column][row] ^= mask` immediately
before the selected operation, exactly once. Other blocks remain fault-free.

The output includes the affected byte before/after injection, XOR differences
for all saved states, differing byte/bit counts, both ciphertexts, and decryption
of the faulty ciphertext. `--matrix` adds correct/faulty state matrices.
Snapshots are after each operation; the separately returned before/after byte
shows the injection itself. For the default one-bit fault, MixColumns spreads
the single-byte difference into four bytes.

For the public known-answer input and default fault:

```text
Correct ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
Faulty ciphertext:  1bc4e0d86a7b04a5d8cd58807083c55a
Ciphertext XOR:     72000000000000950000ef0000370000
```

Decryption of the faulty ciphertext is checked against independent AES
decryption. Its mismatch with the original plaintext is reported as the
**expected fault consequence**, not as a decryption implementation error.
Recovered bytes are displayed raw with padding retained; the program does not
try to interpret corrupted plaintext as valid PKCS#7 text.

`/fault on` enables comparisons for subsequent encryption messages in this PC
session. Each hardware request contains its own fault model; nothing is left
armed on the target. `/fault off` restores the ordinary workflow. Explicit
decryption commands never inject faults. This option does not recover the key.

This is software emulation of a transient state fault **executed on the STM32**.
It does not use voltage, clock, electromagnetic, or laser perturbations, and it
does not establish that the same fault is physically achievable. Both physical
glitch outputs remain disabled.

### Timing and validation

`firmware/aes_trace.c` reuses the pinned TinyAES round primitives in a separate
translation unit, preserving the upstream source files. Snapshot copying changes
execution time and exposes internal states deliberately for teaching. Use the
normal `p` command (as in `aes_capture.py capture`) for baseline power captures.
Rebuilding changes code layout, so earlier physical glitch timing calibrations
must be checked again.

Software tests exercise real compiled C callbacks and compare every saved state
with the Python reference. GPIO/UART are stubbed in those tests. Physical UART,
programming, and timing still need validation on your connected board.

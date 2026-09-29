# SM4 experiment: implementation and file report

## Purpose and architecture

The STM32F303 performs every encryption, decryption and injected-fault operation.
The PC sends commands through ChipWhisperer-Lite SimpleSerial V1.1, reads results,
and checks them against a separate Python implementation. The browser talks only
to the local Python HTTP server. Hardware connections are serialized by a lock.

```text
Browser GUI / terminal
         | requests and verified reports
sm4_device.py + sm4_reference.py
         | USB via the ChipWhisperer Python package
ChipWhisperer-Lite capture board
         | 38400 baud UART / clock / reset / TIO4 trigger
STM32F303: main.c -> sm4.c
```

The new directory is independent of the AES experiment. Both applications share
the vendored ChipWhisperer HAL/build dependencies. Only one application occupies
the target at a time; programming SM4 replaces AES. This work does not modify the
existing `sm4/src/sm4.py` demonstration or the AES source files.

## File inventory

| File | Responsibility |
| --- | --- |
| `firmware/sm4.h` | Cipher API, four-byte fault descriptor, snapshot buffer contract. |
| `firmware/sm4.c` | Big-endian conversion, key expansion, 32 rounds, decrypt key order, trace and XOR hook. |
| `firmware/sbox.inc` | Standard 256-byte SM4 substitution table, also present in the repository's original Python SM4 demo. |
| `firmware/main.c` | STM32 initialization, SimpleSerial handlers, input validation, trigger and snapshot lifetime. |
| `firmware/Makefile` | CWLITEARM, SimpleSerial 1.1, size optimization and `CRYPTO_TARGET=NONE`; SM4 comes from our C source. |
| `build.py` | Stages application files, invokes ARM GCC through make, exports HEX/ELF/map/listing and records hashes. |
| `build/pfe-sm4-CWLITEARM.hex` | Flashable STM32F303 application. |
| `build/build_info.json` | Compiler, upstream revision, source and artifact SHA-256 hashes. |
| `sm4_reference.py` | Python key schedule and round oracle, including the same explicitly defined fault model. |
| `sm4_device.py` | USB lifecycle, protocol validation, known-answer tests, target/reference comparisons and message processing. |
| `sm4_terminal.py` | Interactive and one-shot encrypt/decrypt/FI commands with JSON output. |
| `sm4_capture.py` | Flash, verify and baseline ADC capture commands; per-trace persistence and metadata. |
| `gui_server.py` | Standard-library HTTP server on loopback port 8766; one locked hardware session. |
| `gui/index.html` | AES-matched visual layout with SM4 tabs, controls and state matrices. |
| `gui/app.js` | Connection/key controls, verified operation requests, round steppers, fault comparisons and JSON export. |
| `requirements.txt` | Pinned ChipWhisperer 6.0.0 and compatible NumPy 1.26.4. |
| `commands.txt` | PowerShell setup, build, flash, GUI, terminal, capture, tests and AES restoration commands. |
| `tests/native_runner.c` | Native adapter calling the exact firmware cipher without MCU peripherals. |
| `tests/test_sm4.py` | Cipher, fault, host/protocol-adapter, input and HTTP tests. |
| `.gitignore` | Excludes environment, caches, results and bulky build products; retains HEX and build metadata. |
| `README.md` | Board setup and practical demonstration walkthrough. |
| `FILES.md` | This design and validation report. |

## Cipher implementation

SM4 uses a 128-bit key, a 128-bit block and 32 rounds. Each block becomes four
big-endian 32-bit words. `sm4_expand` derives the 32 round keys using FK, CK, the
byte S-box and the key-schedule linear map. `sm4_block` computes each new state
word, shifts the rolling state and reverses the final four words for output.
Decryption runs the same round function with the round keys in reverse order.

For zero-based round index i:

```text
B = tau(X[i+1] XOR X[i+2] XOR X[i+3] XOR rk[i])
X[i+4] = X[i] XOR B XOR ROL(B,2) XOR ROL(B,10) XOR ROL(B,18) XOR ROL(B,24)
Output = X[35] || X[34] || X[33] || X[32]
Key expansion uses L'(B) = B XOR ROL(B,13) XOR ROL(B,23).
```

The algorithm description and example vectors are available in the
[archived SM4 Internet-Draft](https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10).
It is an expired draft, not an IETF standard. Independent local tests also use
[OpenSSL's SM4 implementation](https://docs.openssl.org/3.0/man7/EVP_CIPHER-SM4/).

## Snapshots and fault semantics

There are 34 snapshots, each containing 16 bytes:

| Index | Meaning |
| --- | --- |
| 0 | Unmodified block input, before round 1. |
| 1–32 | Rolling four-word state immediately after the corresponding round. |
| 33 | Final word reversal, equal to the block output. |

There is no AES-style SubBytes/ShiftRows/MixColumns stage sequence. The GUI shows
SM4 words and uses byte highlights when clean and faulty states differ.

The fault descriptor is `[round, word, byte, mask]`. Round is 1–32, word/byte 0–3,
and mask 1–255. Immediately before the chosen round, the firmware applies:

```text
state[word] ^= mask << (24 - 8 * byte)
```

The event reports the selected byte before and after the XOR. Snapshots before
that round remain clean. The hook is local to one call; subsequent normal
operations have no armed fault. A multi-block request injects into only the
selected one-based message block. The host verifies the entire faulty trajectory,
reports output Hamming distance and compares inverse decryption with the oracle.
This is deterministic software FI, without faulting the key schedule or physically
disturbing voltage/clock. It does not implement an SM4 key-recovery attack.

## SimpleSerial protocol

All requests use SimpleSerial V1.1 hex framing. Replies use `r`, followed by the
normal `z` acknowledgement. The host reads and validates both separately.

| Command | Request bytes | Response bytes | Meaning |
| --- | ---: | ---: | --- |
| `i` | 0 | 4 | Identity `53 4d 34 01` (`SM4`, revision 1). |
| `k` | 16 | ACK only | Expand and set the key; invalidate snapshots. |
| `p` | 16 | 16 | Normal encryption, no snapshots. |
| `d` | 16 | 16 | Normal decryption, no snapshots. |
| `t` | 16 | 16 | Encrypt and retain snapshots. |
| `u` | 16 | 16 | Decrypt and retain snapshots. |
| `f` | 20 | 18 | Four fault bytes + plaintext; ciphertext + before/after byte. |
| `s` | 1 | 19 | Snapshot index; reply is index, round, stage and 16-byte state. |

Stage IDs: 0=input, 1=round, 2=output reversal. Status codes: 0=success,
1=invalid length, 2=key not set, 3=no trace, 4=invalid snapshot index,
5=invalid fault descriptor. Length/framing rejection may also occur inside the
SimpleSerial parser before a callback. Each block operation invalidates the old
trace; the host downloads snapshots before issuing another block command.

## Host and GUI behavior

`Device.connect` disables physical glitch outputs, sets the clock and UART,
checks the firmware identity and runs encrypt/decrypt known-answer tests.
`Device.block` validates output, event and every downloaded snapshot.
`execute` handles UTF-8 padding or raw hex blocks, optional software FI, inverse
operation verification and structured reports. Nonfaulted blocks must round-trip
exactly. A faulty block is expected to recover a different input.

The HTTP API offers `GET /api/status` and `POST /api/connect`, `/api/disconnect`,
`/api/run`, `/api/key`. The server also serves `GET /app.js`. JSON requests are size-limited; operations use the same verified
workflow as the terminal. No hardware simulation is exposed by the GUI. The
server binds to `127.0.0.1`, rejects foreign browser origins and serializes USB
operations. Run a single GUI process per capture device.

Text always uses PKCS#7 padding; hex uses none. Removing padding is explicit on
decryption. The interface limits a message to 4096 bytes. This independent-block
teaching format does not provide authentication or hide repeated blocks.

## Measurement and build

TIO4 is high during `sm4_block`; setup, key expansion and UART traffic are outside
that interval. Traced execution includes snapshot writes and differs in timing
from the baseline `p` command. The C routine still contains conditional hook checks
on its normal path; it is not an optimized constant-time production cipher.

The build records its inputs and upstream revision. The linked image used
5916 bytes ROM and 2368 bytes RAM in the initial build; consult the current
`build.log` after rebuilding. The upstream STM32 linker script produces an RWX
LOAD-segment linker warning; this experiment does not change that shared script.
The generated `.elf`, `.map`, `.lss` and log remain local and ignored by Git.

## Validation record

Offline validation on 2026-09-29:

- ARM GCC successfully built the CWLITEARM HEX from the existing minimal HAL subset.
- The standard encrypt/decrypt vector and first/last round keys matched.
- 24 deterministic random key/block pairs matched OpenSSL SM4-ECB and Python;
  native C encryption and decryption snapshots matched the Python oracle.
- 144 fault configurations covered every round, every word, all byte positions
  and nonzero masks, checking output, event and every snapshot between C/Python.
- A native-C-backed serial test adapter exercised multi-block UTF-8 encryption,
  decryption, selected-block FI and rejection of corrupted responses.
- Input tests covered padding boundaries, Unicode, bad hex and invalid faults.
- HTTP tests exercised page/status serving, disconnected-target errors and
  rejection of a foreign browser origin.

These tests do not emulate USB, the SimpleSerial C parser, MCU peripheral timing,
or the analog capture chain. Flashing and real-board UART/capture validation must
be completed on the actual device. Browser rendering also requires a manual check.
After flashing, `verify` checks both directions directly on the STM32. For the
presentation, demonstrate the standard vector, its decryption, then a late-round
software fault and the changed trajectory; describe physical glitching as a
separate subsequent experiment.

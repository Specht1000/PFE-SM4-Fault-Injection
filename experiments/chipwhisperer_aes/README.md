# AES-128 firmware and host tools for ChipWhisperer-Lite / STM32F303

The compiled target firmware is `build/pfe-aes-CWLITEARM.hex`.
Copy and run the PowerShell commands in **commands.txt** one at a time.
All source code, comments, output, and documentation are in English.

## What runs where

- STM32F303 target: `firmware/main.c`, linked to the official ChipWhisperer HAL,
  SimpleSerial V1.1, and TinyAES-128-C backend.
- Computer: `aes_capture.py` connects through the ChipWhisperer Python API,
  programs the target, checks AES results, and records baseline power traces.
- Capture board: retains its own USB/control firmware. The `flash` command
  programs the STM32 target application through its UART bootloader.

The platform supports AES encryption/decryption, educational state inspection,
and baseline captures for future fault experiments. Command `p` performs normal
AES encryption; command `t` records intermediate states; command `f` injects
one software state fault on the STM32. No physical glitch campaign is included.
Both voltage glitch outputs are disabled and the clock
output is configured without glitches. See [TERMINAL.md](TERMINAL.md) for the
interactive program and decryption verification.

## First use

The project uses an isolated environment at `experiments/chipwhisperer_aes/.venv`.
Install dependencies there as shown in `commands.txt`; no Jupyter or CubeIDE GUI
is needed to flash the supplied HEX file. This environment is separate from the
workspace's existing `.venv` because ChipWhisperer 6.0 requires NumPy below 2.

1. Connect the Lite through a USB data cable.
2. Check the connections for your target configuration using the NewAE docs.
   A separated target needs the 20-pin cable. Power measurement uses the MEASURE
   input and the target measurement connection; it does not use the GLITCH output.
3. Run `aes_capture.py connect` using the isolated environment's Python.
4. Run `aes_capture.py flash`. It programs the target and checks the firmware
   identity and AES known-answer result automatically.
5. Run `aes_capture.py capture --traces 10` to record verified baseline traces.

The CLI uses the standard Lite setup (nominal target clock 7.3728 MHz), 38400-baud
UART, and the TIO4 trigger. Changing the firmware clock requires revisiting UART
and capture settings. Specify `--serial-number` when several capture devices are connected.

## Firmware protocol

| Command | Payload | Response |
| --- | --- | --- |
| `i` | Empty | `r` with four bytes: `41 45 53 03` (AES, application revision 3) |
| `k` | 16 key bytes | Successful acknowledgement after key expansion |
| `p` | 16 plaintext bytes | `r` with 16 ciphertext bytes, then acknowledgement |
| `t` | 16 plaintext bytes | Encrypt, record 41 states in RAM, return 16 ciphertext bytes |
| `s` | One snapshot index, 0–40 | `r` with 19 bytes: index, round, operation ID, state |
| `d` | 16 ciphertext bytes | `r` with 16 recovered plaintext bytes |
| `f` | 5 fault parameters + 16 plaintext bytes | `r` with 16 faulty ciphertext bytes + affected byte before/after XOR |

The SimpleSerial library encodes data as hexadecimal ASCII on UART. The Python
API accepts raw bytes and handles encoding. SimpleSerial V1.1 acknowledgements
use `z`: status 0 is success, 1 is a callback length error, and 2 means no key has
been loaded. Status 3 means no saved trace; status 4 means an invalid snapshot
index. Status 5 means an invalid fault model. The parser can discard malformed
frames without an acknowledgement.

The fault parameters are round (1–10), operation ID (1–4), row (0–3), column
(0–3), and nonzero XOR mask (1–255). Round 10/MixColumns is rejected. Command
`f` applies a single alteration immediately before the selected operation and
saves the same 41 snapshots as `t`. It never arms a persistent fault. See the
software FI section in [TERMINAL.md](TERMINAL.md).

After reset, a key must be loaded before encryption/decryption. The trigger
brackets AES processing, with key expansion and UART traffic outside the marked
region. Each request processes one raw AES block without padding or an IV.

Known-answer vector:

```text
Key:        000102030405060708090a0b0c0d0e0f
Plaintext:  00112233445566778899aabbccddeeff
Ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
```

The key is public laboratory data. This unprotected educational implementation
is intended for measurement and fault research.

## Capture files

Each campaign creates a timestamped directory in `results/`:

- `metadata.json`: actual clock settings, software version, public key,
  generation seed, requested/completed trace count, and completion or error status.
- `trace_00000.npz`, etc.: arrays named `wave`, `plaintext`, `ciphertext`, and `key`.

The first capture uses the known-answer input; later inputs come from a
reproducible seeded generator. Every ciphertext is checked against PyCryptodome.
Each valid capture is saved immediately. On a failure, earlier traces remain
available and metadata records the failed campaign.

ADC values are normalized measurements, not watts. The capture window starts
at the trigger and may cover only part of the encryption. A valid ciphertext
does not establish trace quality, complete time coverage, or absence of clipping.

Read a saved trace:

```python
import numpy as np

with np.load("path/to/trace_00000.npz") as trace:
    samples = trace["wave"]
    print(samples.shape)
    print(bytes(trace["ciphertext"]).hex())
```

## Rebuilding

`build.py` stages the application in the included upstream subset's
`firmware/mcu/pfe-aes` directory and invokes the provided Makefile. It detects
`chipwhisperer/` or `third_party/chipwhisperer/` under the workspace, or accepts
`--cw-root`. It requires GNU make, `arm-none-eabi-gcc`, and Unix build utilities.
On this computer, the installed ARM compiler from CubeIDE and Git for Windows
utilities were sufficient. The build script records the compiler, upstream Git
revision, and artifact SHA-256 hashes in `build/build_info.json`.

The required firmware subset is included in this project, so a fresh clone can
build without downloading the full ChipWhisperer repository. Its provenance is
recorded in `chipwhisperer/UPSTREAM.json`. The root `.gitignore` tracks only the
dependencies for this target and backend.

To use a separate full upstream checkout for a different experiment:

```powershell
git clone --depth 1 --filter=blob:none --sparse https://github.com/newaetech/chipwhisperer.git third_party/chipwhisperer
git -C third_party/chipwhisperer sparse-checkout set firmware/mcu software/chipwhisperer
python experiments/chipwhisperer_aes/build.py --cw-root third_party/chipwhisperer
```

For the exact dependency revision used for the supplied binary, consult
`build/build_info.json`. A fresh clone can point to a newer revision.

## Validation and limitations

The ARM firmware has been compiled successfully. The tests exercise the host
protocol (including errors/timeouts) and compile the actual firmware callbacks
and AES backend for the host CPU. Native tests cover encryption/decryption,
known-answer vectors, and 32 random key/block pairs compared with PyCryptodome.
All 41 intermediate states are checked against an independent Python reference.
Host tests also cover multi-block text, padding, and response validation.
GPIO and UART are stubbed
in these tests. Native firmware tests require a host `gcc` compiler.

Physical programming, UART operation, trigger timing, and measured traces still
require validation on the connected STM32F303. A software test is not evidence
of a successful hardware experiment.

## Sources and licenses

`firmware/main.c` is provided under GPL-3.0-or-later to match the linked
ChipWhisperer firmware components. Upstream sources and their license notices
remain in the ChipWhisperer checkout; see its file-specific licenses, including
the TinyAES backend. The application uses upstream APIs and does not include
a separate handwritten AES implementation.

- Target build/programming: https://chipwhisperer.readthedocs.io/en/latest/Targets/CW303%20Arm.html
- Capture hardware: https://chipwhisperer.readthedocs.io/en/latest/Capture/ChipWhisperer-Lite.html
- Windows USB drivers: https://chipwhisperer.readthedocs.io/en/latest/drivers.html
- Official source: https://github.com/newaetech/chipwhisperer
- AES specification: https://csrc.nist.gov/pubs/fips/197/final

# SM4 on CW1173 Lite ARM / STM32F303

Portable C SM4 firmware for the 32-bit target, plus a Python USB/SimpleSerial
client. The target platform is **CWLITEARM**, the STM32F3 configuration in NewAE's
HAL. This is for the ARM version of the Lite, not its XMEGA version.

The SM4 firmware is programmed into the **STM32F303 target**. It does not replace
the capture controller's firmware. CubeIDE is not required to program it: the
client uses the ChipWhisperer STM32 serial-bootloader programmer. The Arm GNU
compiler bundled with CubeIDE can still be used for compilation.

## Build and program

Run commands from the repository root. Full commands are in [commands.txt](commands.txt).
Install the ChipWhisperer Python package and the appropriate USB driver for
your CW-Lite. Use the official [Windows installation instructions](https://chipwhisperer.readthedocs.io/en/latest/windows-install.html)
if the capture device is not recognized. Compilation needs GNU Arm Embedded
tools, GNU make and sh; Git for Windows supplies the shell used by the builder.

~~~powershell
python -m pip install -r chipwhisperer/sm4/requirements.txt
git clone --depth 1 --filter=blob:none --sparse https://github.com/newaetech/chipwhisperer.git .build/chipwhisperer-sdk
git -C .build/chipwhisperer-sdk sparse-checkout set firmware/mcu
python chipwhisperer/sm4/build.py
python chipwhisperer/sm4/client.py --program chipwhisperer/sm4/build/pfe-sm4-CWLITEARM.hex
~~~

Skip the download if the checkout already exists. Alternatively pass an existing
official repository root to the builder with --sdk. The builder copies only
this project's files into firmware/mcu/pfe-sm4, builds with NewAE's HAL, then
copies the HEX, ELF, BIN, MAP and listing files into this project's build folder.
The SDK and build artifacts are ignored by Git. The original upstream sources
are not vendored into this project.

The default client operation loads the key, encrypts the block, compares it with
the Python SM4 implementation, and asks the target to decrypt the result.
Once programmed, subsequent runs need only:

~~~powershell
python chipwhisperer/sm4/client.py
~~~

The official test input is key = plaintext = 0123456789ABCDEFFEDCBA9876543210.
Expected ciphertext: **681EDF34D206965E86B3E94F536E4246**.

To decrypt another block:

~~~powershell
python chipwhisperer/sm4/client.py --operation decrypt --input 681EDF34D206965E86B3E94F536E4246
~~~

Use --key and --input to supply exactly sixteen bytes in hexadecimal. These
are raw blocks, with no padding, chaining mode or authentication.

## Trigger for measurements

Key expansion and UART response transmission are outside the trigger window.
By default the trigger covers the block-processing operation. For a selected
round, it rises before that round's nonlinear-input calculation and falls after
the rolling-state update. The hook marks a round window; it does not guarantee
an exact instruction or byte will be faulted.

~~~powershell
python chipwhisperer/sm4/client.py --trigger-round 31 --capture --samples 5000
~~~

This saves one power trace to logs/chipwhisperer_sm4_trace.json. Samples are
limited to the CW-Lite buffer size, 24400. Capture starts at the trigger edge;
a short capture may cover only part of the marked operation. The 32 rounds use
zero-based processing indices; during decryption index zero uses rk31.

The normal client disables voltage-glitch outputs. No synthetic XOR fault or
physical glitch is applied by this firmware/client. This establishes a clean
reference target for subsequent side-channel/FI work. It is an intentionally
readable, table-based implementation, not a hardened cryptographic library.

## Files

| File | Purpose |
| --- | --- |
| firmware/sm4.c, sm4.h | Portable cipher, key schedule and optional round hook |
| firmware/main.c | Target initialization, serial commands and trigger control |
| firmware/Makefile | CWLITEARM, SimpleSerial 1.1, no external crypto library, -O0 |
| build.py | Stage sources in the SDK and produce flashable firmware |
| client.py | Program, encrypt, decrypt, verify and optionally capture power |
| requirements.txt | Python host dependency |
| commands.txt | Copyable commands from the repository root |

Clock: 7.3728 MHz from the scope; serial protocol: **SimpleSerial 1.1 at 38400 baud**.
The client uses cw.targets.SimpleSerial, not SimpleSerial2. Commands are:

| Command | Payload | Response |
| --- | --- | --- |
| i | Empty | r + 4 bytes: SM4 followed by protocol version 01 |
| k | 16-byte key | ACK |
| p | 16-byte plaintext | r + 16-byte ciphertext, then ACK |
| d | 16-byte ciphertext | r + 16-byte plaintext, then ACK |
| t | One byte: 00..1F or FF for the full cipher | ACK |

ACK status 00 means success; 01 means a key must be loaded; 02 means invalid
parameters. Normal target reset clears the key and restores the full trigger.
SimpleSerial additionally supplies its own protocol commands.

Each host run replaces logs/chipwhisperer_sm4.txt and its colored HTML counterpart.
The key is not printed in these logs. Imports and --help do not connect to USB.

## Validation and references

~~~powershell
python tools/test_chipwhisperer_sm4.py
~~~

The local checks compile the same SM4 C core with native GCC, compare the official
vector and 100 random encrypt/decrypt cases against src/sm4.py, check round-hook
ordering, and exercise serial response/ACK handling with a mock target.

The complete Cortex-M4 firmware was also built with Arm GCC 13.3.1 and upstream
SDK commit 884412281b1c1749b871e16e563d3ff310affd68. USB programming, trigger timing
and power capture still require validation on the physical board.

- [NewAE custom firmware guide](https://chipwhisperer.readthedocs.io/en/latest/custom-firmware.html)
- [CW1173 Lite hardware](https://chipwhisperer.readthedocs.io/en/latest/Capture/ChipWhisperer-Lite.html)
- [CW303 ARM target](https://chipwhisperer.readthedocs.io/en/latest/Targets/CW303%20Arm.html)
- [SimpleSerial protocol](https://chipwhisperer.readthedocs.io/en/latest/simpleserial.html)
- [Target Python API](https://chipwhisperer.readthedocs.io/en/latest/target-api.html)
- [SM4 definition, including test vector](https://datatracker.ietf.org/doc/html/draft-crypto-sm4-00)

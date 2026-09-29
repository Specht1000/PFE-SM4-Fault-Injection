# SM4 on ChipWhisperer-Lite / STM32F303

This experiment provides an SM4 target application and PC tools for encryption,
decryption, round-state inspection, deterministic software fault injection and
baseline power acquisition. The GUI and terminal use the **real STM32 target**;
the Python implementation checks its responses and does not replace the target.

All runnable PowerShell commands are in [commands.txt](commands.txt).
The implementation report and file inventory are in [FILES.md](FILES.md).

## First use

From the repository root, create the environment and install dependencies:

```powershell
python -m venv experiments/chipwhisperer_sm4/.venv
experiments/chipwhisperer_sm4/.venv/Scripts/python.exe -m pip install -r experiments/chipwhisperer_sm4/requirements.txt
```

Attach the STM32F303 target to ChipWhisperer-Lite and connect USB. Close any AES
GUI, notebook or terminal holding the capture device. Program the supplied HEX:

```powershell
experiments/chipwhisperer_sm4/.venv/Scripts/python.exe experiments/chipwhisperer_sm4/sm4_capture.py flash
```

The application is written into **STM32 target flash**, not the capture FPGA.
This replaces the target's AES application. Flashing also runs the encryption and
decryption known-answer tests. The existing AES flash command restores AES later.
STM32CubeIDE is not required for programming through ChipWhisperer.

If changing C sources, run `python experiments/chipwhisperer_sm4/build.py` first.
The build requires ARM GCC, GNU make and `sh`/`rm` (Git for Windows supplies these).
The script reuses the repository's minimal ChipWhisperer HAL subset and stages
only this application under the ignored `chipwhisperer/firmware/mcu/pfe-sm4` directory.

## GUI

```powershell
experiments/chipwhisperer_sm4/.venv/Scripts/python.exe experiments/chipwhisperer_sm4/gui_server.py
```

Open **http://127.0.0.1:8766**. The interface uses the same layout, colors,
connection bar, cards, tabs and matrix steppers as the AES console. Click **Connect**, then:

1. In **Encrypt & Trace**, click **use known-answer vector**, then **Encrypt on target**.
   The ciphertext must be `681edf34d206965e86b3e94f536e4246`.
2. Use **prev / next** to inspect input, the 32 rounds and output reversal.
   Each matrix row is an SM4 word, with the most significant byte on the left.
3. Click **Use ciphertext in Decrypt**, then **Decrypt on target**. The recovered
   plaintext must be `0123456789abcdeffedcba9876543210`.
4. In **Fault Injection**, keep the default hex input, round 31, word 1, byte 0,
   mask `0x01` and block 1. Click **Compare clean vs. faulty**. Compare ciphertexts,
   the injected byte, Hamming distance and side-by-side round states.
5. Use **Download result JSON** to save results. **Set key on target** applies an
   edited key immediately; each operation also applies the current key field.

Orange cells show changes between consecutive normal snapshots. Red cells in
the fault comparison show differences from the clean state at the same round.

Hex input contains complete 16-byte blocks with no padding. UTF-8 text receives
PKCS#7 padding, including an extra padding block when needed. For text ciphertext,
select **Remove PKCS#7 padding after decryption** to recover the original text.
Leave this unchecked for the standard vector. Multi-block messages use independent
blocks (ECB) for this teaching experiment, not a secure application message format.

The fault is injected once, into one selected block, before one selected round.
Word and byte indices are zero-based; byte 0 is the most significant byte. This
changes the actual firmware state but is **software FI**, not a voltage/clock
glitch. A faulty ciphertext decrypts to a different plaintext; the tool verifies
that this decryption still agrees with the SM4 reference.

## Terminal and capture

Run `sm4_terminal.py` with the experiment's Python interpreter. Enter `text:Hello`,
`hex:0123456789abcdeffedcba9876543210`, or `decrypt:<ciphertext hex>`.
Use `decrypt-text:<ciphertext hex>` to remove text padding. `/fault 31 1 0 0x01`
sets the software fault, and `fault:<plaintext hex>` executes it. `/quit` exits.
Every operation prints a JSON report, including intermediate target states.
One-shot options and capture commands are listed in [commands.txt](commands.txt).

`sm4_capture.py capture` records baseline ADC samples using command `p`, without
snapshot writes or injected faults. TIO4 brackets the block operation; key
expansion and serial transfers are outside that interval. Results are `.npz`
files plus metadata. The acquisition window may cover only part of SM4; inspect
the trigger duration before interpreting a trace as a complete encryption.

## Validation and limitations

The supplied firmware was cross-compiled for CWLITEARM. Offline tests compare the
exact C cipher with Python, published vectors and OpenSSL, and exercise host
workflows and HTTP error handling. See [FILES.md](FILES.md) for the validation
record. Physical flashing, UART timing, USB drivers and captured waveforms still
require testing with the connected board. Run `sm4_capture.py verify` after flashing.

The firmware uses a table S-box and exposes internal states intentionally for the
PFE. It is an experimental implementation, without side-channel countermeasures,
authenticated encryption, or physical glitch scanning/key recovery.

If connection fails, close other USB clients, check ChipWhisperer drivers and the
target connection, then retry. An unexpected firmware identity means the SM4 HEX
needs flashing. After a serial timeout, disconnect and reconnect before retrying.
Use `--serial-number` on CLI tools, or the GUI serial field, when multiple capture
devices are connected.

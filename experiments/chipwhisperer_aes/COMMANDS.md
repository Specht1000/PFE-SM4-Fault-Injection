# PowerShell commands — ChipWhisperer-Lite with STM32F303 target

Run commands one at a time. Stop if a command reports an error.
All paths below assume this workspace location:

```powershell
Set-Location 'C:\Projetos\PFE 5A'
```

## 1. Create an isolated Python environment

Only needed once. Skip this command if `experiments/chipwhisperer_aes/.venv` already exists.

```powershell
python -m venv experiments/chipwhisperer_aes/.venv
```

## 2. Install the host dependencies

Only needed once.

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe -m pip install -r experiments/chipwhisperer_aes/requirements.txt
```

## 3. Test the connection

Connect the ChipWhisperer-Lite USB cable. For a separated target, connect the
20-pin cable as documented by NewAE. For power capture, check the
target-to-MEASURE SMA connection for your board.

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_capture.py connect
```

## 4. Program the STM32F303

Programs the supplied, already compiled AES firmware. This replaces the TARGET
application, not the capture-board firmware. A firmware identity check and AES
known-answer test run immediately afterward.

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_capture.py flash
```

## 5. Verify an already programmed target

Does not program the target again.

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_capture.py verify
```

## 6. Capture baseline power traces

Ten traces, with no glitches.

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_capture.py capture --traces 10 --samples 24000
```

Expected AES test output:

```text
AES-128 known-answer test: PASS (69c4e0d86a7b0430d8cdb78070b4c55a)
Captures: experiments/chipwhisperer_aes/results/<UTC timestamp>/
```

Do not claim hardware validation until this test passes on your connected board.

## 7. Interactive graphical console (browser GUI)

A local web page for encryption, decryption, and fault injection, with the
AES state shown as a 4x4 matrix you can step through round by round. It opens
automatically in your default browser. Reflash using step 4 first: fault
injection requires the revision 3 firmware.

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/gui_server.py
```

Click **Connect**, then use the **Encrypt & Trace**, **Decrypt**, and
**Fault Injection** tabs. Press Ctrl+C in the terminal to stop the server.
Keep only one browser tab open: the server holds a single hardware connection.

## 8. Interactive encryption terminal (text console)

States are recorded on the STM32. Reflash using step 4 first: software FI
requires the revision 3 firmware.

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_terminal.py
```

Every encryption is followed by decryption on the STM32 and a round-trip check.
At the prompt, enter:

| Input | Action |
| --- | --- |
| `Hello STM32!` | Encrypt text (UTF-8 + PKCS#7) |
| `hex:00112233445566778899aabbccddeeff` | Encrypt raw blocks |
| `decrypt:69c4e0d86a7b0430d8cdb78070b4c55a` | Decrypt raw blocks |
| `decrypt-text:<ciphertext hex>` | Decrypt text and remove padding |
| `/quit` | Exit |

Single AES block with all intermediate states and 4x4 matrices:

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_terminal.py --hex 00112233445566778899aabbccddeeff --matrix
```

Text message, automatically padded and split into independent AES blocks:

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_terminal.py --text 'Hello STM32!'
```

Pause while displaying each recorded state:

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_terminal.py --text 'Hello STM32!' --step
```

Normal encryption path: input and ciphertext only, no state snapshots:

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_terminal.py --no-trace
```

Decrypt a raw AES block on the STM32 (expected plaintext: `001122...eeff`):

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_terminal.py --decrypt 69c4e0d86a7b0430d8cdb78070b4c55a
```

For ciphertext produced from text, use `--decrypt <hex> --unpad`.

## 9. Software fault injection

Compares correct AES with a software fault injected inside the STM32.
Default: first block, round 9, BEFORE MixColumns, row 0, column 0, XOR `0x01`.
This modifies an internal byte in firmware; no physical glitch is generated.

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_terminal.py --hex 00112233445566778899aabbccddeeff --fault
```

Customize the single transient state fault (indices: row/column 0–3, block 1-based):

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_terminal.py --text 'Hello STM32!' --fault --fault-round 9 --fault-stage MixColumns --fault-row 2 --fault-column 1 --fault-mask 0x55 --matrix
```

In the interactive AES terminal, use these commands (not PowerShell commands):

```text
/fault on
hex:00112233445566778899aabbccddeeff
/fault 9 MixColumns 0 0 0x01
/fault off
Hello STM32!
```

With FI enabled, each encryption message gets one fault in the selected block.
Decryption requests never receive a fault; `/fault off` restores normal encryption.

## Optional

### Rebuild after modifying the firmware

Edit the sources in `experiments/chipwhisperer_aes/firmware/`. The official
sources are already present in `chipwhisperer/`; `build.py` also detects
`third_party/chipwhisperer` if that layout is used. Requires `arm-none-eabi-gcc`,
GNU make, and `sh`/`rm` (Git for Windows supplies these).

```powershell
python experiments/chipwhisperer_aes/build.py
```

### Program a different build of this firmware

Replace the path before running:

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe experiments/chipwhisperer_aes/aes_capture.py flash --firmware 'C:\path\to\pfe-aes-CWLITEARM.hex'
```

### Run software tests without a connected board

```powershell
.\experiments\chipwhisperer_aes\.venv\Scripts\python.exe -m unittest discover -s experiments/chipwhisperer_aes/tests -v
```

## References

- USB troubleshooting: https://chipwhisperer.readthedocs.io/en/latest/windows-install.html
- Windows drivers: https://chipwhisperer.readthedocs.io/en/latest/drivers.html
- Target wiring and programming: https://chipwhisperer.readthedocs.io/en/latest/Targets/CW303%20Arm.html

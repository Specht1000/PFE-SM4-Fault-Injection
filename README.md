# AES & SM4 — Differential Fault Analysis Lab

Educational implementations of **AES-128**, **SM4**, and differential fault
analysis (DFA), with step-by-step terminal demonstrations and an interactive
Python GUI.

Developed as part of a **PFE 5A — final-year engineering project at Polytech
Montpellier**, in collaboration with **STMicroelectronics**, studying fault
injection and embedded cryptographic implementations, with a focus on SM4.

## Author and academic context

| | Information |
| --- | --- |
| **Author** | Guilherme Martins Specht |
| **GitHub** | [@Specht1000](https://github.com/Specht1000) |
| **Institution** | Polytech Montpellier, France |
| **Academic project** | PFE 5A — final-year engineering project |
| **Academic supervisor** | Prof. Philippe Maurine |
| **Industrial collaboration** | STMicroelectronics |
| **Research topics** | Fault injection, differential fault analysis, AES and SM4 |

## What this project demonstrates

- **AES-128:** key expansion, SubBytes, ShiftRows, MixColumns and AddRoundKey,
  including intermediate states and inverse transformations.
- **AES Piret-style DFA:** compare correct and faulty ciphertexts, construct
  final-round key candidates, intersect observations, recover K10 and reverse
  key expansion to reconstruct the master key.
- **SM4:** key expansion, 32 rounds, S-box substitution, linear diffusion,
  rolling-state updates, final word reversal and decryption.
- **SM4 DFA:** recover the final-round subkey under the controlled known-XOR
  fault model described in the project notes.
- **Interactive learning:** choose an algorithm and operation, move through
  individual steps, animate execution, inspect differences and export JSON reports.

Fault-modified bytes and nonzero XOR differences are highlighted in **red**.
The code, comments and interface are written in English.

## Run

Requires **Python 3.9 or newer**. The GUI also requires **Tkinter**, normally
included with the standard Python installer on Windows. The demonstrations use
the Python standard library; no board connection or external Python packages
are required.

Run these commands from the repository root.

**Terminal — AES + Piret, followed by SM4 + DFA:**

```powershell
python src/run.py
```

**GUI — select AES or SM4, then Encrypt, Decrypt or Fault analysis:**

```powershell
python src/gui.py
```

The terminal supports optional step-by-step pauses with `--step`. In the GUI,
use **Load standard example**, then **Build lesson**. Navigate with Previous/Next,
the slider, the step selector or automatic playback.

## Fault models and recovery scope

### AES

The combined terminal and GUI demonstrations follow the project PDF's model:
a single-byte fault before **MixColumns in round 9**. Independent observations
constrain one four-byte group of K10 at a time. Processing all four columns
allows reconstruction of K10 and reversal of the AES-128 key schedule.

The standalone `piret.py` terminal lesson also provides a **round-8 fault model**,
which propagates to all four groups. The recovery function uses ciphertext
observations; the simulation key is used by the target and for final verification.
Recovery stops only when the candidate groups are unique.

### SM4

The demonstration assumes a **known XOR fault in one S-box input byte in the last
round**, indexed 31. Output differences are mapped back through the inverse
linear layer, then S-box constraints identify candidates for **rk31**.

Recovering rk31 alone does **not** recover the SM4 master key. The subsequent
key-schedule reversal exercise uses recovered rk31 together with **reference
rk28, rk29 and rk30**, explicitly identified in the output. This distinction is
preserved in the GUI and exported reports.

These are **software fault simulations**. They support understanding and checking
the fault models; they do not establish that physical clock or voltage glitches
produce the same controlled errors. The educational implementations expose
internal states and are not intended for production cryptographic use.

## Repository structure

```text
src/
  aes.py                   Didactic AES-128 implementation
  sm4.py                   SM4 implementation and configurable example inputs
  piret.py                 AES DFA helpers and terminal key-recovery lesson
  run.py                   Combined terminal demonstrations matching the notes
  gui.py                   Interactive AES / SM4 / DFA interface
docs/
  AES_SM4_DFA.pdf           Encryption, fault models and recovery explanations
  AES_SM4_Scratch.pdf       Supporting project notes
  Piret_AES.pdf             Supporting AES DFA document
  ONE_COMMAND_DFA.md        Terminal and GUI launch commands
tests/
  test_combined_demo.py     PDF values, fault models and terminal highlighting
  test_crypto_lab.py        Cipher checks, GUI lessons and optional Tk tests
  test_piret_terminal.py    AES key recovery and terminal behavior
```

Configure the terminal examples through `KEY` and `PLAINTEXT` in `src/aes.py`
and `src/sm4.py`. Each value represents exactly 16 bytes in hexadecimal.
The GUI accepts its own key and input fields. Operations use raw single blocks,
without message padding or an authenticated encryption format.

## Validation

Tests cover known-answer vectors, independent OpenSSL comparisons when OpenSSL
is available, encryption/decryption consistency, fault propagation, candidate
intersections, key-schedule reversal, ambiguous observations, terminal colors
and GUI workflows. GUI integration checks use a hidden Tk window.

The default public vectors include:

| Cipher | Plaintext | Key | Ciphertext |
| --- | --- | --- | --- |
| AES-128 | `00112233445566778899AABBCCDDEEFF` | `000102030405060708090A0B0C0D0E0F` | `69C4E0D86A7B0430D8CDB78070B4C55A` |
| SM4 | `0123456789ABCDEFFEDCBA9876543210` | `0123456789ABCDEFFEDCBA9876543210` | `681EDF34D206965E86B3E94F536E4246` |

## Reading

- [Project explanation: AES and SM4 DFA](docs/AES_SM4_DFA.pdf)
- [Supporting handwritten notes](docs/AES_SM4_Scratch.pdf)
- [Supporting AES DFA document](docs/Piret_AES.pdf)
- [NIST FIPS 197 — Advanced Encryption Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [Piret and Quisquater, CHES 2003 — institutional publication record](https://research.dial.uclouvain.be/entities/publication/f15e3e1b-78b1-4749-925d-fdc1d60c1694)

This repository documents an academic learning and research project. References
to Polytech Montpellier and STMicroelectronics describe its academic and
industrial context.

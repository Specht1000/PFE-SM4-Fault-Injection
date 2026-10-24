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
- **AES Giraud attack:** inject a single bit before final SubBytes, test inverse
  S-box differences for Hamming weight one, recover all sixteen K10 bytes and
  reverse the AES-128 key schedule.
- **SM4:** key expansion, 32 rounds, S-box substitution, linear diffusion,
  rolling-state updates, final word reversal and decryption.
- **SM4 DFA:** recover rk31, rk30, rk29 and rk28 from controlled fault
  observations, then reverse the schedule to recover the complete master key.
- **SM4 Giraud-inspired adaptation:** use known or unknown single-bit filtering
  and undo recovered rounds to obtain all four final subkeys and the master key.
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

Choose **Giraud attack** in the GUI's Lesson selector for either algorithm.
The bit position is unknown to the solver by default. Enable **Giraud: exact bit
known to solver** for the stronger controlled-mask model. Use one of the masks
`01`, `02`, `04`, `08`, `10`, `20`, `40`, `80` and 1–8 distinct observations per byte.
The row/column fields select the first AES input byte; all sixteen bytes are
processed. For SM4, row selects the first S-box byte and all four are processed.

The candidate functions in `src/giraud.py` accept ciphertext observations and
do not receive a secret key. Its optional `main()` runs a simple terminal
simulation, independently of Tkinter. Visual reports and interface code stay
in `src/gui.py`. Ambiguous observations never produce a claimed recovered key.

```powershell
python src/giraud.py
```

Use `--algorithm aes` or `--algorithm sm4` to select one cipher, `--step` for
pauses, and `--known-bit` to share the exact fault mask with the solver. The
default executes both models with unknown-bit filtering. The terminal recovers
the complete AES and SM4 master keys.

The controlled-byte SM4 attack is also available directly:

```powershell
python src/piret.py --algorithm sm4
```

The terminal supports optional step-by-step pauses with `--step`. In the GUI,
use **Load standard example**, then **Build lesson**. Navigate with Previous/Next,
the slider, the step selector or automatic playback.

## Fault models and recovery scope

### Code responsibilities

- `aes.py` and `sm4.py` implement normal encryption/decryption. Their block
  functions return bytes without printing or pausing; their `main()` functions
  show only normal input/output and round-trip verification.
- `piret.py` and `giraud.py` inject faults through external observer functions
  attached to the actual cipher execution. They do not run separate copies of
  AES/SM4. Candidate solvers use ciphertext observations rather than secret keys.
- `gui.py` presents the actual execution traces, comparisons and explanations.
  `run.py` is the combined terminal entry point.
- The optional observer is a generic experiment interface. With no observer,
  the cipher follows its normal algorithm and no fault is injected.

```powershell
python src/aes.py
python src/sm4.py
python src/piret.py
python src/giraud.py
```

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

Full recovery extends the PDF's last-round model to controlled faults in each
of the final four rounds, indexed **31, 30, 29 and 28**. First recover rk31 from
ciphertext differences. Use that recovered key to undo round 31 in both outputs,
then apply the same differential equations to round 30. Repeat until rk28 is
known, and reverse the key schedule using the four **DFA-recovered** subkeys.

No reference subkeys are supplied to the solver. Its inputs are the correct
ciphertext and an oracle returning outputs for selected round/byte faults. The
controlled-byte model knows the XOR mask; the Giraud-inspired model can test all
eight bit positions without knowing which one was injected. A stage with multiple
remaining candidates stops recovery before an unknown key could be used.

This requires fault access to all four target rounds; last-round faults alone
still recover only rk31. The multi-round experiment is an extension of the PDF,
not a claim that the original last-round worked example already recovers the
master key. Re-encryption verifies the final result in the terminal and GUI.

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
  giraud.py                AES single-bit Giraud attack and SM4 adaptation
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

Full SM4 recovery tests use random keys and a precomputed ciphertext-only oracle.
They block access to `sm4.key_expansion` while the solver runs, verifying that
recovery succeeds without reading a reference schedule. The MATLAB campaign
retains its explicitly labeled single-round rk31 target for statistical analysis.

The default public vectors include:

| Cipher | Plaintext | Key | Ciphertext |
| --- | --- | --- | --- |
| AES-128 | `00112233445566778899AABBCCDDEEFF` | `000102030405060708090A0B0C0D0E0F` | `69C4E0D86A7B0430D8CDB78070B4C55A` |
| SM4 | `0123456789ABCDEFFEDCBA9876543210` | `0123456789ABCDEFFEDCBA9876543210` | `681EDF34D206965E86B3E94F536E4246` |

## Reading

### MATLAB analysis

```powershell
matlab -batch "addpath('matlab'); analyze_dfa('Visible',false);"
```

```matlab
addpath('matlab'); analyze_dfa
```

The analysis generates a reproducible 32-trial dataset, checks raw XOR and Hamming
distances in MATLAB, and prepares fault-propagation plots, affected-byte heatmaps
and candidate-convergence curves. Figures are saved as PNG, PDF and MATLAB FIG
files in `matlab/results`, together with statistics, a MAT workspace and a text
interpretation. MATLAB needs an active license; no extra toolboxes are required.
The Python exporter requires only the standard library.

These are software simulations with fixed configured keys and varied plaintexts,
fault masks and locations. Dispersion is reported as one standard deviation.
AES candidate counts describe 32-bit K10 quartets; SM4 counts describe 8-bit rk31
bytes. The analysis preserves this distinction and does not rank the ciphers'
security or infer physical glitch behavior.

### Project references

- [Project explanation: AES and SM4 DFA](docs/AES_SM4_DFA.pdf)
- [Supporting handwritten notes](docs/AES_SM4_Scratch.pdf)
- [Supporting AES DFA document](docs/Piret_AES.pdf)
- [NIST FIPS 197 — Advanced Encryption Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [Piret and Quisquater, CHES 2003 — institutional publication record](https://research.dial.uclouvain.be/entities/publication/f15e3e1b-78b1-4749-925d-fdc1d60c1694)

This repository documents an academic learning and research project. References
to Polytech Montpellier and STMicroelectronics describe its academic and
industrial context.

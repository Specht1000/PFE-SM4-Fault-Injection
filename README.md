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

Every terminal execution of `aes.py`, `sm4.py`, `piret_aes.py`, `piret_sm4.py`,
`giraud_aes.py`, `giraud_sm4.py`, `gui.py` or `run.py` also saves its output in `logs/<script>.txt` and `logs/<script>.html`.
Each run replaces that program's previous logs instead of appending text or
creating timestamped files. Old timestamped logs for that program are removed
automatically. Logs from other programs are preserved. The first line prints
the complete log path. The files use UTF-8;
the text file preserves terminal ANSI colors. A matching `.html` file renders
those colors in a browser, including red fault differences and green recovery
results. A plain text editor may show ANSI codes rather than colors; open the
HTML file for the formatted version. Use `--color always` on attack commands to
retain colors even when stdout is redirected. Standard errors and unexpected
tracebacks are captured too. The
`logs/` folder is ignored by Git. Imports do not create logs. A GUI session writes every built lesson, including all
numerical steps and recovered keys, to `logs/gui.txt`; its colored HTML log is
finalized when the window closes. Multiple lessons belong to the same session;
relaunching the GUI replaces its previous session logs. The PDF builder and
analysis entry point also save their output to `logs/build_pdf.txt` and
`logs/analysis.txt`, with matching HTML files.

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

The candidate functions in `src/giraud_aes.py` and `src/giraud_sm4.py` accept
ciphertext observations and do not receive a secret key. Each module has its
own terminal entry point, independently of Tkinter. Visual reports and interface code stay
in `src/gui.py`. Ambiguous observations never produce a claimed recovered key.

```powershell
python src/giraud_aes.py
python src/giraud_sm4.py
```

The terminal explains per-pair byte guesses, candidate intersections and complete
master-key recovery for both algorithms. AES prints every reversed schedule word
and K9 through K0. SM4 shows round peeling, rk31 through rk28 recovered from
faults, rk27 through rk0 derived from the schedule, and the final FK removal.
Unknown-bit mode displays all eight permitted errors; only `--known-bit` shares
the exact simulator mask with the candidate solver. Add `--step` for pauses.

Choose the AES or SM4 script above. Use `--step` for pauses and `--known-bit`
to share the exact fault mask with the solver. Each script runs its own cipher
with unknown-bit filtering by default and recovers its complete master key.

The controlled-byte SM4 attack is also available directly:

```powershell
python src/piret_sm4.py
```

This command explains each byte candidate, restores earlier round views with
already recovered subkeys, and assembles rk31 through rk28 from DFA observations.
It then prints all inverse-schedule equations, derives rk27 through rk0, removes
the four FK constants and assembles the original master key. Earlier subkeys are
explicitly labeled as schedule-derived. Add `--step` to pause during the lesson.

The terminal supports optional step-by-step pauses with `--step`. In the GUI,
use **Load standard example**, then **Build lesson**. Navigate with Previous/Next,
the slider, the step selector or automatic playback.

## Fault models and recovery scope

### Code responsibilities

- `aes.py` and `sm4.py` implement normal encryption/decryption. Their block
  functions return bytes without printing or pausing; their `main()` functions
  show only normal input/output and round-trip verification.
- `piret_aes.py`, `piret_sm4.py`, `giraud_aes.py` and `giraud_sm4.py` inject
  faults through external observer functions
  attached to the actual cipher execution. They do not run separate copies of
  AES/SM4. Candidate solvers use ciphertext observations rather than secret keys.
- `gui.py` presents the actual execution traces, comparisons and explanations.
  `run.py` is the combined terminal entry point.
- The optional observer is a generic experiment interface. With no observer,
  the cipher follows its normal algorithm and no fault is injected.

```powershell
python src/aes.py
python src/sm4.py
python src/piret_aes.py
python src/piret_sm4.py
python src/giraud_aes.py
python src/giraud_sm4.py
```

### AES

The combined terminal and GUI demonstrations follow the project PDF's model:
a single-byte fault before **MixColumns in round 9**. Independent observations
constrain one four-byte group of K10 at a time. Processing all four columns
allows reconstruction of K10 and reversal of the AES-128 key schedule.

The standalone `piret_aes.py` terminal lesson also provides a **round-8 fault model**,
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
  piret_aes.py             AES DFA helpers and terminal key-recovery lesson
  piret_sm4.py             Controlled SM4 DFA and full master-key recovery
  giraud_aes.py            AES single-bit Giraud attack
  giraud_sm4.py            SM4 single-bit adaptation and full key recovery
  giraud_common.py         Shared mask validation and candidate intersections
  giraud_terminal.py       Shared terminal presentation for Giraud lessons
  attack_steps.py          Numerical teaching stages shared by terminal and GUI
  run.py                   Combined terminal demonstrations matching the notes
  gui.py                   Interactive AES / SM4 / DFA interface
docs/
  AES_SM4_DFA.pdf           Encryption, fault models and recovery explanations
  AES_SM4_Scratch.pdf       Supporting project notes
  Piret_AES.pdf             Supporting AES DFA document
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
recovery succeeds without reading a reference schedule.

The default public vectors include:

| Cipher | Plaintext | Key | Ciphertext |
| --- | --- | --- | --- |
| AES-128 | `00112233445566778899AABBCCDDEEFF` | `000102030405060708090A0B0C0D0E0F` | `69C4E0D86A7B0430D8CDB78070B4C55A` |
| SM4 | `0123456789ABCDEFFEDCBA9876543210` | `0123456789ABCDEFFEDCBA9876543210` | `681EDF34D206965E86B3E94F536E4246` |

## Reproducible analysis

Install plotting dependencies with `python -m pip install -r analysis/requirements.txt`,
then run `python analysis/run_analysis.py` to measure plaintext/key avalanche,
ciphertext statistics, exact S-box differential/linear/algebraic properties,
encryption/decryption time and Python allocations, and Piret/Giraud key recovery
for both ciphers. The experiment saves a Portuguese report, raw JSON observations
and avalanche CSV in [`analysis/results/`](analysis/results/), along with seven
PNG/SVG figures, a PDF and an HTML gallery. Use `python analysis/plot_results.py`
to regenerate the figures from saved measurements without repeating experiments.
See [`analysis/README.md`](analysis/README.md) for sample sizes, reproducibility
and the distinction between software measurements and physical fault injection.

## Reading

### Project references

- [Project explanation: AES and SM4 DFA](docs/AES_SM4_DFA.pdf)
- [Supporting handwritten notes](docs/AES_SM4_Scratch.pdf)
- [Supporting AES DFA document](docs/Piret_AES.pdf)
- [NIST FIPS 197 — Advanced Encryption Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [Piret and Quisquater, CHES 2003 — institutional publication record](https://research.dial.uclouvain.be/entities/publication/f15e3e1b-78b1-4749-925d-fdc1d60c1694)

This repository documents an academic learning and research project. References
to Polytech Montpellier and STMicroelectronics describe its academic and
industrial context.

# AES & SM4 — Differential Fault Analysis Lab

Educational Python implementations of AES-128 and SM4, with a current focus on
controlled round-input fault injection and complete SM4 key recovery.
Code, comments and execution logs are in English.

## Author and academic context

| | Information |
| --- | --- |
| Author | Guilherme Martins Specht |
| GitHub | [@Specht1000](https://github.com/Specht1000) |
| Institution | Polytech Montpellier, France |
| Academic project | PFE 5A — final-year engineering project |
| Academic supervisor | Prof. Philippe Maurine |
| Industrial collaboration | STMicroelectronics |
| Research topics | Fault injection, differential fault analysis, AES and SM4 |

## Run the SM4 DFA demonstration

Run from the repository root with Python 3.9 or newer:

~~~powershell
python src/piret_sm4.py
~~~

This command uses only the Python standard library. Cipher operations come
from sm4.py, independently of aes.py. No board connection is needed.

The attack:

1. Captures a correct ciphertext.
2. Injects a byte XOR fault into a round input, before XOR with the subkey.
3. Compares ciphertexts, including the changed pass-through word.
4. Applies the inverse linear transformation to the newest-word difference.
5. Tests all 256 subkey-byte candidates and intersects observations until unique.
6. Recovers rk31, rk30, rk29 and rk28, undoing later rounds with recovered keys.
7. Reverses the key schedule and removes FK to reconstruct the master key.
8. Verifies the recovered key by encryption and decryption.

The solver receives ciphertexts and fault descriptors. It does not receive
the target key or hidden round traces. The target and final verification own
the reference key. Full master-key recovery requires fault observations from
all four tail rounds; faults confined to round 31 recover its subkey alone.

### Choose the error and initial byte

Edit the constants near the start of [piret_sm4.py](src/piret_sm4.py):

~~~python
FAULT_MASK = 0x01  # First XOR error: 0x01..0xFF
FAULT_BYTE = 0     # First target byte: 0..3, big-endian order
~~~

These select the first error and byte. The attack uses additional distinct
masks to resolve ambiguity and visits all four bytes of each subkey.
An insufficient observation budget is reported as incomplete recovery.

Useful options:

~~~powershell
python src/piret_sm4.py --step
python src/piret_sm4.py --word 2 --row 1 --faults 8
python src/piret_sm4.py --key 0123456789ABCDEFFEDCBA9876543210 --plaintext 0123456789ABCDEFFEDCBA9876543210
python src/piret_sm4.py --help
~~~

| Option | Meaning |
| --- | --- |
| --step | Pause after each faulty encryption, before candidate testing |
| --word 1, 2 or 3 | Inject into X[i+1], X[i+2] or X[i+3]; default: 1 |
| --row 0..3 | Override the first byte selected by FAULT_BYTE |
| --faults 1..255 | Maximum observations per byte; default: 8 |
| --key HEX | Target master key, exactly 16 bytes |
| --plaintext HEX | Plaintext, exactly 16 bytes |
| --color auto/always/never | Control terminal colors |
| --log PATH | HTML output path; TXT uses the same basename |

Default key and plaintext come from KEY and PLAINTEXT in src/sm4.py.

### Logs

Each run overwrites two files:

- logs/log.html: continuous terminal-style transcript with inline colors.
- logs/log.txt: the same lesson as plain text.

Open the generated HTML in a browser. Red highlights changed bytes and rejected
candidate results. Blue and purple distinguish the two candidate computations;
yellow marks candidates and reference values; green marks matches and results.
Hidden target states are omitted. Values derived by undoing rounds with
recovered subkeys are shown as part of the attack.

The logs folder is ignored by Git. Files appear after running the demonstration.

### Equations

SM4 emits its final words in reverse order:

~~~text
Ciphertext = X[35] || X[34] || X[33] || X[32]
~~~

At the attacked round:

~~~text
q        = X[i+1] XOR X[i+2] XOR X[i+3]
q_faulty = X'[i+1] XOR X'[i+2] XOR X'[i+3]
DeltaB   = inverse_L(X[i+4] XOR X'[i+4])
~~~

For each byte, test every candidate k:

~~~text
S(q_byte XOR k) XOR S(q_faulty_byte XOR k) == DeltaB_byte
~~~

The unchanged oldest word X[i] cancels in the output XOR; its secret value
is not needed to filter candidates. The active inverse uses:

~~~text
inverse_L(y) = ROR_8(L(L(L(y))))
~~~

This follows from L^4(x) = ROL_8(x). It applies to the data transformation L,
rather than the key-schedule transformation L'.

## Current source files

| File | Purpose and current status |
| --- | --- |
| [aes.py](src/aes.py) | AES-128 encryption, decryption and key expansion |
| [sm4.py](src/sm4.py) | SM4 encryption, decryption, key expansion and validation |
| [piret_aes.py](src/piret_aes.py) | AES DFA source; its terminal lesson still references removed support modules |
| [piret_sm4.py](src/piret_sm4.py) | Independent SM4 input-fault DFA lesson and colored logging |

The former GUI, Giraud modules, combined runner, debugger and animations have
been removed. Direct execution of aes.py and sm4.py still references the removed
terminal_log.py. Their cipher functions remain usable through imports.

To run their normal encryption/decryption examples without the old entry-point
wrapper:

~~~powershell
python -c "import sys; sys.path.insert(0, 'src'); import aes; aes.main()"
python -c "import sys; sys.path.insert(0, 'src'); import sm4; sm4.main()"
~~~

These examples print to the terminal. The independent SM4 DFA command provides
the current HTML/TXT logging.

## Validation

~~~powershell
python tools/test_sm4_input_dfa.py
~~~

The six tests cover the official SM4 vector, observable input-fault propagation,
all three selectable input words and all four bytes across the tail rounds,
random-key recovery, ambiguous observations, invalid fault descriptors, and
HTML/TXT generation with overwrite behavior.

## Documents and supporting material

- [AES_SM4_DFA.pdf](docs/AES_SM4_DFA.pdf): main project report.
- [AES_SM4_Scratch.pdf](docs/AES_SM4_Scratch.pdf): supporting notes.
- [Piret_AES.pdf](docs/Piret_AES.pdf): supporting AES DFA document.
- [Piret_SM4_Explained.pdf](docs/Piret_SM4_Explained.pdf): earlier implementation walkthrough.
- [Algorithm_Analysis.pdf](docs/Algorithm_Analysis.pdf): saved analysis.
- [Presentation](docs/Apresentation_PFE.pptx).
- [Reference links](docs/references.txt).
- [Main LaTeX sources](docs/latex/).

Some PDFs, guides and saved results describe previous versions. Their GUI,
matrix-inversion or Giraud examples may differ from the current implementation.
The former root-level PDF build scripts have been removed.

The analysis folder retains scripts, plotting dependencies and saved results
from earlier experiments. Several experiment scripts still import removed
Giraud or logging modules; they are not current runnable entry points.
Supporting generators in tools and the LaTeX lesson folders may also reference
previous modules. The commands documented above are the verified current paths.

## Scope

This project studies single-block algorithms and simulated controlled faults.
It does not implement authenticated message encryption or a physical fault
campaign. A controlled software XOR fault does not establish hardware
reproducibility.

The SM4 attack is an educational DFA adaptation. The original
Piret–Quisquater work concerns AES and KHAZAD, rather than this SM4 fault model.

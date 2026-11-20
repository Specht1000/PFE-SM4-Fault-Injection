# SM4 — Differential Fault Analysis and Hardware Lab

SM4 implementation, controlled byte-fault DFA, and two physical fault-injection
campaigns for a CW1173 Lite ARM with an STM32F303 target. All code and logs are
in English. The only retained comparison with another cipher is at the end of
the principal PDF.

## Academic context

| | Information |
| --- | --- |
| Author | Guilherme Martins Specht |
| GitHub | [@Specht1000](https://github.com/Specht1000) |
| Institution | Polytech Montpellier, France |
| Project | PFE 5A — final-year engineering project |
| Supervisor | Prof. Philippe Maurine |
| Industrial collaboration | STMicroelectronics |

## Software DFA

Run from the repository root with Python 3.9 or newer:

~~~powershell
python src/piret_sm4.py
~~~

The simulator injects a byte XOR into a round-input word, before the subkey XOR.
The solver uses public outputs to test 256 candidates per key byte, recovers
rk31 through rk28, then reverses the schedule to reconstruct the master key.

Edit FAULT_MASK and FAULT_BYTE near the start of src/piret_sm4.py to choose the
first error and byte. Additional masks resolve ambiguity; all bytes are visited.

~~~powershell
python src/piret_sm4.py --step
python src/piret_sm4.py --word 2 --row 1 --faults 8
python src/piret_sm4.py --help
~~~

Logs overwrite logs/log.txt and logs/log.html. The HTML has terminal formatting
and colored equations, candidates and changed bytes. The active inverse is
ROR_8(L(L(L(y)))); no target secret is passed into candidate filtering.

## Hardware firmware

The [hardware project](chipwhisperer/sm4/README.md) provides C SM4 encryption and
decryption, SimpleSerial 1.1 communication, a selectable round trigger and a
Python host client. The firmware runs on the STM32F303, not the capture controller.

~~~powershell
python -m pip install -r chipwhisperer/sm4/requirements.txt
python chipwhisperer/sm4/build.py
python chipwhisperer/sm4/client.py --program chipwhisperer/sm4/build/pfe-sm4-CWLITEARM.hex
~~~

Compilation requires the official MCU SDK and GNU Arm/make tools; see
[commands.txt](chipwhisperer/sm4/commands.txt) for setup. USB programming, flash
verification, the official encryption vector and on-target decryption have
passed on the connected target. The firmware itself does not insert synthetic faults.

## Physical FI: two separate scripts

~~~powershell
python chipwhisperer/sm4/clock_glitch.py --dry-run
python chipwhisperer/sm4/voltage_glitch.py --dry-run
~~~

Dry runs do not connect to USB. To execute physical campaigns on the configured
target:

~~~powershell
python chipwhisperer/sm4/clock_glitch.py --round 31 --max-trials 200
python chipwhisperer/sm4/voltage_glitch.py --round 31 --driver lp --max-trials 200
~~~

Clock glitching perturbs the forwarded target clock. Voltage glitching uses the
Glitch output and requires the correct target-voltage connection. It enables
only the selected LP or HP crowbar. Read [the FI guide](chipwhisperer/sm4/PHYSICAL_FI.md)
before choosing wiring or sweep parameters.

Both scripts record TXT/HTML, CSV and recovery JSON under their own names in logs/.
They distinguish correct results, incomplete responses, rejected faults,
DFA-compatible observations, duplicates and model conflicts. The scripts infer a
candidate fault mask from copied-word differences; pulse settings do not specify
a chosen data error. A compatible output pattern alone is not proof of fault location.

If one campaign uniquely recovers a full round-key candidate, pass its JSON to
the next earlier round. All four tail subkeys are needed for master-key reversal.
No physical fault yield or physical key-recovery result is claimed yet.

## Current files

| File | Purpose |
| --- | --- |
| src/sm4.py | Cipher, decryption, key schedule and validation |
| src/piret_sm4.py | Controlled SM4 DFA, inverse diffusion and key recovery |
| chipwhisperer/sm4/firmware/ | STM32F303 C firmware and Makefile |
| chipwhisperer/sm4/client.py | Program and use the target |
| chipwhisperer/sm4/clock_glitch.py | Clock-injection route and campaign entry point |
| chipwhisperer/sm4/voltage_glitch.py | Voltage-injection route and campaign entry point |
| chipwhisperer/sm4/glitch_common.py | Acquisition, filtering, recovery and cleanup |

The normal cipher example can be run through its function entry point:

~~~powershell
python -c "import sys; sys.path.insert(0, 'src'); import sm4; sm4.main()"
~~~

## Validation

~~~powershell
python tools/test_sm4_input_dfa.py
python tools/test_chipwhisperer_sm4.py
python tools/test_sm4_glitch_campaigns.py
~~~

Tests cover simulated key recovery, native C/Python agreement, the official
vector, random blocks, serial handling, physical-route configuration, model
filtering and mocked acquisition/cleanup. Mocked trials do not apply real faults.

## Report and references

- [Main report](docs/AES_SM4_DFA.pdf): SM4 theory, key recovery, the two physical
  campaigns, and the final cipher comparison. Its established filename is retained.
- [LaTeX sources](docs/latex/).
- [Presentation](docs/Apresentation_PFE.pptx).
- [Reference links](docs/references.txt).
- [Hardware-Security-Labs](https://github.com/morchidy/Hardware-Security-Labs).
- [Historical CW1173 documentation](https://github.com/marc-invalid/chipwhisperer-marc/blob/master/doc/sphinx/naecw1173_cwlite.rst).
- [Official glitch API](https://chipwhisperer.readthedocs.io/en/latest/scope-api.html).

The analysis folder retains SM4-only historical results. Its older
Giraud-comparison scripts depend on removed support modules and are not the
current campaign entry points. Mixed-cipher source files, tutorials and reports
have been removed from the project.

This is an academic single-block implementation and experiment framework,
without message padding or authenticated encryption. Physical faults must be
characterized experimentally rather than equated with software XOR injections.

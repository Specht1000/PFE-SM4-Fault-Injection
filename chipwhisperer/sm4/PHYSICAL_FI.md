# Physical SM4 fault-injection campaigns

Two entry points share acquisition and DFA analysis:

- clock_glitch.py perturbs the forwarded clock with clock_xor.
- voltage_glitch.py drives one voltage crowbar with glitch_only.

Both use the existing SM4 firmware and its trigger; rebuilding is unnecessary
if that firmware is already installed. No synthetic XOR is inserted.

## Inspect the sweep without hardware

~~~powershell
python chipwhisperer/sm4/clock_glitch.py --dry-run
python chipwhisperer/sm4/voltage_glitch.py --dry-run
~~~

The default grid is three widths, two offsets and eleven delays: 66 attempts,
bounded by --max-trials. A dry run never connects to USB.

## Clock campaign

The STM32 must use the scope-generated clock through HS2, as configured by the
normal SM4 client. Connect the CW-Lite USB device and close other programs
holding its USB interface.

~~~powershell
python chipwhisperer/sm4/clock_glitch.py --round 31 --widths 2,5,10 --offsets 0,10 --delays 0:100:10 --max-trials 200
~~~

The script routes HS2 through the glitch block; voltage crowbars remain disabled.
It restores normal clock routing after every attempt. Round 31 is the default.

## Voltage campaign

The scope's Glitch output must connect to the target's intended voltage-glitch
path. Check your board revision and the NewAE connection diagrams first; a
power-measurement connection is not automatically a voltage-injection connection.
The script does not rewire supply jumpers or apply an external voltage.

~~~powershell
python chipwhisperer/sm4/voltage_glitch.py --round 31 --driver lp --widths 2,5,10 --offsets 0,10 --delays 0:100:10
~~~

The normal target clock remains connected. LP is the default crowbar; --driver hp
selects the other driver. Exactly one is enabled, and both are disabled after
each attempt and on exit. The normal cipher must work before a campaign starts.

## Run every attack in one combined log

To run all board attacks in sequence and collect them in a single session log,
use the combined runner. It forwards every option to both campaigns (`--driver`
affects only the voltage one):

~~~powershell
python chipwhisperer/sm4/all_attacks.py --dry-run
python chipwhisperer/sm4/all_attacks.py --round 31 --max-trials 200
~~~

It writes one shared, colour-coded log, `logs/all_attacks.txt` and
`logs/all_attacks.html`, containing the clock campaign followed by the voltage
campaign. The per-method CSV and recovery JSON are still written separately, so
individual evidence is preserved. The process exits nonzero if any campaign
reported an error.

## Instruction-skip / stuck-at recovery

Real clock/voltage glitches on this target often do not flip a single bit: they
force one S-box output byte to a constant (0x00 from a skipped store, or 0xFF).
That stuck-at fault is directly exploitable - one clean stuck-at fault on a byte
pins that key byte - but it does not fit the single-bit (Giraud) or input-word
models, so those campaigns reject it. Use the dedicated recoverer:

~~~powershell
python chipwhisperer/sm4/stuck_at_recover.py --delays 0:120:1 --widths 0.3,0.5,0.8,1.2 --offsets 0,5,10 --max-trials 4000
~~~

It glitches rounds 31, 30, 29 and 28, collects every faulty ciphertext, then runs
`piret_sm4.recover_stuck_at`, which forms the small per-byte candidate sets under
both stuck values (00 and FF) and returns the master key verified by
re-encryption. It writes `logs/stuck_at_recover.txt` / `.html`. To recover, the
sweep must land at least one clean single-byte S-box fault on EACH byte of EACH
round (vary the delay so the glitch hits each of the four S-box lookups).

## Parameter units

| Option | Meaning |
| --- | --- |
| --widths | Comma-separated pulse widths, percentages of one target clock cycle |
| --offsets | Comma-separated fine phase offsets, percentages of one clock cycle |
| --delays | START:STOP:STEP trigger delays, in target clock cycles; stop included |
| --repeat | Glitch repetitions for one triggered event; default 1 |
| --attempts-per-point | Independent attempts at each point; default 1 |
| --max-trials | Cap on attempts, including duplicates and failed responses |
| --round | Triggered processing round, 28..31 |
| --recovered-keys | JSON from prior campaigns with all required later subkeys |

These settings are an initial sweep, not measured successful settings. Clock
period percentages are not nanoseconds. Pulse width and phase are quantized by
the hardware; requested and actual values are both recorded. The glitch DCMs
must report locked. Firmware compilation, optimization and trigger placement
affect the useful delay range.

## Recorded evidence and DFA

Each script first verifies the clean target encryption. Before every trial it
restores a normal clock, disables voltage drivers, resets the target, reloads
the key and selects the trigger round. It then arms one external-trigger event
and requests encryption. The key is used by target setup and baseline checking,
not by the candidate filter.

Every trial records ciphertext, XOR, requested/actual settings and one status:
correct, timeout_or_reset, invalid_response, faulty_rejected, dfa_compatible,
duplicate or model_conflict. A timeout does not independently prove a reset.

The copied output words supply an observed candidate input-byte error. The
solver requires one changed word/byte and a matching inverse-L difference,
then enumerates all 256 key-byte candidates. A compatible pattern is not proof
that the physical fault happened exactly at the intended input. Duplicate
views do not add independent evidence. An empty intersection stops acquisition.

After four bytes become unique, the script saves a model-dependent subkey
candidate. It does not choose which byte will fault and may recover none.

| Script | Outputs, overwritten on each run |
| --- | --- |
| clock_glitch.py | logs/clock_glitch.txt, .html, .csv, clock_glitch_recovery.json |
| voltage_glitch.py | logs/voltage_glitch.txt, .html, .csv, voltage_glitch_recovery.json |
| all_attacks.py | logs/all_attacks.txt, .html (combined); each method's CSV/JSON as above |

Partial CSV/JSON evidence is retained when acquisition is interrupted. A dry
run writes only its TXT/HTML description and leaves prior acquisition files alone.

## Earlier rounds and master-key candidates

Only after rk31 is unique can a round-30 campaign peel it from correct/faulty
outputs. Use the saved JSON as input:

~~~powershell
python chipwhisperer/sm4/clock_glitch.py --round 30 --recovered-keys logs/clock_glitch_recovery.json
~~~

Repeat for round 29 after recovering rk30, then round 28 after rk29. The script
requires the needed later keys and checks the saved baseline context. Each run
starts a fresh candidate intersection for its selected round; it does not resume
partial same-round observations. Save a copy of a CSV/JSON first if you want to
retain a prior sweep.

Four consecutive tail candidates permit reversing the key schedule. A full
master-key candidate is reported as verified only if re-encryption reproduces
the clean target ciphertext. Insufficient observations are not guessed through.

## Validation status

Physical firmware programming and normal SM4 encryption/decryption have passed.
The two campaign routes, compatible-pair filtering, trial logging and cleanup
are tested using mocks and simulated observations. Neither campaign has been
executed as a physical glitch sweep in this task. No fault yield, selected-bit
control or physical key recovery is claimed.

~~~powershell
python tools/test_sm4_glitch_campaigns.py
~~~

Sources:

- [NewAE scope/glitch API](https://chipwhisperer.readthedocs.io/en/latest/scope-api.html)
- [CW1173 hardware and Glitch port](https://chipwhisperer.readthedocs.io/en/latest/Capture/ChipWhisperer-Lite.html)
- [CW303 ARM target](https://chipwhisperer.readthedocs.io/en/latest/Targets/CW303%20Arm.html)
- [LP/HP crowbar choice](https://chipwhisperer.readthedocs.io/en/latest/cw_tips_tricks/basics/glitch_hp_vs_lp.html)

# Physical SM4 DFA on the chip

Two DFA attack entry points recover the full SM4 master key from physical glitch
faults on the CW1173-Lite / STM32F303 target:

- `clock_glitch.py` — glitches the forwarded clock (`clock_xor` on HS2).
- `voltage_glitch.py` — drives one voltage crowbar (`glitch_only`, LP/HP driver).

Both use the existing SM4 firmware and its per-round trigger (no firmware rebuild
needed if it is already installed), glitch rounds 31..28, collect the faulty
ciphertexts, and run the stuck-at solver, which recovers the master key verified
by re-encryption. The shared recovery engine is `stuck_at_recover.py`.

> **Status on this board:** the clock route recovered the full SM4 master key,
> verified by re-encryption (`logs/clock_glitch.txt`, `Re-encryption check:
> PASS`). The voltage route uses the same solver but has not yet faulted (every
> trial `correct` = too weak / wiring). See "Validation status" below.

~~~powershell
python chipwhisperer/sm4/clock_glitch.py                 # DFA via clock glitch
python chipwhisperer/sm4/voltage_glitch.py --driver lp   # DFA via voltage glitch
~~~

## Fault model: instruction-skip / stuck-at

On this target the glitch does not flip a single bit; it forces one S-box output
byte to a constant `V` — empirically `00` (a skipped store) or `FF`. Only the
newest output word changes, and its inverse-`L` difference is confined to one
byte, so it is a clean single-byte fault.

Such a fault is directly exploitable. If byte `b` was forced to `V`, the clean
S-box output was `d XOR V` (with `d` the observed inverse-`L` difference at that
byte), so the S-box input is `a = Sinv(d XOR V)` and the key byte is
`rk_b = a XOR q_b`, where `q_b` is the public combination of the three unchanged
output words. One clean stuck-at fault pins one key byte. The forced value is not
known in advance, so both `V in {00, FF}` are tried and the correct global choice
is fixed by re-encrypting the recovered key.

## Recovery procedure

1. Glitch rounds 31, 30, 29 and 28. The four S-box lookups sit at the same
   trigger-relative delays each round, so the useful delays found on round 31 are
   reused for the deeper rounds (a full grid becomes a few trials).
2. For each clean single-byte fault, form the candidate key byte(s) under both
   stuck values and vote; noisy or multi-byte faults scatter and are outvoted.
3. Per round, assemble `rk_i`, peel the round with it, continue to the next. The
   four tail subkeys reverse the SM4 schedule; the master key is confirmed by
   re-encryption.

## Reading the log and tuning the glitch

Each entry point writes its own colour-coded log, `logs/clock_glitch.*` or
`logs/voltage_glitch.*`, with per-fault lines, a per-round status summary (shown
even with zero faults), a per-byte coverage line, and a step-by-step recovery
derivation (`Sinv(d XOR V) XOR q = ...`).

The per-trial status tells you how to tune:

| In the log | Meaning | Action |
| --- | --- | --- |
| `correct` | glitch too weak (no effect) | raise `--widths` / `--repeat`; for voltage try `--driver hp` |
| `no-response` | glitch too strong (reset/crash) | lower `--widths` |
| `fault` | a fault landed | you are in the useful zone |
| `MISSING [..]` on coverage | a byte never got a clean fault | vary `--delays` to hit its S-box lookup |

Defaults: `clock_glitch.py` uses the NewAE CW-Lite ARM regime (negative widths,
`repeat 3`); `voltage_glitch.py` uses a wider positive-width crowbar regime. Both
accept `--widths --offsets --delays --repeat --max-trials --key --input` and
`--driver lp|hp` (voltage). A Ctrl+C still attempts recovery with the faults
collected so far.

~~~powershell
python chipwhisperer/sm4/clock_glitch.py --delays 0:170:1 --widths -8,-9,-10 --offsets -40 --repeat 3
python chipwhisperer/sm4/voltage_glitch.py --driver hp --widths 10,20,30,40 --offsets 0,20,40
~~~

For voltage, the scope's Glitch SMA must be wired to the target's VCC-glitch path
(not the power-measurement connection); otherwise every trial reads `correct`.

### Finding the voltage fault zone (`voltage_sweep.py`)

The voltage fault zone is narrow and the integer `repeat` steps are coarse, so
tuning by hand is slow. `voltage_sweep.py` is a characterization tool (not an
attack): it sweeps driver x repeat x width on round 31 and prints a fault map of
how many trials were `correct` / `fault` / `no-response` per cell, then lists the
cells that actually faulted and the exact command to recover there.

~~~powershell
python chipwhisperer/sm4/voltage_sweep.py
python chipwhisperer/sm4/voltage_sweep.py --drivers hp --repeats 9,10 --widths 20,25,30,35,40,45
~~~

Read the map: all cells 100% `correct` even at `repeat 10` and the widest width
usually means the Glitch SMA is not wired to VDD; a straight jump from `too weak`
to `too strong` with no fault zone means step `--widths` more finely between those
two widths. Once a cell faults, run `voltage_glitch.py` with that
`--driver/--repeat/--widths/--offsets`. Output: `logs/voltage_sweep.*`.

## Outputs

| Script | Log |
| --- | --- |
| clock_glitch.py | logs/clock_glitch.txt, .html |
| voltage_glitch.py | logs/voltage_glitch.txt, .html |

## Other fault models (library only)

`glitch_common.py` also contains the input-word Piret model and the single-bit
Giraud filter (`run_campaign`, `infer_fault`), used for the simulation study and
the report. They are exercised by the tests but are not the chip attack entry
points, because the observed physical faults are stuck-at, not input-word or
single-bit.

~~~powershell
python tools/test_sm4_glitch_campaigns.py
~~~

## Validation status

Firmware programming and normal SM4 encryption/decryption passed on the board.
Full physical master-key recovery via the clock route has been demonstrated and
verified by re-encryption: with width ~ -7.8%, offset ~ -39.8%, round 31 yielded
13 single-byte stuck-at faults (all four S-box bytes covered), the point was
reused for rounds 30-28, and the solver recovered rk31..rk28 and the master key
0123456789ABCDEFFEDCBA9876543210 (`logs/clock_glitch.txt`, `Re-encryption check:
PASS`). The voltage route uses the same solver; whether it faults depends on
wiring and glitch tuning, and it has not yet faulted on this board.

Sources:

- [NewAE scope/glitch API](https://chipwhisperer.readthedocs.io/en/latest/scope-api.html)
- [CW1173 hardware and Glitch port](https://chipwhisperer.readthedocs.io/en/latest/Capture/ChipWhisperer-Lite.html)
- [CW303 ARM target](https://chipwhisperer.readthedocs.io/en/latest/Targets/CW303%20Arm.html)
- [LP/HP crowbar choice](https://chipwhisperer.readthedocs.io/en/latest/cw_tips_tricks/basics/glitch_hp_vs_lp.html)
- [ChipWhisperer Fault201 DFA labs (Lab 1_3A / 1_3B)](https://github.com/newaetech/chipwhisperer-jupyter/tree/main/courses/fault201)

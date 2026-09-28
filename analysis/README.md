# AES analysis notebook

[`aes_analysis.ipynb`](aes_analysis.ipynb) collects every analysis built in this
project into one Jupyter notebook:

1. **AES-128 correctness** — FIPS 197 known-answer vector, round-trip, the state
   as a 4x4 matrix, and the S-box.
2. **Diffusion / avalanche** — how one flipped plaintext bit spreads across the
   rounds.
3. **Fault propagation** — a single injected byte fault and how far it spreads,
   depending on the round (reuses [`aes_fi_demo`](../fault_injection/aes_fi_demo/README.md)).
4. **Giraud DFA** — recovering the full key from single-bit last-round faults
   (reuses [`giraud_attack`](../fault_injection/giraud_attack/giraud.py); theory
   in [`docs/giraud-attack`](../docs/giraud-attack/README.md)).
5. **Power traces** — inspecting the captured ChipWhisperer waveforms in
   [`experiments/chipwhisperer_aes/results`](../experiments/chipwhisperer_aes/README.md)
   and a correlation-power-analysis (CPA) methodology walk-through.

## Running it

Uses only the base environment (NumPy + Matplotlib) — no ChipWhisperer or
PyCryptodome, because it runs on the project's pure-Python AES.

```powershell
python -m pip install jupyter matplotlib numpy
jupyter notebook analysis/aes_analysis.ipynb
```

Or re-execute headless from the repository root:

```powershell
jupyter nbconvert --to notebook --execute --inplace analysis/aes_analysis.ipynb
```

## Honest limitations

- The fault-injection and DFA sections operate on the **software AES model**.
  The same fault parameters map to the firmware `f` command, but a software
  result is not evidence of a successful *physical* fault campaign.
- The captured campaigns hold only **10 distinct plaintexts**, so the CPA
  section is a demonstration of the *method*, not a validated key recovery — as
  it stands, the correct key byte does not rank first. Capture more traces
  (`aes_capture.py capture --traces 100`) to make it work for real.

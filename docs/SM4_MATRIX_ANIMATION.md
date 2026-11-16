# SM4 Piret matrix animation

Run from the repository root:

```powershell
python src/animate_piret_sm4.py
```

Start with **4-bit teaching matrix** and advance using **Next** or Right arrow.
Use **Previous** or Left arrow to revisit any calculation. **Play / Pause** or
Space runs the current sequence at the selected speed. The timeline slider
seeks to any recorded state; the chapter selector jumps to its first step.
**Restart chapter** returns to the start of the current chapter.

The right panel shows the current code, substituted numerical equation, purpose
and variable values. An orange token moves from the selected matrix cell to the
packed word. Matrix rows start at the top; printed binary bit 0 is on the right.

1. **Build columns:** each unit vector reveals a column of the linear map.
2. **Collect rows:** the outer loop fixes a row and the inner loop visits columns.
   Separate scenes show extraction (`>>` and `& 1`), positioning (`<<`), OR
   accumulation and identity attachment.
3. **Invert the matrix:** search down a pivot column, swap entire augmented rows,
   then XOR each required target row. Changed cells are red. The left half
   becomes identity while the right half becomes the inverse.
4. **Apply the inverse:** select one inverse row, AND with the input, compute
   parity and assemble a result bit. The input-vector positions used by that row
   are highlighted. The real SM4 example restores `2E000000` from `962EB8B8`.
5. **Recover the SM4 key:** actual clean/faulty ciphertexts, candidate
   intersections, four subkeys, inverse schedule and FK removal. Bytes appear
   only after a singleton candidate intersection. Encrypt and decrypt verify the
   recovered master key. The first error mask is `03` (`00000011` in binary),
   which flips two bits in the selected S-box input byte.

The four-bit matrix is an independently checked teaching example, not a
four-bit version of SM4. Selecting **32-bit real SM4 matrix** switches the
matrix chapters to the actual public SM4 map. The final attack chapter always
uses the real SM4 solver, regardless of the teaching-matrix selection.

Snapshots are independent. Moving backwards restores a recorded view and does
not rerun a fault or reverse a live Python process. The matrix functions and
solver are unchanged. The simulated XOR faults do not establish physical
single-bit glitch control on an STM32 target.

Terminal and displayed calculations are logged to `logs/animate_piret_sm4.txt`
and `logs/animate_piret_sm4.html`; they are overwritten for each session.
The current lesson's complete snapshots are also saved to
`logs/animate_piret_sm4_trace.json`, overwritten when the matrix model changes.

Headless numerical verification:

```powershell
python src/animate_piret_sm4.py --check
```

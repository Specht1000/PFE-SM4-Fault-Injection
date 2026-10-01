# Piret-Quisquater-style differential fault analysis: Python lesson

Start with [the AES lesson](../../aes/README.md). This program is a local software
simulation with a public example key. It requires Python 3.9+, with no packages,
ChipWhisperer connection, or firmware changes.

```powershell
python fault_injection/piret_attack/piret.py
python fault_injection/piret_attack/piret.py --step
python fault_injection/piret_attack/piret.py --seed 7 --row 2 --column 3
python fault_injection/piret_attack/piret.py --faults 1
```

The last command intentionally demonstrates ambiguity: it normally leaves many
candidates and exits with status 2. Default `--faults 6` is a maximum; the solver
stops as soon as all four key groups are unique. Increase this limit if needed.
Both `--key` and `--plaintext` accept exactly 16 bytes as hex.

## What the demonstration teaches

1. **Inject:** XOR a nonzero byte just before MixColumns in round 8. This is a
   single transient data fault; keys and instructions are unchanged.
2. **Propagate:** round-8 MixColumns spreads the error to four bytes in one column.
   Round-9 ShiftRows sends them to four different columns. Round-9 MixColumns
   then makes all sixteen state bytes differ.
3. **Observe:** collect a correct ciphertext and faulty ciphertexts for the same
   plaintext/key. The simulator changes the nonzero mask between observations.
4. **Constrain:** guess a last-round key byte, XOR it out, then apply the inverse
   S-box. The resulting differences must match the round-9 MixColumns pattern.
5. **Intersect:** retain four-byte key tuples compatible with every observation.
6. **Recover:** assemble K10 and reverse the AES-128 key schedule to obtain K0.
   Verify by encrypting the known plaintext, and finally check simulator truth.

## The central equation

For the four ciphertext positions belonging to one round-9 column:

```text
d[r] = InvSbox[C[p[r]] XOR k[r]] XOR InvSbox[C_fault[p[r]] XOR k[r]]
d[r] = MixColumns[r][unknown_fault_row] * unknown_error
```

The multiplication is in GF(2^8). For an error in row 0, the four differences must
be `[2e, e, e, 3e]`, all with the **same** nonzero `e`. The other rows use other
columns of the MixColumns matrix. The effective error at round 9 is unknown and
is generally different from the round-8 mask because SubBytes is nonlinear.

Final ShiftRows determines the output positions:

| Round-9 column | Ciphertext / K10 positions, in row order |
| --- | --- |
| 0 | 0, 13, 10, 7 |
| 1 | 4, 1, 14, 11 |
| 2 | 8, 5, 2, 15 |
| 3 | 12, 9, 6, 3 |

`column_candidates` first groups the 256 byte-key guesses by implied difference.
It then enumerates four possible error rows and 255 nonzero effective errors.
The Cartesian product combines compatible byte guesses into four-byte tuples.
`recover_last_key` intersects these tuple sets; it never selects an arbitrary
candidate when several remain. Repeating the same faulty ciphertext adds no
information. Invalid output lengths, no-change outputs, incompatible four-byte
round-9 fault patterns, or empty intersections produce explicit errors.

## Separation of views

`show_propagation` is the **teacher view**: it displays hidden states so you can
understand the mechanism. `recover_last_key(correct, faulty_outputs)` is the
**attacker view**: it receives only ciphertexts, not the master key, coordinates,
mask, plaintext or state traces. Plaintext is used only after recovery to verify.
The code is deterministic by seed for reproducible demonstrations; this is not
a physical glitch campaign or a claim of measured hardware success.

## Relationship to Piret and Quisquater

The reference is Piret and Quisquater, *A Differential Fault Attack Technique
against SPN Structures, with Application to the AES and KHAZAD*, CHES 2003,
pages 77–88, [DOI / institutional record](https://research.dial.uclouvain.be/entities/publication/f15e3e1b-78b1-4749-925d-fdc1d60c1694).
Their abstract reports recovery with two faulty ciphertexts under its fault
assumptions. Here the injection point is before round-8 MixColumns, within that
late-round propagation model. This educational implementation exposes the
final-round differential constraints and independent group intersections;
it does not reproduce every optimization or cross-column constraint in the paper.
It may require additional observations. With the default public vector and seed
42, this implementation recovers the key with two faulty ciphertexts.

Do not confuse this with injecting before round-9 MixColumns: that later fault
changes only four ciphertext bytes and constrains only one key group. The AES
module supports that location for comparison, but this full-key demonstration
expects the round-8 model and rejects the four-byte pattern.

## Files and verification

| File | Role |
| --- | --- |
| `../../aes/src/aes.py` | Visible AES primitives, state observer, fault hook and inverse schedule. |
| `piret.py` | Propagation display, equations, ciphertext-only candidate solving and CLI. |
| `test.py` | Known/intermediate vectors, independent OpenSSL oracle, all 16 fault positions, ambiguity and input errors. |

```powershell
python -m unittest discover -s fault_injection/piret_attack -p test.py -v
```

Only the independent oracle test needs OpenSSL (including Git for Windows' copy);
it is explicitly skipped if unavailable. Demonstrations require only Python.

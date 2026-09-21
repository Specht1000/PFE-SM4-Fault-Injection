# Educational AES-128 fault injection demo

Run from `C:\Projetos\PFE 5A` using Python 3.9 or newer. No external dependencies are required.

```powershell
python fault_injection/aes_fi_demo/demo.py
```

Open `fault_injection/aes_fi_demo/output/demo.html` in a browser. This offline page lets you step through each operation and compare the correct state, faulty state, and XOR difference. **Jump to injection** selects the first affected step. State snapshots are also exported to `output/trace.json`. Running the demo again overwrites files in the selected output directory.

## Fault model

- Encrypt one 16-byte block with AES-128, without a mode of operation or padding.
- Both executions use the same input and key: public values from the FIPS 197 example.
- Apply a single transient modification to one state byte immediately **before** the selected operation: `state[column][row] ^= mask`.
- Default: round 9, before MixColumns, row 0, column 0, XOR mask `0x01`.
- `0x01` flips one bit; `0x55` flips four bits within the same byte. The mask specifies an XOR difference, not a replacement byte value.
- Row/column indices: 0–3; rounds: 1–10. Round 0 represents the initial AddRoundKey and is not an injection point in this demo.
- The library stores `state[column][row]`. HTML matrices display conventional AES rows. Linear byte index = `4 * column + row`.

This simulates the **logical effect** of a fault. It does not control voltage, clock, laser, or electromagnetic equipment. Internal states are visible for educational purposes; this does not assume they are observable in a physical attack.

## Presentation walkthrough — approximately 5 minutes

1. Explain the model and show that both executions match before injection.
2. Click **Jump to injection**: one byte differs, initially by a single bit.
3. Advance: round 9 MixColumns spreads the difference across four bytes in the same column. For mask `01` in row 0, the column difference is `02 01 01 03`, using multiplication in the AES finite field.
4. AddRoundKey preserves the XOR difference: `(a XOR k) XOR (b XOR k) = a XOR b`.
5. In round 10, SubBytes transforms the difference values and ShiftRows disperses their positions. There is no MixColumns in this round. Four output bytes differ: indices 0, 7, 10, and 13 for the default injection column.
6. Distinguish FI (introducing a perturbation) from DFA (exploiting relationships to narrow down key candidates). This program demonstrates FI and propagation, not key recovery.

The number of differing **bytes** and the Hamming distance in **bits** are separate measurements. Four differing bytes do not imply four differing bits.

## Comparative experiments

```powershell
# Flip four bits within one byte in round 9
python fault_injection/aes_fi_demo/demo.py --mask 0x55 --output fault_injection/aes_fi_demo/output_mask55

# Change the injection position
python fault_injection/aes_fi_demo/demo.py --row 2 --column 1 --output fault_injection/aes_fi_demo/output_position

# Late fault: only one output byte differs
python fault_injection/aes_fi_demo/demo.py --round 10 --stage SubBytes --output fault_injection/aes_fi_demo/output_r10

# Earlier fault: observe additional diffusion without assuming a fixed byte count
python fault_injection/aes_fi_demo/demo.py --round 8 --output fault_injection/aes_fi_demo/output_r8

# Run validation tests
python -m unittest discover -s fault_injection/aes_fi_demo -p test_demo.py -v
```

## Files and validation

- `demo.py`: instrumented execution, injection, comparison, CLI, and HTML visualization.
- `aes_reference.py`: unchanged copy of `aes.py` from the supplied ZIP archive.
- `LICENSE.aes`: original MIT license attributing BoppreH; the source also credits Bo Zhu and other contributors.
- `test_demo.py`: AES-128 known-answer vector, comparison with the original implementation, propagation across all 16 positions with different masks, and invalid-parameter rejection.

The known-answer vector uses key `000102030405060708090a0b0c0d0e0f`, input `00112233445566778899aabbccddeeff`, and expected output `69c4e0d86a7b0430d8cdb78070b4c55a`. This example is intended for teaching and experimentation, not production cryptography.

## Presentation references

- NIST, FIPS 197 (AES): https://csrc.nist.gov/pubs/fips/197/final
- Dusart, Letourneux, and Vivolo, Differential Fault Analysis on A.E.S: https://arxiv.org/abs/cs/0301020
- Source repository declared by the supplied library: https://github.com/boppreh/aes

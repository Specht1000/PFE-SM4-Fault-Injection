# Debug the complete SM4 Piret demonstration

Open the repository root in VS Code. Install Microsoft's Python and Python
Debugger extensions if they are missing, and select the project interpreter.
Open Run and Debug with Ctrl+Shift+D, select **SM4 Piret: full key recovery**,
and press F5. This runs the actual entry point and preserves its TXT/HTML logs.
It is a software fault simulation, not a connection to the STM32 board.

## Recommended breakpoint route

Set breakpoints by clicking the gutter beside these statements. Use F5 to
advance between milestones rather than stepping through every printed line.

| Location | Breakpoint statement | What to inspect |
| --- | --- | --- |
| `src/run.py`, `sm4_demo` | First executable statement | Plaintext, key and orchestration. The key belongs to the simulated target. |
| `src/piret_sm4.py`, `recover_sm4_master_key` | `clean_view = peel_sm4(correct, number, keys)` | Target round `number` and previously recovered `keys`. |
| `src/piret_sm4.py`, nested `observer` in `sm4_fault_encrypt` | `value ^= mask << (24 - 8 * byte)` | Actual simulated fault: compare `value` before and after F10. |
| `src/piret_sm4.py`, `sm4_byte_candidates` | `delta_b = inverse_linear(c[0] ^ f[0])` | Correct/faulty word difference and inverse diffusion. |
| `src/piret_sm4.py`, `recover_sm4_master_key` | `event = dict(...)` | `fresh`, `survivors`, `before`, `delta`, `observation`, `mask`. The intersection is already computed here. |
| `src/piret_sm4.py`, `recover_sm4_master_key` | `keys[number] = int.from_bytes(subkey, "big")` | All four unique bytes of one recovered subkey. F10 inserts the word into `keys`. |
| `src/piret_sm4.py`, `peel_sm4` | `previous = words[3] ^ ...` | Undo a later round using a subkey already recovered by the solver. |
| `src/piret_sm4.py`, `recover_sm4_master_key` | `master = reverse_sm4(final_keys)` | Four tail words in order rk28, rk29, rk30, rk31. Use F11 to enter inverse expansion. |
| `src/piret_sm4.py`, `reverse_sm4` | `words[index] = words[index+4] ^ ...` | Each backward key-schedule recurrence. |
| `src/run.py`, `sm4_demo` | `verified_ciphertext = sm4.sm4_encrypt_block(plaintext, recovered)` | Final master-key check against the clean ciphertext. |

## Conditional breakpoints

Right-click a breakpoint and choose Edit Breakpoint to enter a condition.

- At `event = dict(...)`: `number == 31 and byte == 0` limits stops to the first attacked byte.
- At the same statement: `len(survivors) == 1` stops only when a byte becomes unique.
- At `keys[number] = ...`: `number == 28` stops before the last tail word is stored.
- At the XOR inside the fault observer: `fault_round == 31 and byte == 0 and mask == 1` isolates the first fault.

The presentation may recompute simulated faults to illustrate propagation, so
the observer breakpoint can trigger more than once for an illustrated fault.
Disable it after seeing the XOR, and continue at the solver intersection.

## Inspect useful values

At the solver's event breakpoint, add these expressions to Watch:

```python
number
byte
observation
f"{mask:02X}"
f"{delta:08X}"
sorted(fresh)
sorted(survivors)
subkey.hex().upper()
keys
used
```

Expressions are available only in their defining frame. At the fault observer,
inspect `value`, `mask`, `byte` and `fault_round` instead. At the end, inspect
`master.hex().upper()` after executing the call to `reverse_sm4`.

For the default public vector, the first mask 01 gives DeltaB `4F000000` and
key-byte candidates `90 91`. Mask 02 leaves `91`. The recovered tail words are
rk31=`9124A012`, rk30=`01CF72E5`, rk29=`62293496`, rk28=`428D3654`.
The recovered master key is `0123456789ABCDEFFEDCBA9876543210`.

## Controls

- F10: execute the next statement without entering a called function.
- F11: enter a function, for example `inverse_linear` or `reverse_sm4`.
- Shift+F11: finish the current function and return to its caller.
- F5: continue to the next enabled breakpoint.
- Shift+F5: stop debugging.

The second launch configuration adds terminal lesson pauses. Press Enter in
the integrated terminal at a lesson prompt; F5 resumes a debugger breakpoint.
These are separate controls. A printed lesson step is not a Python statement.

Execution logs overwrite `logs/piret_sm4.txt` and `logs/piret_sm4.html`.
Debugger Watch values are not automatically copied into those logs.

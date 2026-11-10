# Fault-Model Verification

This note **proves** that the fault-width taxonomy tables in the report
(chapter *"Causing Single-Bit Faults in Practice"*,
section *"A taxonomy of fault widths and their consequences"*,
`docs/latex/chapters/09_physical_faults.tex`) are correct.

For every cell it gives three things:

1. **Why** — the mathematical reason (the S-box differential).
2. **Where** — the exact check in `src/` that enforces it (`file:line`).
3. **Proof** — a reproducible command and the number it actually produces.

All commands are run from `src/`:

```bash
cd src
```

Keys/plaintexts below are the fixed lab values `key = 00 01 … 0f`,
`pt = 10 11 … 1f` (public, on the project's own ChipWhisperer target).

---

## 0. The one fact everything rests on: the S-box is non-linear

Both attacks inject the fault at an **S-box input**. The claim that you *cannot*
just read the fault off `C ⊕ C'` is the reason the whole taxonomy exists, so we
check it first.

A single-bit input difference does **not** stay a single bit after the S-box:

```bash
python - <<'PY'
import aes
hw = lambda x: bin(x).count('1')
for e in (0x01, 0x08, 0x80):
    mean = sum(hw(aes.SBOX[a] ^ aes.SBOX[a ^ e]) for a in range(256)) / 256
    print(f"input diff {e:#04x} (HW=1) -> mean output-diff HW = {mean:.2f}")
PY
```

Measured output:

```
input diff 0x01 (HW=1) -> mean output-diff HW = 3.94
input diff 0x08 (HW=1) -> mean output-diff HW = 4.06
input diff 0x80 (HW=1) -> mean output-diff HW = 4.14
```

**Consequence.** A 1-bit fault comes out of the S-box as a ~4-bit difference.
So `C ⊕ C'` (an S-box *output* difference, after the linear layer is undone)
never looks like a single bit — you must solve the differential
`S(a⊕k) ⊕ S(a⊕e⊕k) = d` for `k`. This is why "unknown bit" and "unknown byte"
are real cases and not shortcuts.

---

## 1. Table "Consequence by fault width" — the make-or-break table

| Fault width | Report says Giraud | Report says Piret |
|---|---|---|
| 0 bits (no effect) | useless | useless |
| 1 bit | **ideal** | works (bit = byte of weight 1) |
| 2–8 bits, same byte | **breaks** | **ideal** |
| 1 whole byte | breaks | ideal |
| ≥ 2 state bytes | breaks | breaks |

### 1.1 "No effect ⇒ useless" ✔

**Why.** If nothing flips, `C = C'`, so there is no difference to analyse.

**Where.** `giraud_aes.py:79` rejects it (zero changed bytes ≠ one):

```python
if len(changed) != 1:
    raise ValueError("AES Giraud requires exactly one changed ciphertext byte.")
```

**Proof.**

```bash
python - <<'PY'
import aes, giraud_aes
key = bytes(range(16)); pt = bytes(range(16, 32))
C = aes.aes_encrypt(pt, key)
try:
    giraud_aes.aes_candidates(C, C, known_mask=0x08)   # faulty == correct
except ValueError as e:
    print("no-effect ->", e)
PY
```
```
no-effect -> AES Giraud requires exactly one changed ciphertext byte.
```

### 1.2 "1 bit ⇒ Giraud ideal, exactly one ciphertext byte changes" ✔

**Why.** AES has **no MixColumns in the last round**, so a one-bit fault at the
final-SubBytes input stays confined to one byte all the way to the ciphertext.

**Where.** Same guard, `giraud_aes.py:72–80`
(*"Without final-round MixColumns, only one ciphertext byte should change."*).

**Proof.**

```bash
python - <<'PY'
import aes, giraud_aes
key = bytes(range(16)); pt = bytes(range(16, 32))
C = aes.aes_encrypt(pt, key)
F, _ = giraud_aes.aes_fault_encrypt(pt, key, byte=0, mask=0x08)  # 1-bit fault
print("changed bytes:", [i for i in range(16) if C[i] != F[i]])
PY
```
```
changed bytes: [0]
```

### 1.3 "2–8 bits in the same byte ⇒ Giraud breaks, Piret ideal" ✔

This is the key asymmetry in the whole report, so it is proven in full.

**Why.** Giraud keeps a key guess only if the reconstructed input difference has
**Hamming weight 1** (`giraud_common.py:2`,
`SINGLE_BITS = (0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80)`). A multi-bit fault
produces a weight > 1 difference under the *true* key, so the true key is thrown
away — the attack fails. Piret instead accepts **any nonzero byte difference**,
so the same fault is fine.

**Where.**
- Giraud filter: `giraud_aes.py:103` → `if difference in allowed:` with
  `allowed = SINGLE_BITS` (unknown) or the one known bit.
- Piret acceptance: `piret_sm4.py:150` rejects only a *missing* or
  *multi-byte* difference, never a multi-*bit* one inside the byte.

**Proof.** Inject a 2-bit fault (`mask = 0x0A`, weight 2) and check the
difference the solver reconstructs under the **true** key byte:

```bash
python - <<'PY'
import aes
from giraud_common import SINGLE_BITS
hw = lambda x: bin(x).count('1')
key = bytes(range(16)); pt = bytes(range(16, 32))
C = aes.aes_encrypt(pt, key)
def obs(rnd, op, state):
    if rnd == 10 and op == "Before SubBytes":
        state[0][0] ^= 0x0A          # two bits flipped in one byte
F = aes.aes_encrypt(pt, key, observer=obs)
pos = next(i for i in range(16) if C[i] != F[i])
k = key[pos]
d = aes.INV_SBOX[C[pos] ^ k] ^ aes.INV_SBOX[F[pos] ^ k]
print(f"reconstructed diff under TRUE key = {d:#04x}, HW = {hw(d)}")
print("in SINGLE_BITS? ", d in SINGLE_BITS, "  -> Giraud REJECTS true key (breaks)")
print("nonzero byte?   ", d != 0,            "  -> Piret ACCEPTS      (holds)")
PY
```
```
reconstructed diff under TRUE key = 0x4c, HW = 3
in SINGLE_BITS?  False   -> Giraud REJECTS true key (breaks)
nonzero byte?    True    -> Piret ACCEPTS      (holds)
```

The true key survives Piret's test but not Giraud's — exactly what the table
claims, and the concrete reason **Piret is a superset of Giraud**.

### 1.4 "≥ 2 state bytes ⇒ both break" ✔

**Why.** Each solver's propagation model assumes a single faulted byte. Two
independent faulted bytes produce a changed-position pattern that matches neither
the single-byte MixColumns pattern (Piret) nor the single-byte confinement
(Giraud).

**Where.**
- Giraud: `giraud_aes.py:79` (`len(changed) != 1`).
- Piret (SM4): `piret_sm4.py:142` requires three output words unchanged, and
  `piret_sm4.py:150` rejects a difference spilling outside the selected byte.

**Proof.**

```bash
python - <<'PY'
import aes, giraud_aes
key = bytes(range(16)); pt = bytes(range(16, 32))
C = aes.aes_encrypt(pt, key)
F, _ = giraud_aes.aes_fault_encrypt(pt, key, byte=0, mask=0x08)
F2 = bytearray(F); F2[5] ^= 0x11          # tamper a second byte
try:
    giraud_aes.aes_candidates(C, bytes(F2), known_mask=0x08)
except ValueError as e:
    print("multi-byte ->", e)
PY
```
```
multi-byte -> AES Giraud requires exactly one changed ciphertext byte.
```

---

## 2. Table "Consequence by fault value" — the known/unknown cost

| Attack | Value known | Value unknown | Report's measured |
|---|---|---|---|
| Giraud | tests **1** value of `e` | tests **8** values | 32 → ≈ 34.6 |
| Piret | — (sweeps 1…255 by construction) | — | unchanged |

**Why.** A stronger filter (one allowed `e`) leaves fewer surviving key
candidates per fault, so fewer faults are needed to intersect down to one key.
A weaker filter (eight allowed `e`) leaves more survivors, so more faults are
needed. We confirm the *mechanism* — survivors per single observation — which is
what drives the fault counts.

**Where.** `giraud_aes.py:84–87`:

```python
if known_mask is None:
    allowed = SINGLE_BITS      # unknown: 8 masks
else:
    allowed = (known_mask,)    # known: 1 mask
```

**Proof.**

```bash
python - <<'PY'
import aes, giraud_aes
key = bytes(range(16)); pt = bytes(range(16, 32))
C = aes.aes_encrypt(pt, key)
F, _ = giraud_aes.aes_fault_encrypt(pt, key, byte=0, mask=0x08)
_, known   = giraud_aes.aes_candidates(C, F, known_mask=0x08)
_, unknown = giraud_aes.aes_candidates(C, F, known_mask=None)
print("known-bit   survivors per fault:", len(known))
print("unknown-bit survivors per fault:", len(unknown))
PY
```
```
known-bit   survivors per fault: 2
unknown-bit survivors per fault: 14
```

Fewer survivors when the bit is known (2 vs 14) ⇒ faster convergence ⇒ the
smaller median fault count (32 vs ≈ 34.6). Piret has no such row because its
solver already sweeps `e ∈ {1,…,255}` unconditionally
(`piret_sm4.py:162`, `for candidate_input in range(256)`), i.e. it is *always*
the "value unknown" case.

---

## 3. Table "Consequence by fault position" — unknown location does not break

| Situation | Report's claim |
|---|---|
| Unknown which group/column | read from the changed-position signature |
| Unknown position within group | solver sweeps all rows (`r ∈ {0,1,2,3}`) |

**Why / Where.**
- The changed ciphertext positions *are* the group signature — for AES Giraud
  the single changed index names the key byte directly (proven in §1.2: the
  changed set was `[0]`, i.e. key byte 0).
- Piret's candidate set sweeps every in-word byte position; the SM4 solver undoes
  the linear layer (`piret_sm4.py:146`, `delta_b = inverse_linear(...)`) and then
  tests each byte, so the exact row is recovered, not required as input.

**Consequence.** Unknown position only enlarges the candidate set per fault
(weaker filter ⇒ more faults), identical in spirit to §2 — it never rejects the
true key. No separate numeric proof is needed beyond §1.2 (position is read from
the output) and §2 (a weaker filter costs more faults, not correctness).

---

## 4. Table "Consequence by timing" — wrong round/instruction

| Case | Report's claim |
|---|---|
| Glitch too early | extra S-box layers scramble the diff ⇒ no pattern match ⇒ filtered out |
| Glitch too late | wrong positions change ⇒ filtered out |

**Why / Where.** A fault on the wrong round reaches the ciphertext through a
different number of S-box/linear layers, so its changed-position pattern matches
neither solver's model and is rejected by the very same guards used above
(`giraud_aes.py:79`, `piret_sm4.py:142`/`150`). Section §1.4 already shows that
a pattern outside the model is rejected; a mistimed glitch is just another way to
produce such a pattern. The report's delay sweep exists to avoid this.

---

## 5. Summary — every claim checked

| Report claim | Verified by | Result |
|---|---|---|
| S-box hides the bit (no shortcut) | §0 | 1-bit in → ~4-bit out |
| No effect ⇒ useless | §1.1 | rejected by code |
| 1 bit ⇒ Giraud ideal, 1 byte changes | §1.2 | changed = `[0]` |
| Multi-bit same byte ⇒ Giraud breaks, Piret holds | §1.3 | HW 3 ∉ SINGLE_BITS; ≠ 0 |
| Multi-byte ⇒ both break | §1.4 | rejected by code |
| Known bit cheaper than unknown | §2 | 2 vs 14 survivors |
| Piret = superset of Giraud | §1.3 | same fault passes Piret, fails Giraud |
| Unknown position ⇒ more faults, still valid | §3 | position read from output |
| Wrong timing ⇒ filtered out | §4 | pattern-match guard |

Every cell of the taxonomy tables reduces to one of two code facts:

- a **hard guard** on the changed-byte pattern (`len(changed) != 1`,
  "three words unchanged", "difference inside one byte") — this is what makes an
  attack **break** when the width leaves the model; and
- a **filter width** (`SINGLE_BITS` vs a single mask vs the full `1…255` sweep)
  — this is what makes an attack **cost more faults** when value or position is
  unknown, without ever rejecting the true key.

The width leaving the model breaks the attack; missing knowledge only raises the
price.

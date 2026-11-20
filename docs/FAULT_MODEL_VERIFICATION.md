# SM4 fault-model verification

The current target-input model changes one byte of X[i+1], X[i+2] or X[i+3]
before the subkey XOR. It also changes that word's copied output. The oldest
word X[i] is unchanged and cancels when comparing the newest output words.

Required observed checks, after peeling already recovered later rounds:

1. Exactly one copied word changes.
2. Exactly one byte changes in that word.
3. Inverse L of the newest-word XOR is nonzero and confined to that byte.
4. At least one of the 256 key-byte candidates satisfies the S-box differential.
5. Independent observations have a nonempty candidate intersection.

A pair passing these checks is model-compatible, not proven to have that physical
cause. Serial errors, output faults and correlated internal faults must not be
assumed equivalent to the intended state-input error.

The software tests construct compatible observations by design. Physical clock
and voltage campaigns record actual outputs and apply the same checks without
receiving the target key. Empty intersections stop the campaign. Candidate
subkeys remain model-dependent until independently checked; a full master-key
candidate is re-encrypted against the clean target baseline.

Run the software checks:
~~~powershell
python tools/test_sm4_input_dfa.py
python tools/test_sm4_glitch_campaigns.py
~~~

# Differential Fault Analysis (DFA)

## 1. Introduction

Differential Fault Analysis (DFA) is a cryptanalytic technique based on
comparing **correct and faulty executions** of a cryptographic algorithm.

The basic idea is simple:

1. Execute the cryptographic algorithm normally.
2. Obtain the correct ciphertext `C`.
3. Execute the same computation while introducing a fault.
4. Obtain a faulty ciphertext `F`.
5. Analyze the difference between `C` and `F`.

Conceptually:

                   Same Plaintext
                   Same Secret Key
                         |
               +---------+---------+
               |                   |
               v                   v
            Normal              Faulted
          Execution            Execution
               |                   |
               v                   v
               C                   F
               |                   |
               +---------+---------+
                         |
                         v
                   Compare C / F
                         |
                         v
                 Differential Analysis
                         |
                         v
                 Key / State hypotheses

The objective is not simply to cause an incorrect result.

The objective is to understand how the fault propagates through the
cipher and determine whether the observed difference provides
information about secret internal values.

---

# 2. Correct and Faulty Ciphertexts

Let:

    C = correct ciphertext

and:

    F = faulty ciphertext

Both executions use the same:

    Plaintext P
    Secret Key K

The only difference is that a fault is introduced during one execution.

    Normal:

    P + K
      |
      v
    Cipher
      |
      v
      C


    Faulted:

    P + K
      |
      v
    Cipher
      |
      X  <--- Fault
      |
      v
      F

The ciphertext difference can be represented as:

    ΔC = C XOR F

This difference provides information about how the injected error
propagated through the cipher.

---

# 3. Fault Model

DFA requires a **fault model**.

A fault model describes assumptions about the injected fault.

Important properties include:

## Location

Where is the fault introduced?

For example:

    - A state byte
    - A state word
    - A register
    - A specific round

## Time

When does the fault occur?

For example:

    Round 1
    Round 2
    ...
    Round N

## Width

How much data is affected?

For example:

    1 bit
    1 byte
    1 word

## Persistence

Is the fault:

    Transient   -> affects one execution

or:

    Persistent  -> remains active across multiple executions

The fault model determines how the resulting differences should be
interpreted.

---

# 4. DFA on AES

AES provides a useful example because its transformations have
well-defined propagation properties.

Consider AES-128 near its final rounds:

    Round 9

    SubBytes
       |
       v
    ShiftRows
       |
       v
    MixColumns   <--- important for fault propagation
       |
       v
    AddRoundKey
       |
       v

    Round 10

    SubBytes
       |
       v
    ShiftRows
       |
       v
    AddRoundKey
       |
       v
    Ciphertext

The final AES round does not contain `MixColumns`.

This makes faults introduced around the last MixColumns operation
particularly interesting for studying propagation.

---

# 5. Single-Byte Fault Example

Consider a simplified fault model in which one byte is corrupted
before a late MixColumns operation.

Before the fault:

    +----+
    | a0 |
    | a1 |
    | a2 |
    | a3 |
    +----+

After fault injection:

    +--------+
    | a0     |
    | a1 XOR e |  <--- fault
    | a2     |
    | a3     |
    +--------+

where `e` represents an unknown error value.

The faulty column then passes through MixColumns.

Because MixColumns combines the four bytes of a column, a difference
in one input byte propagates to multiple output bytes.

Conceptually:

          Single-byte fault
                 |
                 v
           +------------+
           | MixColumns |
           +------------+
                 |
                 v
          Fault propagation
                 |
          +------+------+------+------+
          | Δ0   | Δ1   | Δ2   | Δ3   |
          +------+------+------+------+

The resulting pattern is not arbitrary.

It is constrained by the mathematical structure of MixColumns.

---

# 6. Differential Propagation

Suppose the correct state is:

    S

and the faulty state is:

    S'

The difference is:

    ΔS = S XOR S'

As both states propagate through AES:

    S  -----> AES operations -----> C

    S' -----> AES operations -----> F

the differences evolve according to the transformations applied by
the cipher.

Linear operations such as MixColumns have predictable differential
behavior.

Nonlinear operations such as the AES S-box require hypotheses about
internal values or key bytes.

This combination allows DFA to constrain possible secret values.

---

# 7. Why the S-box Matters

Near the final AES round, the ciphertext depends on:

    State
      |
      v
    SubBytes
      |
      v
    ShiftRows
      |
      v
    AddRoundKey
      |
      v
    Ciphertext

Because `AddRoundKey` uses XOR, a candidate byte of the final round key
can be used to partially reverse the last round.

Conceptually:

    Ciphertext byte C[i]
            |
            XOR
            |
      Key hypothesis k
            |
            v
       S-box inverse
            |
            v
    Candidate internal value

The same process can be applied to the faulty ciphertext:

    Faulty byte F[i]
            |
            XOR
            |
      Same hypothesis k
            |
            v
       S-box inverse
            |
            v
    Candidate faulty value

The difference between these internal candidates must be compatible
with the assumed fault model.

Incorrect key hypotheses can therefore be rejected.

---

# 8. Key Candidate Filtering

The basic idea is:

    Candidate key byte
           |
           v
    Partially invert C
           |
           +----------------+
           |                |
           v                v
    Correct state      Faulty state
       candidate          candidate
           |                |
           +-------+--------+
                   |
                   v
             Compute difference
                   |
                   v
          Compatible with the
             fault model?
             /         \
           YES          NO
            |            |
            v            v
          Keep         Reject

Instead of trying every complete AES key, DFA uses the structure of the
fault to eliminate incompatible hypotheses.

---

# 9. Multiple Faulty Ciphertexts

One faulty ciphertext may leave several possible candidates.

Therefore, the experiment can be repeated:

    Correct ciphertext:

        C

    Faulty ciphertexts:

        F1
        F2
        F3
        ...
        Fn

Each pair:

    (C, F1)
    (C, F2)
    (C, F3)

provides additional constraints.

Conceptually:

    Initial candidates
          |
          v
      DFA with F1
          |
          v
    fewer candidates
          |
          v
      DFA with F2
          |
          v
    fewer candidates
          |
          v
      DFA with F3
          |
          v
    final candidate(s)

This is why collecting multiple controlled faulty executions can be
valuable.

---

# 10. Piret–Quisquater DFA

A classical example presented in the course is the DFA proposed by
Piret and Quisquater against AES.

The considered model introduces a fault in one byte before the last
relevant MixColumns operation.

The fault propagates through MixColumns and produces a structured
difference in several bytes.

The attacker then uses:

    Correct ciphertext C
              +
    Faulty ciphertext F
              +
    AES mathematical structure
              +
    Assumed fault model

to restrict possible values of the last-round key.

Conceptually:

           Fault
             |
             v
        AES internal state
             |
             v
         MixColumns
             |
             v
      Structured difference
             |
             v
       Final AES round
             |
        +----+----+
        |         |
        v         v
        C         F
        |         |
        +----+----+
             |
             v
      Differential equations
             |
             v
      Round-key candidates

Additional `(C, F)` pairs can further reduce the candidate set.

---

# 11. From Round Key to Master Key

A DFA may initially recover information about a **round key**, rather
than directly recovering the original AES master key.

For AES-128:

    Master Key
        |
        v
    Key Schedule
        |
        +--> Round Key 0
        +--> Round Key 1
        |
       ...
        |
        +--> Round Key 10

The AES-128 key schedule is reversible.

Therefore, knowledge of the complete final round key can allow the
original master key to be reconstructed.

Conceptually:

    Final Round Key
           |
           v
    Reverse Key Schedule
           |
           v
      AES Master Key

---

# 12. DFA Experimental Workflow

A useful workflow for studying DFA is:

    1. Implement / obtain AES
              |
              v
    2. Validate AES with test vectors
              |
              v
    3. Generate correct ciphertext C
              |
              v
    4. Define a fault model
              |
              v
    5. Introduce a controlled fault
              |
              v
    6. Generate faulty ciphertext F
              |
              v
    7. Compute differences
              |
              v
    8. Model fault propagation
              |
              v
    9. Test key hypotheses
              |
              v
    10. Analyze remaining candidates

Before using a physical fault injector, the propagation model can be
studied through controlled software simulations.

---

# 13. Software Fault Model vs. Physical Fault Injection

It is useful to distinguish two stages.

## Software Fault Simulation

A controlled internal value is deliberately modified in an experimental
implementation.

Example:

    Correct:

    state[i] = 0x37

    Simulated fault:

    state[i] = 0x3F

This helps study:

- fault propagation;
- differential patterns;
- DFA algorithms;
- key-candidate filtering.

## Physical Fault Injection

A physical perturbation causes the target hardware to produce an
incorrect computation.

Possible physical mechanisms include:

- voltage glitches;
- clock glitches;
- electromagnetic fault injection;
- laser fault injection.

The resulting physical fault may then be compared with the theoretical
fault model.

Conceptually:

    Theoretical / Software Model
               |
               v
        Expected behavior
               |
               +------------------+
                                  |
                                  v
                         Physical experiment
                                  |
                                  v
                          Observed behavior
                                  |
                                  v
                              Compare

---

# 14. Why Start with AES Before SM4?

AES is useful as a first case study because classical DFA techniques and
well-understood propagation models are available.

The learning process is therefore:

    AES architecture
          |
          v
    AES fault propagation
          |
          v
    Differential Fault Analysis
          |
          v
    Understand C vs. F analysis
          |
          v
    Understand key hypotheses
          |
          v
    Validate the methodology
          |
          v
    Transfer the knowledge to SM4

AES and SM4 have different internal structures.

Therefore, the exact AES fault equations cannot simply be copied to
SM4.

Instead, AES provides a reference example for understanding the
general methodology.

---

# 15. Connection to SM4

For SM4, the same high-level DFA principle applies:

    Correct execution
          |
          v
          C

    Faulted execution
          |
          v
          F

Then:

    C vs. F
       |
       v
    Analyze differential propagation
       |
       v
    Relate differences to SM4 operations
       |
       v
    Evaluate possible information leakage
       |
       v
    Study implementation robustness

However, the internal propagation must be derived according to the
SM4 round structure:

    X[i+4] =
        X[i] XOR
        T(X[i+1] XOR X[i+2] XOR X[i+3] XOR rk[i])

Therefore:

> AES is the learning and validation case.

> SM4 is the target cipher of the final project.

---

# 16. Key Concepts to Remember

| Concept | Meaning |
|---|---|
| `C` | Correct ciphertext |
| `F` | Faulty ciphertext |
| `C XOR F` | Observable ciphertext difference |
| Fault model | Assumptions about location, timing and effect of the fault |
| Fault propagation | How an internal error evolves through the cipher |
| DFA | Differential Fault Analysis |
| Key hypothesis | Candidate secret value tested against the observed difference |
| MixColumns | AES diffusion operation important for fault propagation |
| S-box | Nonlinear transformation involved in key-dependent differential analysis |
| Round key | Key material used during one AES round |
| Master key | Original secret key |

---

# 17. Main Idea

The most important concept is:

    Inject a controlled fault
              |
              v
      Obtain faulty output
              |
              v
    Compare with correct output
              |
              v
    Understand fault propagation
              |
              v
       Build constraints
              |
              v
      Eliminate incompatible
         key hypotheses

DFA does not recover a key simply because the ciphertext is incorrect.

The attack becomes meaningful when the relationship between the
injected fault, the cipher structure, and the resulting ciphertext
difference can be modeled.
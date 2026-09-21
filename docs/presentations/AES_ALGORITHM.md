# AES — Advanced Encryption Standard

## 1. Introduction

AES (Advanced Encryption Standard) is a **symmetric block cipher** widely used to protect digital information.

AES operates on fixed-size blocks of:

- **Block size:** 128 bits
- **Key sizes:** 128, 192, or 256 bits

The number of encryption rounds depends on the key size:

| Key Size | Number of Rounds |
|---|---:|
| AES-128 | 10 |
| AES-192 | 12 |
| AES-256 | 14 |

For the initial study of fault injection, we focus on **AES-128**.

At a high level:

    Plaintext (128 bits)
            |
            v
        +-------+
        |  AES  | <--- Secret Key (128 bits)
        +-------+
            |
            v
    Ciphertext (128 bits)

---

## 2. AES State

AES does not process the 128-bit block as a single integer.

The 16 input bytes are organized into a **4 × 4 byte matrix**, called the **State**.

Conceptually:

    +------+------+------+------+
    | s00  | s01  | s02  | s03  |
    +------+------+------+------+
    | s10  | s11  | s12  | s13  |
    +------+------+------+------+
    | s20  | s21  | s22  | s23  |
    +------+------+------+------+
    | s30  | s31  | s32  | s33  |
    +------+------+------+------+

Each element contains one byte:

    8 bits × 16 bytes = 128 bits

The State is transformed throughout the AES rounds.

---

## 3. AES-128 Encryption Structure

AES-128 consists of:

1. Initial `AddRoundKey`
2. 9 main rounds
3. 1 final round

The general structure is:

    Plaintext
        |
        v
    AddRoundKey
        |
        v
    +----------------+
    | Round 1        |
    | SubBytes       |
    | ShiftRows      |
    | MixColumns     |
    | AddRoundKey    |
    +----------------+
        |
        v
       ...
        |
        v
    +----------------+
    | Round 9        |
    | SubBytes       |
    | ShiftRows      |
    | MixColumns     |
    | AddRoundKey    |
    +----------------+
        |
        v
    +----------------+
    | Round 10       |
    | SubBytes       |
    | ShiftRows      |
    | AddRoundKey    |
    +----------------+
        |
        v
    Ciphertext

An important detail is:

> The final AES round does **not** contain MixColumns.

This property is particularly relevant when studying fault propagation
near the final rounds.

---

# 4. SubBytes

`SubBytes` is the nonlinear transformation of AES.

Each byte of the State is independently replaced using an **S-box**.

Conceptually:

    Input byte
        |
        v
    +---------+
    |  S-box  |
    +---------+
        |
        v
    Output byte

For the complete State:

    +------+------+------+------+
    | s00  | s01  | s02  | s03  |
    +------+------+------+------+
       |      |      |      |
       v      v      v      v
      S()    S()    S()    S()

The same operation is applied to all 16 bytes.

The S-box introduces **nonlinearity**, which is fundamental to the
security of AES.

---

# 5. ShiftRows

`ShiftRows` cyclically shifts the rows of the State.

The rows are shifted by different offsets:

- Row 0: no shift
- Row 1: shift left by 1 byte
- Row 2: shift left by 2 bytes
- Row 3: shift left by 3 bytes

Before:

    a0  a1  a2  a3
    b0  b1  b2  b3
    c0  c1  c2  c3
    d0  d1  d2  d3

After ShiftRows:

    a0  a1  a2  a3
    b1  b2  b3  b0
    c2  c3  c0  c1
    d3  d0  d1  d2

ShiftRows moves bytes between columns and contributes to the diffusion
of AES.

---

# 6. MixColumns

`MixColumns` operates independently on each column of the AES State.

Each column contains four bytes:

    +----+
    | a0 |
    | a1 |
    | a2 |
    | a3 |
    +----+

The column is transformed using matrix multiplication over the finite
field GF(2^8):

    | 02 03 01 01 |   | a0 |
    | 01 02 03 01 | x | a1 |
    | 01 01 02 03 |   | a2 |
    | 03 01 01 02 |   | a3 |

This produces four new bytes.

Conceptually:

    One input byte changes
             |
             v
       +------------+
       | MixColumns |
       +------------+
             |
             v
    Multiple output bytes
       may be affected

This diffusion property is especially important for **Differential
Fault Analysis (DFA)**.

---

# 7. AddRoundKey

`AddRoundKey` combines the current State with a round key using XOR.

    State
      |
      +------+
             |
             XOR ----> New State
             |
      +------+
      |
    Round Key

Mathematically:

    State' = State XOR RoundKey

Because XOR is reversible:

    A XOR K XOR K = A

The round keys are derived from the original AES key through the
AES key schedule.

---

# 8. AES Key Schedule

AES-128 starts with a 128-bit master key.

The key schedule expands this key to generate the round keys required
during encryption.

For AES-128:

    Master Key
        |
        v
    Key Expansion
        |
        +---- Round Key 0
        |
        +---- Round Key 1
        |
        +---- Round Key 2
        |
       ...
        |
        +---- Round Key 10

Each round key contains 128 bits.

Therefore, AES-128 uses:

    11 × 128-bit round keys

including the initial key addition.

---

# 9. Complete AES-128 Round

A normal AES round can be represented as:

    State
      |
      v
    SubBytes
      |
      v
    ShiftRows
      |
      v
    MixColumns
      |
      v
    AddRoundKey
      |
      v
    Next State

Rounds 1 through 9 follow this structure.

The final round is:

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

Again:

> There is no MixColumns in the final round.

---

# 10. Why AES Is Useful for Learning Fault Injection

AES has been extensively studied in the context of fault attacks.

Its structured transformations make it possible to study how an
internal error propagates through the algorithm.

For example, consider a fault affecting one byte near the final
rounds:

    Correct State
         |
         v
       Fault
         X
         |
         v
    MixColumns
         |
         v
    Fault propagation
         |
         v
    Later operations
         |
         v
    Faulty Ciphertext

The difference between the correct and faulty ciphertexts can then be
analyzed.

This forms the basis of **Differential Fault Analysis (DFA)**.

---

# 11. AES and the PFE Workflow

AES is used as an introductory case before studying fault injection
against SM4.

The workflow is:

    Understand AES
          |
          v
    Understand its round structure
          |
          v
    Understand fault propagation
          |
          v
    Study DFA on AES
          |
          v
    Validate the fault-analysis methodology
          |
          v
    Study SM4
          |
          v
    Adapt the methodology to SM4

---

# 12. Key Concepts to Remember

| Property | AES-128 |
|---|---|
| Cipher type | Symmetric block cipher |
| Block size | 128 bits |
| Key size | 128 bits |
| State | 4 × 4 bytes |
| Number of rounds | 10 |
| Nonlinear operation | SubBytes |
| Byte permutation | ShiftRows |
| Diffusion operation | MixColumns |
| Key operation | AddRoundKey |
| Final round MixColumns | No |

The four transformations to remember are:

    SubBytes
       ↓
    ShiftRows
       ↓
    MixColumns
       ↓
    AddRoundKey
# SM4 Block Cipher

## 1. Introduction

SM4 is a **symmetric block cipher** designed for data encryption.

It operates on:

- **Block size:** 128 bits
- **Key size:** 128 bits
- **Number of rounds:** 32
- **Round keys:** 32 round keys of 32 bits each

The same secret key is used for encryption and decryption.

At a high level:

    Plaintext (128 bits)
            |
            v
        +-------+
        |  SM4  | <--- Secret Key (128 bits)
        +-------+
            |
            v
    Ciphertext (128 bits)

SM4 consists of two main processes:

1. **Key expansion**, which generates the 32 round keys.
2. **Encryption**, which transforms a 128-bit plaintext block into a
   128-bit ciphertext block through 32 rounds.

---

## 2. Data Representation

A 128-bit plaintext block is divided into four 32-bit words:

    Plaintext (128 bits)

    +----------+----------+----------+----------+
    |    X0    |    X1    |    X2    |    X3    |
    | 32 bits  | 32 bits  | 32 bits  | 32 bits  |
    +----------+----------+----------+----------+

These four words are used as the initial state of the algorithm.

The 128-bit secret key is also divided into four 32-bit words:

    Secret Key (128 bits)

    +----------+----------+----------+----------+
    |   MK0    |   MK1    |   MK2    |   MK3    |
    | 32 bits  | 32 bits  | 32 bits  | 32 bits  |
    +----------+----------+----------+----------+

The master key is used to generate 32 round keys:

    rk0, rk1, rk2, ..., rk31

---

## 3. Encryption Structure

SM4 performs **32 rounds**.

For each round `i`, a new 32-bit word is generated:

    Xi+4 = Xi XOR T(Xi+1 XOR Xi+2 XOR Xi+3 XOR rki)

where:

- `Xi` represents a 32-bit state word.
- `rki` is the 32-bit round key for round `i`.
- `XOR` is the bitwise exclusive-OR operation.
- `T()` is the SM4 nonlinear transformation.

Therefore, one round can be represented as:

    Xi+1 --------+
                 |
    Xi+2 --------+--- XOR ---+
                 |           |
    Xi+3 --------+           |
                             +--- XOR ---> T() ---+
    rki ---------------------+                   |
                                                 +--- XOR ---> Xi+4
    Xi ------------------------------------------+

After calculating `Xi+4`, the algorithm moves to the next round.

For example:

    Initial state:

    X0   X1   X2   X3
     |    |    |    |
     +----+----+----+
              |
           Round 0
              |
              v
             X4

    Next state:

    X1   X2   X3   X4
              |
           Round 1
              |
              v
             X5

This process continues until all 32 rounds have been executed.

---

## 4. The T Transformation

The `T()` transformation is one of the most important parts of SM4.

It consists of two stages:

    Input
      |
      v
    +-------------------------+
    | Nonlinear transformation|
    |        S-box            |
    +-------------------------+
      |
      v
    +-------------------------+
    | Linear transformation L |
    +-------------------------+
      |
      v
    Output

Mathematically:

    T(B) = L(tau(B))

where:

- `tau()` is the nonlinear S-box transformation.
- `L()` is the linear transformation.

---

## 5. Nonlinear Transformation: S-box

The input to `T()` is a 32-bit word.

It is divided into four bytes:

    B = (b0, b1, b2, b3)

Each byte passes independently through the SM4 S-box:

    b0 ---> S-box ---> S(b0)
    b1 ---> S-box ---> S(b1)
    b2 ---> S-box ---> S(b2)
    b3 ---> S-box ---> S(b3)

The results are combined again into a 32-bit word.

The S-box introduces **nonlinearity** into the cipher, which is an
essential property for cryptographic security.

Conceptually:

    32-bit input
         |
         v
    +----+----+----+----+
    | b0 | b1 | b2 | b3 |
    +----+----+----+----+
      |    |    |    |
      v    v    v    v
     S()  S()  S()  S()
      |    |    |    |
      +----+----+----+
              |
              v
         32-bit output

---

## 6. Linear Transformation

After the S-box substitution, the resulting 32-bit word `B` passes
through the linear transformation `L`.

The encryption linear transformation is:

    L(B) = B
           XOR (B <<< 2)
           XOR (B <<< 10)
           XOR (B <<< 18)
           XOR (B <<< 24)

where `<<<` represents a **32-bit circular left rotation**.

For example:

    B
    |
    +---- B <<< 2
    |
    +---- B <<< 10
    |
    +---- B <<< 18
    |
    +---- B <<< 24
    |
    v
    XOR
    |
    v
    L(B)

The combination of the S-box and the linear transformation forms:

    T(B) = L(tau(B))

---

## 7. Complete SM4 Round

A complete round can therefore be expanded as:

    Xi+1 ----+
             |
    Xi+2 ----+--- XOR ---+
             |           |
    Xi+3 ----+           |
                         +--- XOR ---> B
    rki -----------------+             |
                                       v
                                     S-box
                                       |
                                       v
                                      tau
                                       |
                                       v
                               Linear transformation
                                       |
                                       v
                                      T(B)
                                       |
    Xi --------------------------------+--- XOR ---> Xi+4

Or mathematically:

    B = Xi+1 XOR Xi+2 XOR Xi+3 XOR rki

    Xi+4 = Xi XOR T(B)

This operation is repeated for all 32 rounds.

---

## 8. Final Output

After the 32 rounds, the algorithm has generated:

    X32, X33, X34, X35

SM4 reverses their order to produce the ciphertext:

    Ciphertext = (X35, X34, X33, X32)

Therefore:

    X0 X1 X2 X3
        |
        v
    +-----------+
    | Round 0   | <--- rk0
    +-----------+
        |
        v
    +-----------+
    | Round 1   | <--- rk1
    +-----------+
        |
       ...
        |
        v
    +-----------+
    | Round 31  | <--- rk31
    +-----------+
        |
        v
    X32 X33 X34 X35
        |
        v
    Reverse order
        |
        v
    X35 X34 X33 X32
        |
        v
    Ciphertext

---

## 9. Key Expansion

The 128-bit master key cannot be directly used as a single key for
every round.

Instead, SM4 generates **32 different round keys**.

The master key is initially divided into:

    MK0, MK1, MK2, MK3

Four fixed system parameters, called `FK`, are first applied:

    K0 = MK0 XOR FK0
    K1 = MK1 XOR FK1
    K2 = MK2 XOR FK2
    K3 = MK3 XOR FK3

The following words are then generated recursively.

For each round `i`:

    Ki+4 = Ki XOR T'(Ki+1 XOR Ki+2 XOR Ki+3 XOR CKi)

and:

    rki = Ki+4

where:

- `CKi` is a fixed constant associated with round `i`.
- `T'()` is a transformation used specifically for key expansion.

Therefore:

    Master Key
        |
        v
    MK0 MK1 MK2 MK3
        |
       XOR
        |
    FK0 FK1 FK2 FK3
        |
        v
    K0 K1 K2 K3
        |
        v
    Key Expansion
        |
        +----> rk0
        +----> rk1
        +----> rk2
        |
       ...
        |
        +----> rk31

---

## 10. Key Expansion Transformation

The key expansion transformation is similar to the encryption
transformation, but uses a different linear operation.

It is defined as:

    T'(B) = L'(tau(B))

with:

    L'(B) = B
            XOR (B <<< 13)
            XOR (B <<< 23)

Therefore, it is important to distinguish:

### Encryption

    T(B) = L(tau(B))

    L(B) = B
           XOR (B <<< 2)
           XOR (B <<< 10)
           XOR (B <<< 18)
           XOR (B <<< 24)

### Key Expansion

    T'(B) = L'(tau(B))

    L'(B) = B
            XOR (B <<< 13)
            XOR (B <<< 23)

Both transformations use the same S-box but different linear
transformations.

---

## 11. Decryption

One useful characteristic of SM4 is that decryption uses essentially
the same round structure as encryption.

The main difference is the order of the round keys.

Encryption uses:

    rk0, rk1, rk2, ..., rk30, rk31

Decryption uses:

    rk31, rk30, rk29, ..., rk1, rk0

Therefore, the same core implementation can often be reused by
reversing the round-key order.

---

## 12. Complete SM4 Overview

The complete encryption process can be summarized as:

    +-------------------+
    | 128-bit Secret Key|
    +-------------------+
              |
              v
       +--------------+
       | Key Expansion|
       +--------------+
              |
              v
       rk0 ... rk31
              |
              |
    +-------------------+
    | 128-bit Plaintext |
    +-------------------+
              |
              v
       X0 X1 X2 X3
              |
              v
       +-------------+
       | 32 Rounds   |
       |             |
       | XOR         |
       | S-box       |
       | Rotations   |
       | Round Keys  |
       +-------------+
              |
              v
      X32 X33 X34 X35
              |
              v
        Reverse Order
              |
              v
    +-------------------+
    |128-bit Ciphertext |
    +-------------------+

---

## 13. SM4 and the Fault Injection Project

The objective of this project is not only to implement SM4, but also
to study the robustness of its embedded implementation against
**fault injection**.

A normal execution can be represented as:

    Plaintext
        |
        v
      SM4
        |
    +---+---+---+---+
    | Round 0       |
    | Round 1       |
    | ...           |
    | Round 31      |
    +---------------+
        |
        v
    Correct Ciphertext

A faulted execution can conceptually be represented as:

    Plaintext
        |
        v
      SM4
        |
    +---------------+
    | Round 0       |
    | ...           |
    | Round N   <--- Fault
    | ...           |
    | Round 31      |
    +---------------+
        |
        v
    Faulty Ciphertext

The project studies how controlled perturbations can affect the
execution of SM4 and whether these effects can lead to security
weaknesses.

The main research workflow is:

    Understand SM4
          |
          v
    Analyze the embedded implementation
          |
          v
    Identify fault-sensitive operations
          |
          v
    Define an experimental methodology
          |
          v
    Perform controlled fault experiments
          |
          v
    Compare correct and faulty executions
          |
          v
    Analyze the security impact
          |
          v
    Investigate possible countermeasures

Possible countermeasures may then be studied to detect or reduce the
impact of injected faults.

---

## 14. Key Concepts to Remember

| Property | SM4 |
|---|---|
| Cipher type | Symmetric block cipher |
| Block size | 128 bits |
| Key size | 128 bits |
| Number of rounds | 32 |
| Initial state | Four 32-bit words |
| Round keys | 32 x 32-bit |
| Nonlinear operation | S-box |
| Encryption linear operation | Rotations by 2, 10, 18 and 24 bits |
| Key-schedule linear operation | Rotations by 13 and 23 bits |
| Decryption | Same structure with reversed round keys |

The central round equation is:

    Xi+4 = Xi XOR T(Xi+1 XOR Xi+2 XOR Xi+3 XOR rki)

Understanding this equation, the S-box, the linear transformation,
and the key schedule provides the foundation for analyzing the
behavior of SM4 under fault injection.
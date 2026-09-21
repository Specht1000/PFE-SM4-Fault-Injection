# Fault Injection Attacks

## 1. Introduction

Fault Injection (FI) is a class of hardware attacks in which an attacker
intentionally perturbs the execution of a target device in order to cause
computational errors.

Unlike Side-Channel Attacks (SCA), which observe physical information
leaked by a device without intentionally modifying its execution, fault
injection attacks actively disturb the target.

Conceptually:

    Normal execution:

    Plaintext + Key
           |
           v
      Cryptosystem
           |
           v
    Correct output C


    Faulted execution:

    Plaintext + Key
           |
           v
      Cryptosystem
           |
           | <--- Physical perturbation
           X
           |
           v
     Faulty output F

The difference between the correct and faulty executions can then be
analyzed to understand the effect of the injected fault.

In cryptographic systems, fault injection may be used to:

- Bypass security checks
- Obtain unauthorized privileges
- Disable security countermeasures
- Disturb cryptographic computations
- Potentially recover secret information

---

## 2. Fault Injection vs. Side-Channel Attacks

Hardware attacks can be divided into two important families:

### Side-Channel Attack

A Side-Channel Attack observes physical quantities produced during the
normal execution of a device.

Examples include:

- Power consumption
- Electromagnetic emissions
- Execution time
- Optical emissions
- Temperature

Conceptually:

    Cryptographic execution
             |
             v
       Physical leakage
             |
             v
          Observe
             |
             v
       Analyze leakage

The computation itself is not intentionally modified.

### Fault Injection Attack

A Fault Injection Attack intentionally perturbs the target during its
execution.

    Cryptographic execution
             |
             v
       Inject a fault
             |
             v
      Incorrect internal
          computation
             |
             v
        Faulty output
             |
             v
          Analysis

Therefore:

    Side-Channel Attack = Observe the execution

    Fault Injection     = Disturb the execution

---

## 3. Basic Principle

Digital circuits perform computations using logic gates, registers,
flip-flops, memories, and other electronic components.

Under normal conditions, a value may be correctly stored as:

    Expected:

    10110110

A physical perturbation may cause an incorrect value to be captured:

    Expected:  10110110
    Faulted:   10111110
                   ^
                changed bit

The software may therefore continue executing with corrupted data.

This fault can then propagate through subsequent operations.

For example:

    Correct state
         |
         v
      Round N
         |
         v
      Round N+1
         |
         v
    Correct output


    Faulted state
         |
         v
      Round N
         |
         X  <--- Fault
         |
         v
      Round N+1
         |
         v
     Faulty output

The objective is not simply to crash the device, but to study how
controlled faults affect the computation.

---

## 4. Fault Injection Platform

A typical experimental fault-injection platform may contain:

- Oscilloscope
- Side-channel sensor
- Pattern detector / trigger generator
- Pulse generator
- Fault injector
- Positioning system for the injector

A simplified architecture is:

                     +----------------+
                     |  Oscilloscope  |
                     +-------+--------+
                             |
                             |
    +-------------+     +----v----+
    |   Trigger   |---->|  Target |
    |   System    |     |  Device |
    +------+------+     +----+----+
           |                  ^
           |                  |
           v                  |
    +-------------+     +-----+------+
    |    Pulse    |---->|  Injector  |
    |  Generator  |     +------------+
    +-------------+

The trigger is particularly important because the perturbation must be
synchronized with the execution of the target operation.

---

## 5. Main Fault Injection Techniques

Several physical phenomena can be used to generate faults.

The main techniques presented in the course are:

- LFI  - Laser Fault Injection
- EMFI - Electromagnetic Fault Injection
- BBI  - Body Bias Fault Injection
- PGFI - Power Glitch Fault Injection
- CGFI - Clock Glitch Fault Injection

Each technique perturbs the target through a different physical
mechanism.

---

## 6. Laser Fault Injection (LFI)

Laser Fault Injection uses a laser to locally perturb the integrated
circuit.

The course describes the use of an infrared laser with a wavelength
around:

    1064 nm

The technique generally requires access to the backside of the
integrated circuit and therefore requires decapsulation.

One important advantage of LFI is its high spatial and temporal
resolution.

Conceptually:

             Laser
               |
               v
        +--------------+
        |     Chip     |
        |              |
        |      X       | <--- Targeted region
        |              |
        +--------------+

The laser can generate local photocurrents inside semiconductor
junctions.

The sequence can be represented as:

    Laser pulse
         |
         v
    PN junction
         |
         v
    Photocurrent
         |
         v
    Transient electrical perturbation
         |
         v
    Logic value temporarily disturbed
         |
         v
    Incorrect value may be sampled
         |
         v
       FAULT

If the transient perturbation is sampled by a flip-flop at the
appropriate clock edge, an incorrect value can enter the digital
computation and propagate through the system.

---

## 7. Electromagnetic Fault Injection (EMFI)

Electromagnetic Fault Injection uses an electromagnetic probe placed
close to the target device.

A pulse generator drives the probe:

    Pulse Generator
           |
           v
       EM Probe
        )))
        )))
        )))
           |
           v
    +-------------+
    | Target Chip |
    +-------------+

According to the course, EMFI probes can range approximately from:

    50 um to 2 mm

One important advantage is that the target generally does not need to
be decapsulated, except in situations where the package prevents the
electromagnetic coupling.

The electromagnetic pulse can induce parasitic currents in the target,
particularly through its power and ground networks.

The process can be summarized as:

    EM pulse
       |
       v
    Electromagnetic coupling
       |
       v
    Local parasitic currents
       |
       v
    Internal voltage perturbation
       |
       v
    Incorrect sampling by flip-flops
       |
       v
      FAULT

---

## 8. Power Glitch Fault Injection (PGFI)

Power Glitch Fault Injection perturbs the power supply of the target
device for a short period.

Normal supply:

    VDD
     |
     |------------------------------

Faulted supply:

    VDD
     |
     |-------------\__/-------------
                    ^
                  glitch

The temporary disturbance may cause some internal digital operations
to behave incorrectly.

The resulting fault may affect data, control flow, or other internal
operations depending on the target and the timing of the perturbation.

---

## 9. Clock Glitch Fault Injection (CGFI)

Clock Glitch Fault Injection intentionally perturbs the clock signal
used by a synchronous digital circuit.

Normal clock:

       +---+     +---+     +---+
    ---+   +-----+   +-----+   +---

Faulted clock:

       +---+  +-+  +---+
    ---+   +--+ +--+   +------------

                ^
              glitch

Digital logic requires enough time between clock edges for signals to
propagate and stabilize.

A clock perturbation may cause a register to sample a value before the
combinational logic has produced the expected result.

This can result in an incorrect internal state.

---

## 10. Timing and Fault Injection

Timing is a fundamental aspect of fault injection.

Suppose a cryptographic algorithm executes several rounds:

    Time ---------------------------------------------------->

    Round 0 | Round 1 | Round 2 | ... | Round N | ... | Final
                                         ^
                                         |
                                      target

The attacker attempts to synchronize the perturbation with a specific
part of the execution.

This is one reason why experimental platforms use trigger systems.

Conceptually:

    Trigger
       |
       v
    Wait for target operation
       |
       v
    Generate pulse
       |
       v
    Inject perturbation
       |
       v
    Observe result

The same physical perturbation applied at different moments may
produce completely different effects.

---

## 11. Fault Propagation

Injecting a fault is only the first part of the analysis.

The next question is:

> How does the fault propagate through the algorithm?

Suppose an internal state should contain:

    X = 0xA52F10C8

A fault changes it to:

    X' = 0xA52F10C9

The following cryptographic operations now receive `X'` instead of
`X`.

Therefore:

    Correct execution:

    X
    |
    v
    Operation 1
    |
    v
    Operation 2
    |
    v
    C


    Faulted execution:

    X'
    |
    v
    Operation 1
    |
    v
    Operation 2
    |
    v
    F

where:

    C = correct ciphertext
    F = faulty ciphertext

The relationship between `C` and `F` can provide information about
how the fault propagated through the cryptographic algorithm.

---

## 12. Differential Fault Analysis (DFA)

Differential Fault Analysis (DFA) analyzes the differences between
correct and faulty cryptographic computations.

The basic principle is:

                 Same input
                 Same key
                    |
             +------+------+
             |             |
             v             v
          Normal        Faulted
        execution      execution
             |             |
             v             v
             C             F
             |             |
             +------+------+
                    |
                    v
              Compare C and F
                    |
                    v
           Analyze fault propagation
                    |
                    v
        Restrict possible internal
        states or key hypotheses

A mathematical model of the cryptographic algorithm is used to
determine which faults could explain the observed difference.

The important idea is:

    Known:
        plaintext/ciphertext
        correct output C
        faulty output F
        cryptographic algorithm

    Unknown:
        secret key
        exact internal state

    Analysis:
        determine which hypotheses are
        compatible with the observed fault

Additional faulty executions may further reduce the number of
compatible hypotheses.

---

## 13. DFA Example: AES

The course introduces Differential Fault Analysis using AES as an
example.

One example is the Piret and Quisquater DFA.

The considered fault is introduced into one byte before a MixColumns
operation near the end of AES.

Conceptually:

    Internal AES state
          |
          X <--- Fault in one byte
          |
          v
      MixColumns
          |
          v
    Fault propagation
          |
          v
    Multiple affected bytes
          |
          v
    Faulty ciphertext F

Because MixColumns has a known mathematical structure, the propagation
of the fault is constrained.

The correct ciphertext `C` and faulty ciphertext `F` can therefore be
used to test hypotheses about the final-round key.

The course shows that multiple `(C, F)` pairs progressively reduce the
number of possible key candidates.

This illustrates an important principle:

> A computational error is not automatically useful. It becomes
> useful when its propagation can be modeled and related to secret
> information.

---

## 14. Fault Injection Applied to SM4

The same general reasoning motivates the study of fault injection
against SM4.

SM4 is a 128-bit symmetric block cipher with 32 rounds.

A normal execution can be represented as:

    Plaintext
        |
        v
     Round 0
        |
        v
     Round 1
        |
       ...
        |
        v
     Round 31
        |
        v
    Ciphertext C

A faulted execution can conceptually be represented as:

    Plaintext
        |
        v
     Round 0
        |
       ...
        |
        v
     Round N
        |
        X <--- Injected fault
        |
        v
     Round N+1
        |
       ...
        |
        v
     Round 31
        |
        v
    Faulty Ciphertext F

The central SM4 round equation is:

    X[i+4] =
        X[i] XOR
        T(X[i+1] XOR X[i+2] XOR X[i+3] XOR rk[i])

A fault affecting an intermediate value can therefore propagate
through subsequent rounds.

For example:

    Correct:

    X26 = correct intermediate state
           |
           v
       later rounds
           |
           v
           C


    Faulted:

    X26' = corrupted intermediate state
            |
            v
        later rounds
            |
            v
            F

The objective of the project is to study this behavior systematically.

---

## 15. Experimental Methodology for SM4

A general research workflow for studying SM4 fault injection is:

    1. Understand SM4
              |
              v
    2. Obtain a correct reference implementation
              |
              v
    3. Validate normal executions
              |
              v
    4. Identify sensitive operations
              |
              v
    5. Define fault models
              |
              v
    6. Perform controlled experiments
              |
              v
    7. Collect correct and faulty outputs
              |
              v
    8. Analyze fault propagation
              |
              v
    9. Evaluate the security impact
              |
              v
    10. Investigate countermeasures

Before performing physical experiments, fault models can also be
studied at software level to understand how modifications of internal
states propagate through SM4.

The physical fault-injection technique used in the final experimental
platform depends on the target hardware and experimental setup.

---

## 16. Fault Models

To analyze fault injection systematically, a fault can be described
using several properties.

### Location

Where does the fault occur?

Examples:

    - Intermediate state
    - Register
    - Round computation
    - Key-related computation

### Time

When does the fault occur?

    Round 0
    Round 1
    ...
    Round 30
    Round 31

### Width

How much information is affected?

Examples:

    - One bit
    - One byte
    - One word
    - Multiple values

### Effect

What happens to the affected value?

Conceptually:

    Original value
         |
         +----> bit modification
         |
         +----> corrupted value
         |
         +----> incorrect computation

The exact fault models relevant to SM4 must be determined from the
implementation and experimental setup.

---

## 17. What Makes a Fault Interesting?

Not every fault represents a useful security vulnerability.

For example:

    Fault
      |
      v
    Device crashes
      |
      v
    No cryptographic output

This demonstrates that the system is sensitive to the perturbation,
but it does not necessarily reveal useful cryptographic information.

A more interesting situation is:

    Fault
      |
      v
    Cryptographic execution continues
      |
      v
    Faulty output F
      |
      v
    Predictable fault propagation
      |
      v
    Information about internal computation
      |
      v
    Potential security impact

Therefore, the objective is not simply to generate as many errors as
possible.

The objective is to understand:

- Where the fault occurred
- How the fault affected the computation
- How the error propagated
- Whether the effect is reproducible
- Whether the effect has security consequences

---

## 18. Countermeasures

Once sensitive behaviors are identified, countermeasures can be
investigated.

The general objective of a fault-injection countermeasure is to:

    prevent faults

            or

    detect faults

            or

    prevent faulty results from being used

A simplified defensive architecture could be:

    Cryptographic computation
             |
             v
       Result verification
             |
        +----+----+
        |         |
      Valid     Invalid
        |         |
        v         v
      Output    Reject

The appropriate countermeasure depends on the fault model, target
architecture, performance constraints, and implementation.

---

## 19. Fault Injection Research Workflow

The complete idea can be summarized as:

                Target cryptographic device
                          |
                          v
                    Normal execution
                          |
                          v
                  Reference output C
                          |
                          |
            +-------------+-------------+
            |                           |
            v                           v
      Physical perturbation       Fault model
            |                           |
            +-------------+-------------+
                          |
                          v
                   Faulty execution
                          |
                          v
                  Faulty output F
                          |
                          v
                     Compare C/F
                          |
                          v
                 Analyze propagation
                          |
                          v
                Evaluate security impact
                          |
                          v
                Study countermeasures

---

## 20. Key Concepts to Remember

| Concept | Description |
|---|---|
| Fault Injection | Intentional perturbation of a device during execution |
| Side-Channel Attack | Observation of physical leakage without intentionally modifying execution |
| LFI | Laser Fault Injection |
| EMFI | Electromagnetic Fault Injection |
| PGFI | Power Glitch Fault Injection |
| CGFI | Clock Glitch Fault Injection |
| BBI | Body Bias Fault Injection |
| Trigger | Synchronizes the perturbation with the target computation |
| Correct ciphertext `C` | Output produced by a normal execution |
| Faulty ciphertext `F` | Output produced after a fault |
| Fault propagation | Evolution of an injected error through later computations |
| DFA | Differential Fault Analysis |
| Countermeasure | Mechanism designed to prevent, detect, or mitigate fault effects |

---

## 21. Main Idea

The fundamental principle of fault injection can be summarized as:

    Perturb
       |
       v
    Create a fault
       |
       v
    Observe its effect
       |
       v
    Model its propagation
       |
       v
    Analyze the security impact

For the SM4 project, the central question is therefore not simply:

> "Can SM4 be made to produce an incorrect result?"

The more important questions are:

> "Which parts of the implementation are sensitive to faults?"

> "How do these faults propagate through SM4?"

> "Can the resulting behavior compromise the security of the
> implementation?"

> "How can these faults be detected or mitigated?"
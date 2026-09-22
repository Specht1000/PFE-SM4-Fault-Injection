# PFE — SM4 Fault Injection

Final-year project studying fault injection in cryptographic implementations,
starting with AES-128 on a ChipWhisperer-Lite STM32F303 target and progressing
toward SM4.

- [Hardware AES experiment](experiments/chipwhisperer_aes/README.md): firmware,
  compilation, programming, known-answer verification, and baseline power capture.
- [PowerShell commands](experiments/chipwhisperer_aes/commands.txt): start here to
  connect and program the board.
- [Python FI demonstration](fault_injection/aes_fi_demo/README.md): simulated AES
  fault propagation with an offline HTML visualization.
- [Presentations](docs/presentations/) and [bibliography](docs/bibliography/).

The [ChipWhisperer subset](chipwhisperer/PFE_SUBSET.md) includes only the firmware
dependencies required by the current experiment. The root `.gitignore` excludes
the rest of a full local checkout. Install the host Python API using the
experiment's requirements file; virtual environments and hardware capture data
are not committed.

The software build and tests do not establish successful physical fault
injection. Hardware programming, captures, and fault models must be validated
on the target and recorded as experimental results.

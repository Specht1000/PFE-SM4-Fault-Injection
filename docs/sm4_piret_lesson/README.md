# Independent SM4 fault-recovery lesson

Build from the repository root:

```powershell
python build_sm4_piret_pdf.py
```

Output: `docs/SM4_Piret_Walkthrough.pdf`.

Every function defined in `piret_sm4.py` and `run.py` has its complete numbered
source, an input/process/output diagram, a physical-interpretation box and a
table explaining each executable physical source line. Nested callbacks and
the terminal class methods are included. AES-only branches in `run.py` are
marked as inactive for the SM4 command. Comments, blank lines and docstrings
remain visible in the source but are not described as executable instructions.

`line_notes.py` contains the authored semantic explanations. The build fails
if it encounters a new arithmetic statement without an explanation. Coverage
is recorded in `generated/line_coverage.json`. `physical_execution.tex` adds
conceptual PC/ChipWhisperer/STM32 diagrams and clearly distinguishes software
XOR replacement from an experimentally validated physical fault.

This is an independent LaTeX project. `main.tex` contains the illustrated
explanations, equations and TikZ diagrams. `generate_example.py` executes the
actual SM4 recovery and refreshes numerical tables, source excerpts and
`generated/example.json` before each build. The existing report is not modified.

The fixed public example uses plaintext and key
`0123456789ABCDEFFEDCBA9876543210`. It recovers four tail keys and the master
key from 32 faulty ciphertexts. The document explains the exact controlled-fault
assumptions; it does not claim a physical glitch experiment has reproduced them.

To upload independently to Overleaf, upload `main.tex`, `physical_execution.tex`
and the complete `generated/` folder, preserving paths. Select `main.tex` as
the main document.
Local building uses the existing portable Tectonic installation/cache; its first
use may download the compiler and packages. Build logs are saved in
`logs/build_sm4_piret_pdf.txt` and `logs/build_sm4_piret_pdf.html`.

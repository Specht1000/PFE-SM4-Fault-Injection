# Function-by-function SM4 Piret guide

Build from the repository root:

```powershell
python build_piret_sm4_guide.py
```

Output: `docs/Piret_SM4_Explained.pdf`.

This independent English document explains every function, the nested fault
callback, imports, data representation and terminal entry point. It uses small
worked examples rather than exhaustive tables. Five visual pages show matrix
indices, the nested loops, bit extraction and assembly, augmented rows, pivot
elimination, and inverse application using a verified four-bit teaching matrix.
Section 3.4 also includes a direct drawing beside the row-building code, a
line-by-line substitution example, every iteration of the four-bit construction,
and all 32 columns of one real SM4 row. Generated values are recorded in
`generated/row_building_values.json`.
The main AES/SM4 report and the
older extensive walkthrough are separate documents.

The chronological execution section follows the actual terminal call chain,
fully works through the first two observations, lists all 32 observed pairs and
byte-buffer updates, and connects recovered keys to peeling and reverse expansion.
The builder runs the real terminal entry point without pauses and saves its
output in `generated/execution_terminal.txt`. The underlying numerical history
is available in `generated/execution_values.json`.

Numerical examples are generated and verified from the current implementation.
`generated/verification.json` records the source hash and function coverage.
Build logs overwrite `logs/build_piret_sm4_guide.txt` and its HTML counterpart.
The builder reuses the project's portable Tectonic compiler and package cache.

For an independent Overleaf project, upload `main.tex` and the complete
`generated/` directory, `row_building_steps.tex` and
`matrix_visual_walkthrough.tex` and `execution_flow.tex` after a local build.
Select `main.tex` as the main file.

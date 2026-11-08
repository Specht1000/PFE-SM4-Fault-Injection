# LaTeX report

The report contains algorithm theory, mathematical attack descriptions, fault models and key recovery. Implementation explanations, function references and source listings have been removed.

## Local PDF

Run from the repository root:

```powershell
python build_pdf.py
```

Output: `docs/AES_SM4_DFA.pdf`. The first run downloads a portable compiler and LaTeX packages.

## Overleaf

Keep the folder structure and select `main.tex` as the main document. `full_report.tex` and `part_01.tex` build the same report. Edit the theory in `chapters/01_purpose.tex` through `chapters/08_comparison.tex`.

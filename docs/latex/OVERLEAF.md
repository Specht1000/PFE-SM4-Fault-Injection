# Modular LaTeX report

Import `overleaf_project.zip` using **New Project > Upload Project** in Overleaf.
Alternatively, upload all the `.tex` files and folders below to an existing
project. Uploading only `main.tex` is no longer sufficient.

Keep the folder structure. The two institution logo PNG files are optional:
place them at the project root with their original names. If absent, the title
page displays placeholders.

## Choose the PDF to compile

In the project settings, select the desired **Main document**, then recompile.
After importing this version, use **Recompile from scratch** once. Download each
PDF before switching main documents.

| Main document | PDF content |
| --- | --- |
| `main.tex` or `part_01.tex` | Algorithms, fault models and mathematical theory |
| `part_02.tex` | Implementation walkthrough, all four attack paths and examples |
| `part_03.tex` | AES and SM4 function reference and execution order |
| `part_04.tex` | Piret and Giraud functions, methods and callbacks |
| `part_05.tex` | Terminal and GUI functions and worker lifecycle |
| `part_06.tex` | Complete AES source, with original line numbers |
| `part_07.tex` | Complete SM4 source |
| `part_08.tex` | Complete Piret/DFA source |
| `part_09.tex` | Complete Giraud source |
| `part_10.tex` | Complete terminal demonstration source |
| `part_11.tex` | Complete GUI source |
| `full_report.tex` | Entire report; needs a longer compilation allowance |

You can also change `\ReportPart` in `main.tex` to the corresponding number.
Zero selects the entire report.

## Files to edit

```text
main.tex                    Default entry point (Part 1)
part_01.tex ... part_11.tex  Independent part entry points
full_report.tex             Complete report entry point
report.tex                  Shared document assembly and selection
preamble.tex                Packages, commands and formatting
frontmatter/
  title.tex                 Title page and academic information
  references.tex            References and experimental scope
parts/                      Ordered input lists for each part
chapters/
  01_purpose.tex ...         Theory and worked attack chapters
  11_manual_introduction.tex Implementation reading guide
  functions_aes.tex          AES function explanations
  functions_sm4.tex          SM4 function explanations
  functions_piret.tex        DFA function explanations
  functions_giraud.tex       Single-bit function explanations
  functions_run.tex          Terminal function explanations
  functions_gui.tex          GUI function explanations
appendices/
  source_aes.tex ...         All six complete source snapshots
```

Parts 3-5 retain all 134 callable explanations; Parts 6-11 retain all six
complete Python modules. Source references identify the part and original line
numbers. Edit content in the chapter or appendix file; entry points only choose
what to compile.

Splitting files improves organization. Compilation work is reduced by selecting
one part, which reads only that part's content files. Building all parts together
can still exceed Overleaf's time limit. Local PDF compilation has not been
verified because a LaTeX engine is not installed in the current environment.

`Underfull` and `Overfull` messages are layout warnings, separate from a timeout
or fatal compilation error.

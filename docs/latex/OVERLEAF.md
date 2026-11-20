# Main SM4 report

Upload this directory, preserving chapters/, parts/, frontmatter/ and figures/.
Select main.tex as the main document. The report explains SM4 and physical FI;
the final chapter retains a cipher comparison for context.

For local compilation with Tectonic, run from the repository root:
~~~powershell
tectonic --outdir .build/references-update docs/latex/main.tex
~~~

Create the output directory first. After a successful build, publish main.pdf
as docs/AES_SM4_DFA.pdf, whose established filename is retained for existing links.
The two physical scripts are documented in chapters/09_physical_faults.tex.

# PFE Overleaf Auto Sync

This local VS Code extension mirrors disk changes from
`C:\Projetos\PFE 5A\docs\latex` to the project opened through Overleaf Workshop.
It uses the existing authenticated filesystem provider, not copied cookies or
Git credentials. It captures external edits as well as ordinary editor saves.

## One-time connection

1. Install `pfe-overleaf-auto-sync-1.0.3.vsix` and reload the VS Code window.
2. Open **AES_SM4_DFA** in a new window through Overleaf Workshop.
3. In that window, press Ctrl+Shift+P and run
   **PFE Overleaf: Connect and Start Automatic Sync**.
4. Confirm the local source folder and inspect the displayed remote destination.
   Select **Start automatic sync** to upload matching local files.
5. Wait for **Overleaf auto sync** in the status bar. Keep that window open.

The project must already contain `main.tex` and `report.tex`. If the files are
inside an uploaded subfolder, the connector searches up to two directory levels
and binds to that LaTeX root. If multiple roots exist, select the intended one. After syncing a nested project, the connector creates a managed `pfe_sync_entry.tex` at project root, selects it as the Overleaf main document and attempts a PDF build. Its input search path points to the actual uploaded LaTeX folder. An existing unmarked file of that name is never overwritten.

## Behavior

- Local files are the source of truth. Changes made by Codex, another editor or
  file saves are queued after a short debounce and uploaded serially.
- New text files are created as documents before their content is written, avoiding the rejected multipart upload route.
- Text is sent and compared with LF line endings and without a UTF-8 BOM, matching Overleaf document representation. Other whitespace and all binary bytes remain significant.
- Verification retries reads briefly for delayed document events; it does not blindly reapply edits.
- Matching remote files are replaced and verified through the provider. Files
  present only remotely are retained during initial synchronization.
- Subsequent local file deletions are mirrored remotely. Directory cleanup is
  not recursive, and remote-only files are not pruned.
- TeX, bibliography, style/class, PNG/JPEG/SVG/EPS and text/Markdown files are
  included. Hidden files, ZIP archives, Python sources, logs, compiled PDFs and
  auxiliary outputs are excluded. Local filesystem symlinks are not traversed.
- Remote edits are not downloaded. Use the local files for continued editing.
- The connection resumes when the same Overleaf project window is reopened.
  VS Code and the authenticated Overleaf Workshop connection must remain active.
- A failed upload appears in the status bar and **Output > PFE Overleaf Sync**.
  After reconnecting, click the status bar or run **Sync All Files Now** to retry.
- **PFE Overleaf: Stop Automatic Sync** stops watching and forgets the connection.

The watcher/queue was tested against a simulated remote filesystem. Actual
Overleaf delivery must be confirmed after connecting the extension to the project.
Syncing does not remove Overleaf's PDF compilation time limits.

## Development

```powershell
node --test tools/overleaf-auto-sync/test.js
python tools/overleaf-auto-sync/package_vsix.py
```

The VSIX contains only the extension manifest, implementation and this guide.
No account credentials or project content are packaged.

"""Build the complete LaTeX report locally: python build_pdf.py."""
import argparse
import hashlib
import io
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "docs" / "latex"
VERSION = "0.17.0"
DOWNLOAD = f"https://github.com/tectonic-typesetting/tectonic/releases/download/tectonic%40{VERSION}/tectonic-{VERSION}-x86_64-pc-windows-msvc.zip"
SHA256 = "f61ce51f0b0ade1015b7de7ef368541c5424e9756ecbd0d7af97d6d48030845f"


def find_compiler():
    installed = shutil.which("tectonic")
    if installed:
        return Path(installed)
    portable = ROOT / ".tools" / "tectonic" / "tectonic.exe"
    if portable.is_file():
        return portable
    if platform.system() != "Windows" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise RuntimeError("Install Tectonic and put it on PATH to build on this platform.")
    print(f"Downloading official portable Tectonic {VERSION} (first run only)...", flush=True)
    request = urllib.request.Request(DOWNLOAD, headers={"User-Agent": "PFE-LaTeX-Builder"})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise RuntimeError("The compiler download did not match the official release checksum.")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        member = next(name for name in archive.namelist() if Path(name).name.lower() == "tectonic.exe")
        portable.parent.mkdir(parents=True, exist_ok=True)
        portable.write_bytes(archive.read(member))
    return portable


def build(part=0):
    filename = "full_report.tex" if part == 0 else f"part_{part:02d}.tex"
    if not (SOURCE / filename).is_file():
        raise RuntimeError(f"Missing LaTeX entry point: {SOURCE / filename}")
    compiler = find_compiler()
    output_folder = ROOT / ".build" / "latex" / f"part_{part:02d}"
    output_folder.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["TECTONIC_CACHE_DIR"] = str(ROOT / ".tools" / "tectonic" / "cache")
    command = [str(compiler), "-X", "compile", "--untrusted", "--keep-logs", "--outdir", str(output_folder), filename]
    generated = output_folder / Path(filename).with_suffix(".pdf")
    # Never mistake a PDF from an earlier build for a newly generated document.
    if generated.is_file():
        generated.unlink()
    print(f"Compiling {filename}. The first run also downloads LaTeX packages...", flush=True)
    log_path = output_folder / "build.log"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(command, cwd=SOURCE, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        try:
            for line in process.stdout:
                log.write(line)
                log.flush()
                print(line, end="", flush=True)
            status = process.wait()
        except KeyboardInterrupt:
            process.terminate()
            process.wait()
            raise
        finally:
            process.stdout.close()
    if status != 0 or not generated.is_file() or not generated.read_bytes().startswith(b"%PDF-"):
        raise RuntimeError(f"PDF compilation failed. Build log: {log_path}")
    name = "AES_SM4_DFA.pdf" if part == 0 else f"AES_SM4_DFA_part_{part:02d}.pdf"
    destination = ROOT / "docs" / name
    # Replace the previous published PDF only after a successful build.
    temporary = destination.with_suffix(".pdf.tmp")
    shutil.copyfile(generated, temporary)
    try:
        temporary.replace(destination)
    except PermissionError as error:
        raise RuntimeError(f"Close the PDF viewer and retry. The generated PDF is available at {generated}") from error
    print(f"\nPDF generated: {destination}")
    print(f"Build log: {log_path}")
    return destination


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--part", type=int, choices=(0, 1), default=0, help="0 builds the report; 1 selects the theory entry point.")
    args = parser.parse_args()
    try:
        build(args.part)
    except KeyboardInterrupt:
        print("\nPDF build interrupted.", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

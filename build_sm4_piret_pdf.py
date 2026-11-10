"""Build the independent illustrated lesson: python build_sm4_piret_pdf.py."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
from build_pdf import find_compiler

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'src'))


def main():
    source = ROOT / 'docs' / 'sm4_piret_lesson'

    # Execute the real attack and regenerate all numerical tables before typesetting.
    spec = importlib.util.spec_from_file_location('sm4_lesson_example', source / 'generate_example.py')

    example = importlib.util.module_from_spec(spec)

    spec.loader.exec_module(example)

    example.generate()

    output = ROOT / '.build' / 'sm4_piret_lesson'

    output.mkdir(parents=True, exist_ok=True)

    environment = os.environ.copy()

    environment['TECTONIC_CACHE_DIR'] = str(ROOT / '.tools' / 'tectonic' / 'cache')

    compiler = find_compiler()

    command = [str(compiler), '-X', 'compile', '--untrusted', '--keep-logs', '--outdir', str(output), 'main.tex']

    # The shared logger captures every compiler diagnostic in TXT and colored HTML.
    process = subprocess.Popen(command, cwd=source, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')

    try:
        for line in process.stdout:
            print(line, end='', flush=True)

        status = process.wait()
    except KeyboardInterrupt:
        process.terminate()

        process.wait()

        raise
    finally:
        process.stdout.close()

    generated = output / 'main.pdf'

    if status != 0 or not generated.is_file() or not generated.read_bytes().startswith(b'%PDF-'):
        raise RuntimeError(f'Independent lesson compilation failed; inspect {output / "main.log"}.')

    # Keep the original report untouched; publish only this new document.
    destination = ROOT / 'docs' / 'SM4_Piret_Walkthrough.pdf'

    temporary = destination.with_suffix('.pdf.tmp')

    shutil.copyfile(generated, temporary)

    temporary.replace(destination)

    print(f'PDF generated: {destination}')

    return 0


if __name__ == '__main__':
    from terminal_log import run_with_log

    raise SystemExit(run_with_log(main, 'build_sm4_piret_pdf'))

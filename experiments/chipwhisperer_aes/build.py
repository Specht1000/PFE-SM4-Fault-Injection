"""Build the STM32F303 target using a local official ChipWhisperer checkout.

This script compiles only. It never connects to or programs hardware.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def default_cw_root():
    for candidate in (ROOT / 'chipwhisperer', ROOT / 'third_party/chipwhisperer'):
        if (candidate / 'firmware/mcu/Makefile.inc').is_file():
            return candidate
    return ROOT / 'chipwhisperer'


def find_make(explicit=None):
    if explicit:
        return str(Path(explicit).resolve())
    for name in ('make', 'mingw32-make'):
        if shutil.which(name):
            return shutil.which(name)
    # STM32CubeIDE also bundles GNU make on Windows.
    candidates = sorted(Path('C:/ST').glob('STM32CubeIDE*/STM32CubeIDE/plugins/*make*/tools/bin/make.exe'))
    if candidates:
        return str(candidates[-1])
    raise RuntimeError('GNU make not found. Install the ChipWhisperer build tools or pass --make.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cw-root', type=Path, default=default_cw_root())
    parser.add_argument('--make', help='Path to GNU make')
    args = parser.parse_args()
    cw_root = args.cw_root.resolve()
    if not (cw_root / 'firmware/mcu/Makefile.inc').is_file():
        parser.error('Missing ChipWhisperer firmware sources. See README.md.')
    compiler = shutil.which('arm-none-eabi-gcc')
    if not compiler:
        parser.error('arm-none-eabi-gcc is not on PATH. Install the ARM GNU toolchain.')
    make = find_make(args.make)
    stage = cw_root / 'firmware/mcu/pfe-aes'
    marker = stage / '.pfe-aes-build-directory'
    if stage.exists() and not marker.is_file():
        parser.error(f'Refusing to overwrite an unowned directory: {stage}')
    stage.mkdir(parents=True, exist_ok=True)
    marker.write_text('Managed by experiments/chipwhisperer_aes/build.py\n', encoding='utf-8')
    source_names = ('main.c', 'aes_trace.c', 'aes_trace.h', 'Makefile')
    for name in source_names:
        shutil.copy2(HERE / 'firmware' / name, stage / name)
    env = os.environ.copy()
    tool_dirs = [str(Path(make).parent)]
    if os.name == 'nt':
        git = shutil.which('git')
        if git:
            unix_tools = Path(git).resolve().parents[1] / 'usr/bin'
            if (unix_tools / 'sh.exe').is_file():
                tool_dirs.append(str(unix_tools))
    env['PATH'] = os.pathsep.join(tool_dirs + [env['PATH']])
    if not shutil.which('sh', path=env['PATH']) or not shutil.which('rm', path=env['PATH']):
        parser.error('Build requires sh and rm. Install Git for Windows or the ChipWhisperer tools.')
    # Keep relative firmware paths to support workspace paths containing spaces.
    command = [make, 'hex', 'elf', 'lss', 'PLATFORM=CWLITEARM',
               'CRYPTO_TARGET=TINYAES128C', 'SS_VER=SS_VER_1_1']
    result = subprocess.run(command, cwd=stage, env=env, capture_output=True, text=True)
    output = HERE / 'build'
    output.mkdir(exist_ok=True)
    (output / 'build.log').write_text(result.stdout + result.stderr, encoding='utf-8')
    print(result.stdout)
    if result.returncode:
        print(result.stderr)
        raise SystemExit(f'Build failed. Read {output / "build.log"}')
    artifacts = {}
    for suffix in ('hex', 'elf', 'lss', 'map'):
        src = stage / f'pfe-aes-CWLITEARM.{suffix}'
        shutil.copy2(src, output / src.name)
        artifacts[src.name] = hashlib.sha256(src.read_bytes()).hexdigest()
    # A vendored subset has no independent Git history. Do not accidentally
    # record the enclosing PFE repository's revision as the upstream revision.
    upstream_file = cw_root / 'UPSTREAM.json'
    if upstream_file.is_file():
        revision = json.loads(upstream_file.read_text(encoding='utf-8'))['revision']
    elif (cw_root / '.git').exists():
        revision = subprocess.check_output(['git', '-C', str(cw_root), 'rev-parse', 'HEAD'], text=True).strip()
    else:
        revision = 'unknown'
    metadata = dict(platform='CWLITEARM', protocol='SS_VER_1_1', crypto='TINYAES128C',
                    optimization='s', upstream_revision=revision,
                    compiler=subprocess.check_output([compiler, '--version'], text=True).splitlines()[0],
                    artifacts_sha256=artifacts,
                    main_sha256=hashlib.sha256((HERE / 'firmware/main.c').read_bytes()).hexdigest(),
                    application_sha256={name: hashlib.sha256((HERE / 'firmware' / name).read_bytes()).hexdigest()
                                        for name in source_names})
    (output / 'build_info.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    print(f'Firmware ready: {output / "pfe-aes-CWLITEARM.hex"}')


if __name__ == '__main__':
    main()

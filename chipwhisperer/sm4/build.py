"""Build the STM32F303 firmware with NewAE's HAL and GNU Arm tools."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[2]
PROJECT = Path(__file__).resolve().parent


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, default=ROOT / ".build" / "chipwhisperer-sdk", help="Official ChipWhisperer repository root.")
    args = parser.parse_args(argv)
    mcu = args.sdk.resolve() / "firmware" / "mcu"

    if not (mcu / "Makefile.inc").is_file():
        parser.error("Missing SDK firmware/mcu/Makefile.inc. See commands.txt for the download commands.")

    make = shutil.which("make")

    if make is None:
        make = shutil.which("mingw32-make")

    if make is None or shutil.which("arm-none-eabi-gcc") is None:
        parser.error("Add GNU make and arm-none-eabi-gcc to PATH, or run from the ChipWhisperer environment.")

    stage = mcu / "pfe-sm4"

    if stage.exists() and not (stage / ".pfe-sm4-project").exists():
        parser.error(f"Refusing to overwrite an unrecognized SDK project: {stage}")

    stage.mkdir(parents=True, exist_ok=True)
    (stage / ".pfe-sm4-project").write_text("Managed by chipwhisperer/sm4/build.py\n", encoding="utf-8")

    for name in ("Makefile", "main.c", "sm4.c", "sm4.h"):
        shutil.copy2(PROJECT / "firmware" / name, stage / name)

    environment = os.environ.copy()

    if os.name == "nt":
        # NewAE's makefiles invoke sh and Unix utilities, available with Git Bash.
        git = shutil.which("git")

        if git is not None:
            unix_tools = Path(git).resolve().parents[1] / "usr" / "bin"

            if unix_tools.is_dir():
                environment["PATH"] = str(unix_tools) + os.pathsep + environment["PATH"]

    output = PROJECT / "build"
    output.mkdir(exist_ok=True)
    print(f"SDK project: {stage}")
    print("Building CWLITEARM / STM32F303, SimpleSerial 1.1, optimization -O0.")

    # Rebuild every object so an older SDK project's flags cannot leak into this build.
    command = [make, "-B", "PLATFORM=CWLITEARM", "SS_VER=SS_VER_1_1", "CRYPTO_TARGET=NONE", "OPT=0", "all"]

    with (output / "build.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen(command, cwd=stage, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")

        for line in process.stdout:
            print(line, end="")
            log.write(line)

        status = process.wait()

    if status != 0:
        raise SystemExit(f"Build failed. Inspect {output / 'build.log'}")

    for suffix in ("hex", "elf", "bin", "map", "lss"):
        artifact = stage / f"pfe-sm4-CWLITEARM.{suffix}"

        if artifact.is_file():
            shutil.copy2(artifact, output / artifact.name)

    if not (output / "pfe-sm4-CWLITEARM.hex").is_file():
        raise SystemExit("The build returned success but no HEX file was produced.")

    print(f"Firmware: {output / 'pfe-sm4-CWLITEARM.hex'}")


if __name__ == "__main__":
    main()

# ChipWhisperer firmware subset for this project

Only the dependencies needed by the STM32F303 AES experiment are tracked here.
The root `.gitignore` contains an explicit file allowlist; the full upstream
checkout may remain on a developer's machine without being published.

The 43 upstream files cover the STM32F303 HAL and Cortex-M4 headers, startup and
linker files, SimpleSerial V1.1, TinyAES-128-C, build rules, and upstream license.
They were selected from the compiler's dependency output plus the required
Makefiles, linker script, and license. Upstream file contents are unchanged.

`UPSTREAM.json` records the source repository, revision, configuration, and
SHA-256 of every upstream file. File-specific copyright and license notices
remain in place and take precedence over the general `LICENSE.txt` where stated.

The repository does not need the upstream Python source tree: the host API is
installed with pip into the experiment's isolated environment. Other targets,
Jupyter courses, FPGA/capture firmware, nested Git metadata, and generated
`firmware/mcu/pfe-aes` build files are ignored.

Build from the project root:

```powershell
python experiments/chipwhisperer_aes/build.py
```

See `experiments/chipwhisperer_aes/commands.txt` for programming and capture.
This subset supports the current CWLITEARM / TINYAES128C / SS_VER_1_1 build.
Other configurations may require explicitly adding further upstream files to
the allowlist and updating the manifest.

# File guide — what each file does

A map of this experiment, focused on the AES project and how the **browser GUI**
fits together. For step-by-step commands see [COMMANDS.md](COMMANDS.md); for the
protocol and hardware details see [README.md](README.md).

## The big picture

Two sides talk over a USB→UART link using the SimpleSerial protocol:

```
  Browser (gui/index.html)
        |  HTTP + JSON  (localhost)
        v
  gui_server.py ──uses──> aes_capture.py + aes_terminal.py   (host protocol code)
        |  SimpleSerial over UART (38400 baud)
        v
  STM32F303 firmware (firmware/main.c + aes_trace.c)  ── runs the actual AES
```

The host (PC) never computes AES for real work — it drives the STM32, which runs
the encryption, decryption, and fault injection. The host only cross-checks the
results against a software AES.

## Host (PC) files

| File | What it does |
| --- | --- |
| [`gui_server.py`](gui_server.py) | The GUI's backend. A small local web server (Python standard library only) that holds one ChipWhisperer connection and exposes a JSON API: `/api/connect`, `/api/key`, `/api/encrypt`, `/api/decrypt`, `/api/fault`, `/api/status`. It does **not** re-implement the protocol — it calls the functions in `aes_capture.py` and `aes_terminal.py`. |
| [`gui/index.html`](gui/index.html) | The GUI's front end: a single self-contained page (HTML/CSS/JS, no build step). Tabs for **Encrypt & Trace**, **Decrypt**, and **Fault Injection**, the AES state drawn as a steppable 4x4 matrix, and the connection/key controls. It talks to `gui_server.py` over `fetch`. |
| [`aes_capture.py`](aes_capture.py) | Command-line tool for `connect`, `flash`, `verify`, and `capture` (power traces). It also **defines the shared protocol helpers** (`set_key`, `encrypt`, `decrypt`, `verify`, `read_response`, …) that both the terminal and the GUI import. |
| [`aes_terminal.py`](aes_terminal.py) | The interactive text console (the GUI's command-line twin). It adds the encryption/decryption/fault **workflow** on top of `aes_capture.py`'s helpers: input parsing, the 41-state snapshot readout, and the fault comparison. The GUI reuses these functions (`prepare_input`, `fetch_trace`, `fetch_fault_trace`, `FaultSettings`, …). |
| [`build.py`](build.py) | Compiles the firmware. Stages `firmware/` into the ChipWhisperer tree, runs `make`, and records compiler + source hashes in `build/build_info.json`. Only needed if you change the firmware. |
| [`requirements.txt`](requirements.txt) | Host Python dependencies for the capture/terminal tools (`chipwhisperer`, `numpy`, `pycryptodome`). The GUI server uses `chipwhisperer` and `pycryptodome` (to cross-check every result). |

## Firmware (runs on the STM32F303)

| File | What it does |
| --- | --- |
| [`firmware/main.c`](firmware/main.c) | The target program. Registers the SimpleSerial commands (`i` identity, `k` key, `p` encrypt, `t` trace, `s` snapshot, `d` decrypt, `f` fault) and dispatches each to a handler. This is the entry point for everything the GUI sends. |
| [`firmware/aes_trace.c`](firmware/aes_trace.c) | The instrumented AES path. Reuses the TinyAES round primitives to encrypt while recording all 41 intermediate states, and applies the single-byte XOR for command `f`. This is what powers the GUI's state matrices and fault comparison. |
| [`firmware/aes_trace.h`](firmware/aes_trace.h) | Interface + constants for the traced path (`AES_TRACE_STEPS = 41`, `AES_TRACE_PACKET_SIZE = 19`). |
| [`firmware/Makefile`](firmware/Makefile) | Build recipe: names the target, sources, platform (`CWLITEARM`), AES backend (`TINYAES128C`), and SimpleSerial version. |

## Build output (generated, not edited)

| File | What it does |
| --- | --- |
| `build/pfe-aes-CWLITEARM.hex` | The compiled firmware image that `aes_capture.py flash` programs onto the STM32. |
| `build/build_info.json` | Provenance: compiler version and SHA-256 of the sources and artifacts. |
| `build/*.elf` / `*.lss` / `*.map` | Debug/disassembly/memory-map by-products of the build. |

## Tests (no hardware needed)

| File | What it does |
| --- | --- |
| [`tests/test_aes.py`](tests/test_aes.py) | Host tests: the SimpleSerial protocol (including errors/timeouts), input parsing, and native compilation of the real firmware AES backend, cross-checked against PyCryptodome and a Python reference. |
| [`tests/native_firmware.c`](tests/native_firmware.c) | A small C harness that compiles the firmware's AES callbacks for the PC so they can be tested without the board. |
| [`tests/stubs/hal.h`](tests/stubs/hal.h), [`tests/stubs/simpleserial.h`](tests/stubs/simpleserial.h) | Minimal stand-ins for the hardware HAL and SimpleSerial headers used by the native test build. |

## Documentation

| File | What it does |
| --- | --- |
| [`README.md`](README.md) | Main reference: what runs where, the firmware protocol table, capture format, rebuilding, and limitations. |
| [`COMMANDS.md`](COMMANDS.md) | Copy-paste PowerShell commands, in order, from setup to GUI to capture. |
| [`TERMINAL.md`](TERMINAL.md) | Guide to the interactive text console and decryption verification. |
| `FILES.md` | This file map. |

## How a GUI action flows through the files

Example — clicking **Compare clean vs. faulty** on the Fault Injection tab:

1. `gui/index.html` sends `POST /api/fault` with the message and fault settings.
2. `gui_server.py` validates them, building a `FaultSettings` from `aes_terminal.py`.
3. It calls `aes_terminal.fetch_trace` (clean run) and `fetch_fault_trace`
   (faulty run), which send the `t` and `f` SimpleSerial commands via the
   helpers in `aes_capture.py`.
4. On the STM32, `main.c`'s `handle_fault` calls `trace_encrypt_fault` in
   `aes_trace.c`, which injects the one-byte XOR and records the 41 states.
5. The states travel back over UART; `gui_server.py` diffs them and returns JSON;
   `index.html` draws the clean and faulty matrices side by side.

Encryption and decryption follow the same path through the `p`/`t` and `d`
commands.

"""Program and use the SM4 SimpleSerial target on a CW1173 Lite ARM."""
import argparse
import html
import json
from pathlib import Path
import sys
import time


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
import sm4


class SessionLog:
    """Overwrite terminal-style HTML and TXT logs for each hardware session."""

    def __init__(self, name="chipwhisperer_sm4"):
        directory = ROOT / "logs"
        directory.mkdir(exist_ok=True)
        self.text = (directory / (name + ".txt")).open("w", encoding="utf-8")
        self.page = (directory / (name + ".html")).open("w", encoding="utf-8")
        self.page.write('<!doctype html><html lang="en"><meta charset="utf-8"><title>ChipWhisperer SM4</title><style>body{background:#0b0f14;color:#e6edf3;margin:24px}pre{font:14px/1.5 Consolas,monospace}.green{color:#78d994}.red{color:#ff7373}.cyan{color:#4fd1c5}</style><body><pre>')

    def line(self, message, color="cyan"):
        self.text.write(message + "\n")
        self.page.write('<span class="' + color + '">' + html.escape(message) + '</span>\n')
        self.text.flush()
        self.page.flush()
        codes = {"green": "32", "red": "31", "cyan": "36"}

        if sys.stdout.isatty():
            print("\033[" + codes[color] + "m" + message + "\033[0m")
        else:
            print(message)

    def close(self):
        self.page.write('</pre></body></html>')
        self.page.close()
        self.text.close()


def parse_block(value):
    try:
        block = bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Use a 16-byte hexadecimal block.") from error

    if len(block) != 16:
        raise argparse.ArgumentTypeError("Use exactly 16 bytes (32 hexadecimal digits).")

    return block


def exchange(target, command, data, response_length=0):
    """Send one command and consume both its response and its acknowledgement."""
    target.simpleserial_write(command, bytearray(data))
    response = b""

    if response_length:
        # Read the data separately so a nonzero zXX status cannot be ignored.
        received = target.simpleserial_read("r", response_length, timeout=2000, ack=False)

        if received is None or len(received) != response_length:
            raise RuntimeError(f"Missing response to '{command}'. Check the firmware, clock and serial protocol.")

        response = bytes(received)

    status = target.simpleserial_wait_ack(timeout=2000)

    if status != 0:
        raise RuntimeError(f"Command '{command}' failed: status={status}. Status 1 means no key; 2 means invalid parameters.")

    return response


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", type=Path, help="Program this HEX into the STM32 target before communicating.")
    parser.add_argument("--key", type=parse_block, default=sm4.KEY)
    parser.add_argument("--input", type=parse_block, default=sm4.PLAINTEXT, help="Plaintext for encrypt/verify; ciphertext for decrypt.")
    parser.add_argument("--operation", choices=("verify", "encrypt", "decrypt"), default="verify")
    parser.add_argument("--trigger-round", type=int, default=255, help="255: whole cipher; 0..31: one processing round.")
    parser.add_argument("--capture", action="store_true", help="Save one power trace during the requested first operation.")
    parser.add_argument("--samples", type=int, default=5000)
    parser.add_argument("--serial-number", help="Capture device USB serial number, if multiple scopes are attached.")
    args = parser.parse_args(argv)

    if args.trigger_round not in range(32) and args.trigger_round != 255:
        parser.error("--trigger-round must be 0..31 or 255.")

    if not 1 <= args.samples <= 24400:
        parser.error("CW-Lite capture length must be 1..24400 samples.")

    if args.program is not None and not args.program.is_file():
        parser.error(f"HEX file not found: {args.program}")

    log = SessionLog()
    scope = None
    target = None

    try:
        import chipwhisperer as cw

        if not hasattr(cw, "scope"):
            raise RuntimeError("Install the ChipWhisperer Python package using chipwhisperer/sm4/requirements.txt.")

        log.line("Connecting to CW1173 Lite ARM / STM32F303...")
        scope = cw.scope(sn=args.serial_number)
        scope.default_setup()
        scope.clock.clkgen_freq = 7372800
        scope.io.glitch_hp = False
        scope.io.glitch_lp = False
        target = cw.target(scope, cw.targets.SimpleSerial)
        target.baud = 38400

        if args.program is not None:
            log.line(f"Programming STM32F303: {args.program.resolve()}")
            cw.program_target(scope, cw.programmers.STM32FProgrammer, str(args.program.resolve()))

        # Start the application normally after reset or bootloader programming.
        scope.io.nrst = "low"
        time.sleep(0.05)
        scope.io.nrst = "high_z"
        time.sleep(0.25)
        target.flush()

        identity = exchange(target, "i", b"", 4)

        if identity != b"SM4\x01":
            raise RuntimeError(f"Unexpected target identity: {identity!r}")

        log.line("SM4 firmware protocol v1 identified.", "green")
        exchange(target, "k", args.key)
        exchange(target, "t", bytes([args.trigger_round]))
        log.line(f"Key loaded; trigger selection: {args.trigger_round}.")
        log.line(f"Input: {args.input.hex().upper()}")
        command = "p"

        if args.operation == "decrypt":
            command = "d"

        if args.capture:
            scope.adc.samples = args.samples
            scope.adc.timeout = 2
            scope.arm()
            target.simpleserial_write(command, bytearray(args.input))

            if scope.capture():
                raise RuntimeError("Capture timed out. Check trigger and firmware.")

            response = target.simpleserial_read("r", 16, timeout=2000, ack=False)
            status = target.simpleserial_wait_ack(timeout=2000)

            if response is None or len(response) != 16 or status != 0:
                raise RuntimeError(f"Invalid captured response: status={status}.")

            output = bytes(response)
            samples = []

            for sample in scope.get_last_trace():
                samples.append(float(sample))

            trace_path = ROOT / "logs" / "chipwhisperer_sm4_trace.json"
            trace_path.write_text(json.dumps(dict(input=args.input.hex(), output=output.hex(), operation=command, trigger_round=args.trigger_round, sample_rate=float(scope.clock.adc_freq), samples=samples), indent=2), encoding="utf-8")
            log.line(f"Power trace: {trace_path}", "green")
        else:
            output = exchange(target, command, args.input, 16)

        if command == "d":
            expected = sm4.sm4_decrypt_block(args.input, args.key)
            label = "Plaintext"
        else:
            expected = sm4.sm4_encrypt_block(args.input, args.key)
            label = "Ciphertext"

        log.line(f"STM32 {label}: {output.hex().upper()}")
        log.line(f"Python expected: {expected.hex().upper()}")

        if output != expected:
            raise RuntimeError("STM32 output does not match the Python SM4 reference.")

        log.line("STM32 / Python comparison: PASS", "green")

        if args.operation == "verify":
            recovered = exchange(target, "d", output, 16)
            log.line(f"STM32 decrypted: {recovered.hex().upper()}")

            if recovered != args.input:
                raise RuntimeError("STM32 encryption/decryption round trip failed.")

            log.line("STM32 encryption/decryption round trip: PASS", "green")

        return 0
    except (Exception, KeyboardInterrupt) as error:
        log.line(f"ERROR: {error}", "red")
        return 1
    finally:
        try:
            if target is not None:
                target.dis()
        finally:
            try:
                if scope is not None:
                    scope.dis()
            finally:
                log.close()


if __name__ == "__main__":
    raise SystemExit(main())

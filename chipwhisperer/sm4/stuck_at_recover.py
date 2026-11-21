"""Full SM4 master-key recovery from INSTRUCTION-SKIP / STUCK-AT glitch faults.

Many glitches do not flip a single bit; they force one S-box output byte to a
constant (0x00 from a skipped store, or 0xFF). That is a stuck-at fault, and it
is directly exploitable: a clean stuck-at fault on one byte pins that key byte.

This tool glitches rounds 31, 30, 29 and 28 in turn, collects every faulty
ciphertext (no peeling needed during collection), then runs the stuck-at solver
(piret_sm4.recover_stuck_at), which searches the small per-byte candidate sets
and returns the master key verified by re-encryption -- when clean single-byte
faults are available. Both common stuck values (0x00 and 0xFF) are tried, so the
campaign need not know which one occurred. (On the project's board neither the
clock nor the voltage route yielded a clean single-byte fault; the solver itself
is validated in the Python simulation.)

The default glitch shape follows NewAE's known-good CW-Lite ARM (STM32) values
from the fault201 DFA lab (width ~ -9, offset ~ -40, repeat 3); these are the
strength/phase of the glitch, independent of which cycle the per-round trigger
delay selects. Override them for a different target or to search.

Run (board connected):
  python chipwhisperer/sm4/stuck_at_recover.py

Output: logs/stuck_at_recover.txt / .html, plus the recovered key if found.
"""
import argparse
import struct
import sys
import time

import clock_glitch
import voltage_glitch
from client import ROOT, SessionLog, exchange
from glitch_common import acquire, decimal_values, delay_values, disable_attack, parse_block, reset_target
import piret_sm4
import sm4

ROUNDS = (31, 30, 29, 28)


def setup_glitch(scope, repeat):
    """Same glitch wiring the campaigns use (external single-shot on TIO4)."""
    scope.adc.samples = 1000
    scope.adc.timeout = 1
    scope.trigger.triggers = "tio4"
    scope.glitch.clk_src = "clkgen"
    scope.glitch.trigger_src = "ext_single"
    scope.glitch.arm_timing = "after_scope"
    scope.glitch.repeat = repeat


def _round31_bytes(baseline, faults):
    """Which round-31 bytes already have a clean single-byte fault (no peeling)."""
    covered = set()
    c = struct.unpack(">4I", baseline)
    for faulty in faults:
        f = struct.unpack(">4I", faulty)
        if c[1:] != f[1:] or c[0] == f[0]:
            continue
        delta_b = piret_sm4.inverse_linear(c[0] ^ f[0])
        nonzero = [b for b in range(4) if (delta_b >> (24 - 8 * b)) & 255]
        if len(nonzero) == 1:
            covered.add(nonzero[0])
    return covered


def collect_round(scope, target, configure, args, number, baseline, log, out_list, points=None, record=None):
    """Glitch one round, appending distinct faulty ciphertexts to out_list (so a
    Ctrl+C keeps partial results). With points=None it sweeps the full grid; with
    an explicit list of (width, offset, delay) it replays just those. If `record`
    is given, each (width, offset, delay) that yields a clean single-byte round-31
    fault is appended to it. Returns a dict of outcome counts so the caller can
    report progress even when the glitch never faults (e.g. an untuned voltage
    route). A heartbeat line is logged every 40 trials so the run is never silent."""
    seen = set(out_list)
    counts = {"correct": 0, "fault": 0, "timeout_or_reset": 0, "invalid_response": 0}
    trials = 0
    last_setting = None

    if points is None:
        grid = [(width, offset, delay)
                for width in args.widths
                for offset in args.offsets
                for delay in args.delays]
    else:
        grid = list(points)

    for width, offset, delay in grid:
        if trials >= args.max_trials:
            return counts
        # Round 31 coverage is exact (no peeling), so stop once all four bytes hit.
        if number == 31 and len(_round31_bytes(baseline, out_list)) == 4:
            return counts

        if last_setting != (width, offset):
            disable_attack(scope)
            scope.glitch.width = width
            scope.glitch.offset = offset
            time.sleep(0.05)
            _phase1, _phase2, lock1, lock2 = scope.glitch.readStatus()
            if not lock1 or not lock2:
                raise RuntimeError("The glitch clock DCMs are not locked.")
            last_setting = (width, offset)

        scope.glitch.ext_offset = delay
        reset_target(scope, target, args.key, number)

        try:
            configure(scope, args.driver)
            data, status, _detail = acquire(scope, target, args.input, args.timeout)
        finally:
            disable_attack(scope)

        trials += 1

        if status != "received":
            counts[status] = counts.get(status, 0) + 1
        elif bytes(data) == baseline:
            counts["correct"] += 1
        else:
            counts["fault"] += 1
            faulty = bytes(data)
            if faulty not in seen:
                seen.add(faulty)
                out_list.append(faulty)
                log.line(f"  round {number} | w={scope.glitch.width} off={scope.glitch.offset} delay={delay}: fault {faulty.hex().upper()}", "cyan")

                if record is not None and len(_round31_bytes(baseline, [faulty])) == 1:
                    record.append((width, offset, delay))

        # Heartbeat: show the run is alive even when nothing faults.
        if trials % 40 == 0:
            log.line(f"  round {number}: {trials} trials | {len(out_list)} fault(s), "
                     f"{counts['correct']} correct, {counts['timeout_or_reset']} no-response", "cyan")

    return counts


def _log_round_summary(log, number, faults, counts):
    """One line per round, shown even with zero faults so the run is legible."""
    total = sum(counts.values())
    log.line(f"Round {number}: {len(faults)} distinct fault(s) from {total} trials "
             f"(correct={counts.get('correct', 0)}, no-response={counts.get('timeout_or_reset', 0)}, "
             f"invalid={counts.get('invalid_response', 0)}).", "green" if faults else "red")
    if not faults and total:
        log.line(f"  No faults at round {number}: the glitch did not disturb the cipher at any "
                 f"swept point. Tune the glitch (for voltage, try different widths/offsets and "
                 f"--driver hp/lp); 'correct' means too weak, 'no-response' means too strong.", "red")


def explain_recovery(log, plaintext, baseline, faulty_by_round, master):
    """Replay the recovery step by step into the log, using the found subkeys to
    show, for each round and byte, how a stuck-at fault pins that key byte."""
    schedule = sm4.key_expansion(master)
    log.line("Step-by-step recovery (how each key byte follows from a stuck-at fault):", "green")

    for number in (31, 30, 29, 28):
        later = {n: schedule[n] for n in range(number + 1, 32)}
        clean = piret_sm4.peel_sm4(baseline, number, later)
        c = struct.unpack(">4I", clean)
        peeled = ",".join(str(n) for n in sorted(later)) or "none"
        log.line(f"  rk{number} (peel rounds: {peeled}):", "cyan")
        subkey = [None, None, None, None]

        for faulty in faulty_by_round.get(number, ()):
            f = struct.unpack(">4I", piret_sm4.peel_sm4(faulty, number, later))
            if c[1:] != f[1:] or c[0] == f[0]:
                continue
            delta_b = piret_sm4.inverse_linear(c[0] ^ f[0])
            nonzero = [b for b in range(4) if (delta_b >> (24 - 8 * b)) & 255]
            if len(nonzero) != 1:
                continue
            byte = nonzero[0]
            if subkey[byte] is not None:
                continue
            shift = 24 - 8 * byte
            d = (delta_b >> shift) & 255
            q = ((c[1] ^ c[2] ^ c[3]) >> shift) & 255
            true_byte = (schedule[number] >> shift) & 255
            for stuck in (0x00, 0xFF):
                if piret_sm4.INV_SBOX[d ^ stuck] ^ q == true_byte:
                    subkey[byte] = true_byte
                    log.line(f"    byte {byte}: dX35={c[0] ^ f[0]:08X}  L_inv={delta_b:08X}  d={d:02X}  q={q:02X}"
                             f"  | forced V={stuck:02X} -> Sinv(d XOR V) XOR q = {true_byte:02X}", "cyan")
                    break

        assembled = "".join(f"{b:02X}" if b is not None else "??" for b in subkey)
        log.line(f"    => rk{number} = {assembled}", "green")

    log.line(f"  reverse SM4 schedule (rk28..rk31) and strip FK -> master key {master.hex().upper()}", "green")


def run(args, connect, log_name="stuck_at_recover"):
    log = SessionLog(log_name)
    scope = None
    target = None

    try:
        log.line("SM4 STUCK-AT (instruction-skip) MASTER-KEY RECOVERY", "green")
        log.line("Collecting faulty ciphertexts for rounds 31, 30, 29, 28.")

        scope, target, cw = connect(args)
        scope.default_setup(verbose=False)
        scope.clock.clkgen_freq = 7372800
        target.baud = 38400

        reset_target(scope, target, args.key, 31)
        baseline = exchange(target, "p", args.input, 16)

        if baseline != sm4.sm4_encrypt_block(args.input, args.key):
            raise RuntimeError("Clean target baseline does not match SM4. No glitches applied.")

        log.line("Clean baseline: " + baseline.hex().upper(), "green")
        configure = clock_glitch.configure_attack if args.method == "clock" else voltage_glitch.configure_attack
        setup_glitch(scope, args.repeat)

        # Lists are filled in place so a Ctrl+C still leaves partial data to use.
        faulty_by_round = {number: [] for number in ROUNDS}
        good_points = []
        try:
            # Round 31 first: full grid, exact coverage, and learn the useful points.
            counts = collect_round(scope, target, configure, args, 31, baseline, log, faulty_by_round[31], record=good_points)
            _log_round_summary(log, 31, faulty_by_round[31], counts)

            # The four S-box lookups sit at the same trigger-relative delays every
            # round, so reuse round 31's useful points (plus a small +/-2 window)
            # for the deeper rounds. That turns a full grid into a few trials.
            focused = set()
            for width, offset, delay in good_points:
                for nearby in range(delay - 2, delay + 3):
                    if nearby >= 0:
                        focused.add((width, offset, nearby))
            focused = sorted(focused)
            log.line(f"Reusing {len(focused)} good glitch point(s) for rounds 30, 29, 28.", "green")

            for number in (30, 29, 28):
                counts = collect_round(scope, target, configure, args, number, baseline, log, faulty_by_round[number], points=focused)
                _log_round_summary(log, number, faulty_by_round[number], counts)
        except KeyboardInterrupt:
            log.line("Interrupted during collection; attempting recovery with the faults collected so far.", "red")

        # Round-31 byte coverage is exact (no peeling needed); a missing byte means
        # the glitch never cleanly hit that S-box lookup, so rk31 cannot be built.
        covered = set()
        cc = struct.unpack(">4I", baseline)
        for faulty in faulty_by_round.get(31, ()):
            ff = struct.unpack(">4I", faulty)
            if cc[1:] != ff[1:] or cc[0] == ff[0]:
                continue
            delta_b = piret_sm4.inverse_linear(cc[0] ^ ff[0])
            nonzero = [b for b in range(4) if (delta_b >> (24 - 8 * b)) & 255]
            if len(nonzero) == 1:
                covered.add(nonzero[0])
        missing = sorted(set(range(4)) - covered)
        log.line(f"Round 31 single-byte coverage: have bytes {sorted(covered)}, MISSING {missing}",
                 "green" if not missing else "red")
        if missing:
            log.line("Vary the delay so the glitch hits the S-box lookup of each missing byte.", "red")

        log.line("Running stuck-at solver (trying forced values 00 and FF), verified by re-encryption...")
        master = piret_sm4.recover_stuck_at(args.input, baseline, faulty_by_round)

        if master is not None and sm4.sm4_encrypt_block(args.input, master) == baseline:
            explain_recovery(log, args.input, baseline, faulty_by_round, master)
            log.line("RECOVERED MASTER KEY: " + master.hex().upper(), "green")
            log.line("Re-encryption check: PASS", "green")
            return 0

        log.line("No master key from the stuck-at model with the faults collected.", "red")
        log.line("Need at least one clean single-byte S-box fault on EACH byte of EACH round.", "red")
        return 2
    except Exception as error:  # noqa: BLE001
        log.line(f"ERROR: {error}", "red")
        return 1
    finally:
        try:
            if scope is not None:
                disable_attack(scope)
                scope.io.nrst = "low"
                time.sleep(0.05)
                scope.io.nrst = "high_z"
                if target is not None:
                    target.dis()
                scope.dis()
        finally:
            log.close()


def _connect(args):
    import chipwhisperer as cw

    scope = cw.scope(sn=args.serial_number)
    target = cw.target(scope, cw.targets.SimpleSerial)
    return scope, target, cw


def main(argv=None, method=None, log_name="stuck_at_recover"):
    parser = argparse.ArgumentParser(description="SM4 stuck-at master-key recovery.")
    # When `method` is fixed by a wrapper (recover_clock.py / recover_voltage.py)
    # the --method flag is hidden; otherwise it is selectable.
    if method is None:
        parser.add_argument("--method", choices=("clock", "voltage"), default="clock")
    parser.add_argument("--key", type=parse_block, default=sm4.KEY)
    parser.add_argument("--input", type=parse_block, default=sm4.PLAINTEXT)
    # Defaults follow NewAE's CW-Lite ARM (STM32) DFA lab: width ~ -9, offset ~ -40,
    # repeat 3. A small range around them is swept to absorb board-to-board drift.
    parser.add_argument("--widths", type=decimal_values, default="-8,-9,-10,-11")
    parser.add_argument("--offsets", type=decimal_values, default="-40,-38,-42")
    parser.add_argument("--delays", type=delay_values, default="0:170:1")
    parser.add_argument("--repeat", type=int, choices=range(1, 11), default=3)
    parser.add_argument("--max-trials", type=int, default=4000, help="Cap on trials per round.")
    parser.add_argument("--timeout", type=int, default=500)
    parser.add_argument("--driver", choices=("lp", "hp"), default="lp")
    parser.add_argument("--serial-number")
    args = parser.parse_args(argv)

    if method is not None:
        args.method = method

    if args.max_trials < 1 or args.timeout < 1:
        parser.error("Trial limit and timeout must be positive.")

    return run(args, _connect, log_name=log_name)


if __name__ == "__main__":
    raise SystemExit(main())

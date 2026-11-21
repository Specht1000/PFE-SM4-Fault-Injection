"""Shared acquisition and ciphertext-only analysis for two physical FI methods.

No glitch parameter is interpreted as a known bit/byte error. The observed
pass-through-word difference supplies a candidate error descriptor. Passing the
output checks establishes model compatibility, not proof of the physical fault.
"""
import argparse
from collections import Counter
import csv
import json
import math
from pathlib import Path
import struct
import sys
import time

from client import ROOT, SessionLog, exchange, parse_block

sys.path.insert(0, str(ROOT / "src"))
import piret_sm4
import sm4


def decimal_values(text):
    values = []

    for item in text.split(","):
        value = float(item)

        if not math.isfinite(value) or not -49.0 <= value <= 49.0:
            raise argparse.ArgumentTypeError("Use comma-separated finite percentages in -49..49.")

        values.append(value)

    if not values:
        raise argparse.ArgumentTypeError("At least one value is required.")

    return values


def delay_values(text):
    try:
        start, stop, step = map(int, text.split(":"))
    except ValueError as error:
        raise argparse.ArgumentTypeError("Use START:STOP:STEP in target clock cycles.") from error

    if not 0 <= start <= stop <= 1000000 or step < 1:
        raise argparse.ArgumentTypeError("Use 0 <= START <= STOP <= 1000000 and STEP >= 1.")

    return range(start, stop + 1, step)


def load_keys(path, round_number):
    keys = {}

    if path is not None:
        saved = json.loads(path.read_text(encoding="utf-8"))

        for number, value in saved.get("round_keys", {}).items():
            index = int(number)
            key = int(value, 16)

            if not 28 <= index <= 31 or not 0 <= key <= 0xFFFFFFFF:
                raise ValueError("Invalid saved tail subkey.")

            keys[index] = key

    for number in range(round_number + 1, 32):
        if number not in keys:
            raise ValueError(f"Recover rk{number} before attacking round {round_number}.")

    return keys


def infer_fault(clean_view, faulty_view):
    """Infer one input-word/byte difference, without a target key or teacher trace."""
    clean = struct.unpack(">4I", clean_view)
    faulty = struct.unpack(">4I", faulty_view)
    changed = []

    for position in range(1, 4):
        difference = clean[position] ^ faulty[position]

        if difference:
            changed.append((position, difference))

    if not changed:
        # No pass-through word moved. If only the newest word changed, the glitch
        # hit the S-box INPUT directly. The input difference is unobservable, so we
        # fall back to the Giraud assumption of a SINGLE-BIT fault and filter over
        # the eight one-bit masks (sm4_sbox_input_giraud_candidates). A multi-bit
        # or multi-byte S-box fault leaves no candidate and is rejected as off-model.
        if clean[0] == faulty[0]:
            raise ValueError("No output difference to analyse.")

        delta_b = piret_sm4.inverse_linear(clean[0] ^ faulty[0])
        nonzero = [index for index in range(4) if (delta_b >> (24 - 8 * index)) & 255]

        if len(nonzero) != 1:
            raise ValueError(
                "S-box-input fault spread over several bytes (L^-1 is not confined "
                "to one byte): not single-bit exploitable. Retune for a cleaner, "
                "narrower fault (smaller glitch width)."
            )

        byte = nonzero[0]
        candidates, _, delta = piret_sm4.sm4_sbox_input_giraud_candidates(clean_view, faulty_view, byte)
        # word=0 marks the newest word; mask is None because the exact bit is unknown.
        return dict(model="giraud-sbox-input", word=0, byte=byte, mask=None, delta_b=delta, candidates=candidates)

    if len(changed) != 1:
        raise ValueError("Expected exactly one changed pass-through word.")

    position, difference = changed[0]
    changed_bytes = []

    for byte in range(4):
        mask = (difference >> (24 - 8 * byte)) & 255

        if mask:
            changed_bytes.append((byte, mask))

    if len(changed_bytes) != 1:
        raise ValueError("Expected exactly one changed byte in that input word.")

    byte, mask = changed_bytes[0]
    candidates, _, delta = piret_sm4.sm4_byte_candidates(clean_view, faulty_view, byte, mask)

    if not candidates:
        raise ValueError("The S-box differential has no key-byte candidate.")

    # Public reversed output position 3 is input word 1, position 1 is word 3.
    return dict(model="input-word", word=4 - position, byte=byte, mask=mask, delta_b=delta, candidates=candidates)


def disable_attack(scope):
    """Remove the crowbar drive and restore a normal clock before target reset."""
    # Try every independent cleanup action even if one USB write fails.
    for name, value in (("glitch_hp", False), ("glitch_lp", False), ("hs2", "clkgen")):
        try:
            setattr(scope.io, name, value)
        except Exception:
            pass


def reset_target(scope, target, key, round_number):
    disable_attack(scope)
    scope.io.nrst = "low"
    time.sleep(0.05)
    scope.io.nrst = "high_z"
    time.sleep(0.2)
    target.flush()

    if exchange(target, "i", b"", 4) != b"SM4\x01":
        raise RuntimeError("Wrong target firmware. Program the SM4 firmware first.")

    exchange(target, "k", key)
    exchange(target, "t", bytes([round_number]))


def acquire(scope, target, plaintext, timeout):
    """Arm one external-trigger glitch and collect the serial response and ACK."""
    scope.arm()
    target.simpleserial_write("p", bytearray(plaintext))
    capture_timeout = bool(scope.capture())
    data = target.simpleserial_read("r", 16, timeout=timeout, ack=False)
    acknowledgement = target.simpleserial_wait_ack(timeout=timeout)

    if capture_timeout:
        return None, "timeout_or_reset", "No capture trigger or clock stopped."

    if data is None or acknowledgement is None:
        return None, "timeout_or_reset", "No complete serial response; reset is not independently confirmed."

    if len(data) != 16 or acknowledgement != 0:
        return None, "invalid_response", f"Invalid length or ACK status {acknowledgement}."

    return bytes(data), "received", ""


def run_campaign(kind, configure_attack, argv=None, log=None):
    # `log` lets a combined runner (all_attacks.py) collect several campaigns in
    # ONE shared log. When it is None we own a per-method log, as before.
    parser = argparse.ArgumentParser(description=f"Physical {kind} glitch campaign on the SM4 STM32F303 target.")
    parser.add_argument("--round", type=int, choices=(28, 29, 30, 31), default=31)
    parser.add_argument("--key", type=parse_block, default=sm4.KEY, help="Target setup only; never passed to DFA filtering.")
    parser.add_argument("--input", type=parse_block, default=sm4.PLAINTEXT)
    parser.add_argument("--widths", type=decimal_values, default="2,5,10", help="Pulse-width percentages of a target clock cycle.")
    parser.add_argument("--offsets", type=decimal_values, default="0,10", help="Fine phase offsets in percent of a clock cycle.")
    parser.add_argument("--delays", type=delay_values, default="0:100:10", help="Coarse trigger delays START:STOP:STEP, inclusive.")
    parser.add_argument("--repeat", type=int, choices=range(1, 11), default=1)
    parser.add_argument("--attempts-per-point", type=int, default=1)
    parser.add_argument("--max-trials", type=int, default=200)
    parser.add_argument("--timeout", type=int, default=500, help="Serial timeout in milliseconds.")
    parser.add_argument("--driver", choices=("lp", "hp"), default="lp", help="Voltage crowbar choice; ignored for clock glitching.")
    parser.add_argument("--recovered-keys", type=Path, help="Previous campaign JSON with later round-key candidates.")
    parser.add_argument("--serial-number")
    parser.add_argument("--dry-run", action="store_true", help="Describe the grid without opening USB or applying faults.")
    args = parser.parse_args(argv)

    if args.attempts_per_point < 1 or args.max_trials < 1 or args.timeout < 1:
        parser.error("Attempt counts, trial limit and timeout must be positive.")

    for value in args.widths:
        if value == 0:
            parser.error("Use nonzero widths; zero-width settings are not used as a clean baseline.")

    try:
        keys = load_keys(args.recovered_keys, args.round)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    total = len(args.widths) * len(args.offsets) * len(args.delays) * args.attempts_per_point
    count = min(total, args.max_trials)
    name = kind + "_glitch"
    own_log = log is None          # only close a log we created ourselves
    if own_log:
        log = SessionLog(name)
    scope = None
    target = None
    statuses = Counter()
    survivors = {}
    # Giraud (unknown-bit) tallies: physical single-bit faults all vote for the
    # true key byte, while multi-bit faults scatter their votes. Voting (instead
    # of a hard intersection) tolerates the off-model faults a real glitch mixes in.
    votes = {byte: Counter() for byte in range(4)}
    giraud_obs = Counter()
    seen = set()
    output = ROOT / "logs"
    records = []
    baseline = None
    complete = False
    verified_master = False

    try:
        log.line(f"SM4 {kind.upper()} GLITCH CAMPAIGN: round={args.round}, trials <= {count}")
        log.line("width/offset are clock-cycle percentages; delay is in target-clock cycles.")

        if args.dry_run:
            log.line(f"Widths: {args.widths}; offsets: {args.offsets}; delays: {args.delays}")
            log.line("Dry run: no USB connection, target reset or physical fault.", "green")
            return 0

        import chipwhisperer as cw

        scope = cw.scope(sn=args.serial_number)
        scope.default_setup(verbose=False)
        scope.clock.clkgen_freq = 7372800
        target = cw.target(scope, cw.targets.SimpleSerial)
        target.baud = 38400
        reset_target(scope, target, args.key, args.round)
        baseline = exchange(target, "p", args.input, 16)

        if baseline != sm4.sm4_encrypt_block(args.input, args.key):
            raise RuntimeError("Clean target baseline does not match SM4. No glitches applied.")

        if args.recovered_keys is not None:
            prior = json.loads(args.recovered_keys.read_text(encoding="utf-8"))

            if prior.get("plaintext") is not None and bytes.fromhex(prior["plaintext"]) != args.input:
                raise RuntimeError("Saved subkeys belong to a different plaintext campaign.")

            if prior.get("correct") is not None and bytes.fromhex(prior["correct"]) != baseline:
                raise RuntimeError("Saved subkeys belong to a different target key/baseline.")

        clean_view = piret_sm4.peel_sm4(baseline, args.round, keys)
        log.line("Clean baseline: " + baseline.hex().upper(), "green")
        scope.adc.samples = 1000
        scope.adc.timeout = 1
        scope.trigger.triggers = "tio4"
        scope.glitch.clk_src = "clkgen"
        scope.glitch.trigger_src = "ext_single"
        scope.glitch.arm_timing = "after_scope"
        scope.glitch.repeat = args.repeat
        fields = ["trial", "method", "round", "width_requested", "width_actual", "offset_requested", "offset_actual", "delay", "repeat", "status", "correct", "faulty", "xor", "model", "input_word", "byte", "observed_mask", "newest_word_diff", "delta_b", "sbox_output_diff", "q", "q_faulty", "before", "pair_candidates", "remaining", "detail"]

        with (output / (name + ".csv")).open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()

            for width in args.widths:
                for offset in args.offsets:
                    # Changing phase may reset the glitch DCM; keep normal clock
                    # forwarding and crowbars disabled during configuration.
                    disable_attack(scope)
                    scope.glitch.width = width
                    scope.glitch.offset = offset
                    time.sleep(0.05)
                    phase1, phase2, lock1, lock2 = scope.glitch.readStatus()

                    if not lock1 or not lock2:
                        raise RuntimeError("The glitch clock DCMs are not locked. No trial applied at this setting.")

                    for delay in args.delays:
                        scope.glitch.ext_offset = delay

                        for attempt in range(args.attempts_per_point):
                            if len(records) >= count:
                                break

                            reset_target(scope, target, args.key, args.round)
                            row = dict(trial=len(records) + 1, method=kind, round=args.round, width_requested=width, width_actual=scope.glitch.width, offset_requested=offset, offset_actual=scope.glitch.offset, delay=delay, repeat=args.repeat, correct=baseline.hex().upper())

                            try:
                                configure_attack(scope, args.driver)
                                faulty, status, detail = acquire(scope, target, args.input, args.timeout)
                            finally:
                                disable_attack(scope)

                            row.update(status=status, detail=detail)

                            if faulty is not None:
                                row["faulty"] = faulty.hex().upper()
                                difference = bytearray(16)

                                for position in range(16):
                                    difference[position] = baseline[position] ^ faulty[position]

                                row["xor"] = difference.hex().upper()

                                if faulty == baseline:
                                    row["status"] = "correct"
                                else:
                                    try:
                                        faulty_view = piret_sm4.peel_sm4(faulty, args.round, keys)
                                        observation = infer_fault(clean_view, faulty_view)
                                    except ValueError as error:
                                        row.update(status="faulty_rejected", detail=str(error))
                                    else:
                                        byte = observation["byte"]
                                        pair = observation["candidates"]
                                        model = observation.get("model", "input-word")
                                        mask = observation.get("mask")
                                        # Reconstruct the public breakdown so the log can show each DFA step,
                                        # just like the software walkthrough: L-inverse, q, S-box differential.
                                        cc = struct.unpack(">4I", clean_view)
                                        ff = struct.unpack(">4I", faulty_view)
                                        shift = 24 - 8 * byte
                                        d_byte = (observation["delta_b"] >> shift) & 255
                                        q = ((cc[1] ^ cc[2] ^ cc[3]) >> shift) & 255
                                        q_faulty = ((ff[1] ^ ff[2] ^ ff[3]) >> shift) & 255
                                        observed_mask = f"{mask:02X}" if mask is not None else "1-bit(unknown)"
                                        row.update(model=model, input_word=observation["word"], byte=byte, observed_mask=observed_mask, newest_word_diff=f"{cc[0] ^ ff[0]:08X}", delta_b=f"{observation['delta_b']:08X}", sbox_output_diff=f"{d_byte:02X}", q=f"{q:02X}", q_faulty=f"{q_faulty:02X}", pair_candidates=sorted(pair))

                                        if model == "giraud-sbox-input":
                                            # Unknown-bit: VOTE. A multi-bit fault that slips through the
                                            # single-byte test simply never gains a clear lead, and never
                                            # aborts the run. Lock a byte only when one value leads by >= 3.
                                            giraud_obs[byte] += 1
                                            votes[byte].update(pair)
                                            ranked = votes[byte].most_common()
                                            best_value, best_count = ranked[0]
                                            runner_up = ranked[1][1] if len(ranked) > 1 else 0
                                            row.update(before=giraud_obs[byte], remaining=[best_value])
                                            row["detail"] = f"vote leader {best_value:02X}={best_count} (next {runner_up}), {giraud_obs[byte]} observations"

                                            if best_count - runner_up >= 3:
                                                survivors[byte] = {best_value}
                                            row["status"] = "dfa_compatible"
                                        else:
                                            # Input-word (known mask): a hard intersection is correct, and an
                                            # empty one means the model/setup is wrong, so it stops the run.
                                            previous = survivors.get(byte, set(range(256)))
                                            remaining = previous & pair
                                            signature = (model, byte, mask, observation["delta_b"])
                                            row.update(before=len(previous), remaining=sorted(remaining))

                                            if signature in seen:
                                                row.update(status="duplicate", detail="Repeated differential equation; no new candidate information.")
                                            elif not remaining:
                                                row.update(status="model_conflict", detail="Candidate intersection is empty; stop and re-evaluate the fault model.")
                                            else:
                                                seen.add(signature)
                                                survivors[byte] = remaining
                                                row["status"] = "dfa_compatible"

                            statuses[row["status"]] += 1
                            records.append(row)
                            writer.writerow(row)
                            stream.flush()
                            tone = "cyan"

                            if row["status"] == "dfa_compatible":
                                tone = "green"
                            elif row["status"] != "correct":
                                tone = "red"

                            log.line(f"Trial {row['trial']}: width={row['width_actual']}, offset={row['offset_actual']}, delay={delay} -> {row['status']}", tone)

                            if row.get("faulty"):
                                log.line("  Faulty ciphertext: " + row["faulty"], tone)
                                log.line("  XOR vs baseline:   " + row["xor"], tone)

                            # Rejected faults: say WHY, so the operator can retune the sweep.
                            if row["status"] == "faulty_rejected" and row.get("detail"):
                                log.line("  Rejected: " + row["detail"], "red")

                            # Usable faults: print the full DFA breakdown, step by step.
                            if row["status"] in ("dfa_compatible", "duplicate", "model_conflict"):
                                if row.get("model") == "giraud-sbox-input":
                                    log.line(f"  Observed fault: S-box input of round {args.round}, byte {row['byte']}, single-bit (Giraud, unknown bit)", tone)
                                    log.line(f"  Newest-word diff {row['newest_word_diff']}  ->  L_inv = {row['delta_b']}  =>  S-box output diff d={row['sbox_output_diff']} (byte {row['byte']})", tone)
                                    log.line(f"  Public q={row['q']}  ->  keep k with some 1-bit e: S(q XOR k) XOR S(q XOR k XOR e) = d", tone)
                                else:
                                    word_index = args.round + row["input_word"]
                                    log.line(f"  Observed fault: input word X{word_index}, byte {row['byte']}, input mask {row['observed_mask']}", tone)
                                    log.line(f"  Newest-word diff {row['newest_word_diff']}  ->  L_inv = {row['delta_b']}  =>  S-box output diff d={row['sbox_output_diff']} (byte {row['byte']})", tone)
                                    log.line(f"  Public q={row['q']}, q'={row['q_faulty']}  ->  solve S(q XOR k) XOR S(q' XOR k) = d", tone)
                                pair_hex = " ".join(f"{k:02X}" for k in row["pair_candidates"])
                                log.line(f"  Candidates from this pair ({len(row['pair_candidates'])}): {pair_hex}", tone)
                                if row.get("model") == "giraud-sbox-input":
                                    locked = "LOCKED" if row["byte"] in survivors else "not locked yet (need lead >= 3)"
                                    log.line(f"  Vote byte {row['byte']}: {row['detail']} -> {locked}", tone)
                                else:
                                    remain_hex = " ".join(f"{k:02X}" for k in row["remaining"])
                                    log.line(f"  Intersect byte {row['byte']}: {row['before']} -> {len(row['remaining'])}  survivors: {remain_hex}", tone)

                            if row["status"] == "dfa_compatible":
                                # Show progress across the four bytes of this round key.
                                have = {b: next(iter(survivors[b])) for b in survivors if len(survivors[b]) == 1}
                                known = " ".join(f"b{b}={have[b]:02X}" for b in sorted(have)) or "none yet"
                                log.line(f"  rk{args.round} bytes uniquely known so far: {known}", "green")

                            if row["status"] == "model_conflict":
                                raise RuntimeError(row["detail"])

                            complete = len(survivors) == 4

                            for values in survivors.values():
                                if len(values) != 1:
                                    complete = False

                            if complete:
                                break

                        if complete or len(records) >= count:
                            break

                    if complete or len(records) >= count:
                        break

                if complete or len(records) >= count:
                    break

        if complete:
            subkey = bytearray(4)

            for byte in range(4):
                subkey[byte] = next(iter(survivors[byte]))

            keys[args.round] = int.from_bytes(subkey, "big")
            log.line(f"Model-dependent candidate rk{args.round} = {keys[args.round]:08X}", "green")

            all_tail_keys = True

            for number in range(28, 32):
                if number not in keys:
                    all_tail_keys = False

            if all_tail_keys:
                final_keys = []

                for number in range(28, 32):
                    final_keys.append(keys[number])

                master = piret_sm4.reverse_sm4(final_keys)

                if sm4.sm4_encrypt_block(args.input, master) != baseline:
                    # Do not export the newly completed subkey as reusable after
                    # the combined master candidate contradicts the baseline.
                    keys.pop(args.round, None)
                    raise RuntimeError("Master-key candidate failed re-encryption. Physical fault assumptions were insufficient.")

                verified_master = True
                log.line("Verified master key: " + master.hex().upper(), "green")
        else:
            log.line("No unique full subkey in this campaign. This does not prove the target is resistant.")

        log.line("Outcome counts: " + str(dict(statuses)))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        log.line(f"ERROR: {error}", "red")
        return 1
    finally:
        # Hardware cleanup comes before file I/O, so a full disk cannot leave a
        # voltage driver enabled or the target clock routed through the glitcher.
        try:
            try:
                if scope is not None:
                    disable_attack(scope)
                    scope.io.nrst = "low"
                    time.sleep(0.05)
                    scope.io.nrst = "high_z"
            finally:
                try:
                    if target is not None:
                        target.dis()
                finally:
                    if scope is not None:
                        scope.dis()
        finally:
            try:
                if not args.dry_run:
                    saved_keys = {}

                    for number, value in keys.items():
                        saved_keys[str(number)] = f"{value:08X}"

                    saved_survivors = {}

                    for byte, values in survivors.items():
                        saved_survivors[str(byte)] = sorted(values)

                    document = dict(method=kind, round=args.round, master_key_verified=verified_master, plaintext=args.input.hex(), correct=None, round_keys=saved_keys, survivors=saved_survivors, counts=dict(statuses), trials=records)

                    if baseline is not None:
                        document["correct"] = baseline.hex()

                    # Persist partial acquisition after timeout or interruption.
                    (output / (name + "_recovery.json")).write_text(json.dumps(document, indent=2), encoding="utf-8")
            finally:
                if own_log:
                    log.close()

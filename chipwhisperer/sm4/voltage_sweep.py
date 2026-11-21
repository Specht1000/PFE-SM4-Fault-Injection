"""Voltage-glitch CHARACTERIZATION sweep (a "fault map"), not a full attack.

The voltage crowbar's fault zone on this board is narrow and sits between
"too weak" (every trial `correct`) and "too strong" (every trial `no-response`).
Integer `repeat` steps are coarse, so this tool sweeps driver x repeat x width on
round 31 and tallies, per cell, how many trials were correct / faulted /
no-response. It does NOT try to recover the key: the goal is to find a (driver,
repeat, width) cell that actually FAULTS, then run the real attack there:

  python chipwhisperer/sm4/voltage_sweep.py
  # read the fault map, pick a FAULTING cell, then:
  python chipwhisperer/sm4/voltage_glitch.py --driver hp --widths 30 --offsets 0 --repeat 10

Wiring first: the scope's Glitch SMA must reach the target's VCC-glitch path. If
every cell is 100% `correct` at every repeat (including 10), the crowbar is not
wired to VDD -- a software flag cannot fault an unconnected supply.

Output: logs/voltage_sweep.txt / .html.
"""
import argparse
import time

import voltage_glitch
from client import SessionLog, exchange
from glitch_common import acquire, decimal_values, delay_values, disable_attack, parse_block, reset_target
import sm4
from stuck_at_recover import setup_glitch


def _cell(scope, target, args, driver, width, baseline, log):
    """Sweep offsets x delays at one (driver, repeat, width); return outcome counts."""
    counts = {"correct": 0, "fault": 0, "no_response": 0}
    faults = []
    last_off = None
    for offset in args.offsets:
        if last_off != (width, offset):
            disable_attack(scope)
            scope.glitch.width = width
            scope.glitch.offset = offset
            time.sleep(0.05)
            _p1, _p2, lock1, lock2 = scope.glitch.readStatus()
            if not lock1 or not lock2:
                raise RuntimeError("The glitch clock DCMs are not locked.")
            last_off = (width, offset)
        for delay in args.delays:
            scope.glitch.ext_offset = delay
            reset_target(scope, target, args.key, 31)
            try:
                voltage_glitch.configure_attack(scope, driver)
                data, status, _detail = acquire(scope, target, args.input, args.timeout)
            finally:
                disable_attack(scope)
            if status != "received":
                counts["no_response"] += 1
            elif bytes(data) == baseline:
                counts["correct"] += 1
            else:
                counts["fault"] += 1
                if bytes(data) not in faults:
                    faults.append(bytes(data))
    return counts, faults


def run(args, connect):
    log = SessionLog("voltage_sweep")
    scope = target = None
    hits = []
    try:
        log.line("VOLTAGE GLITCH CHARACTERIZATION (fault map, round 31)", "green")
        scope, target, _cw = connect(args)
        scope.default_setup(verbose=False)
        scope.clock.clkgen_freq = 7372800
        target.baud = 38400

        reset_target(scope, target, args.key, 31)
        baseline = exchange(target, "p", args.input, 16)
        if baseline != sm4.sm4_encrypt_block(args.input, args.key):
            raise RuntimeError("Clean baseline does not match SM4. No glitches applied.")
        log.line("Clean baseline: " + baseline.hex().upper(), "green")
        per_cell = max(1, len(args.offsets) * len(args.delays))
        log.line(f"Sweeping drivers={args.drivers} repeats={args.repeats} "
                 f"widths={[round(w, 2) for w in args.widths]}  ({per_cell} trials/cell)")
        log.line("driver  repeat  width   correct  fault  no-resp   verdict", "cyan")

        for driver in args.drivers:
            for repeat in args.repeats:
                setup_glitch(scope, repeat)
                for width in args.widths:
                    counts, faults = _cell(scope, target, args, driver, width, baseline, log)
                    if counts["fault"] > 0:
                        verdict = "FAULT ZONE"
                    elif counts["no_response"] > counts["correct"]:
                        verdict = "too strong"
                    else:
                        verdict = "too weak"
                    color = "green" if counts["fault"] else "red"
                    log.line(f"{driver:>5}  {repeat:>6}  {width:>6.2f}  {counts['correct']:>7}  "
                             f"{counts['fault']:>5}  {counts['no_response']:>7}   {verdict}", color)
                    if counts["fault"]:
                        hits.append((driver, repeat, width, counts, faults[:3]))

        log.line("", "green")
        if hits:
            log.line("FAULTING CELLS (use one of these for the real attack):", "green")
            for driver, repeat, width, counts, faults in hits:
                log.line(f"  --driver {driver} --repeat {repeat} --widths {width:.4f} --offsets "
                         f"{args.offsets[0]}   ({counts['fault']} fault(s), e.g. {faults[0].hex().upper()})",
                         "cyan")
            best = max(hits, key=lambda h: h[3]["fault"])
            log.line("Then recover with, e.g.:", "green")
            log.line(f"  python chipwhisperer/sm4/voltage_glitch.py --driver {best[0]} "
                     f"--repeat {best[1]} --widths {best[2]:.4f} --offsets {args.offsets[0]}", "cyan")
        else:
            log.line("No faults anywhere in the swept grid.", "red")
            log.line("If even repeat 10 / widest width is 100% 'correct', the Glitch SMA is probably "
                     "not wired to the target's VCC-glitch path (check the hardware), or the range is "
                     "still too weak: widen --widths and add --repeats 10, and try --drivers hp.", "red")
            log.line("If cells flip straight from 'too weak' to 'too strong' with no fault zone, step "
                     "--widths more finely between those two widths.", "red")
        return 0 if hits else 3
    except KeyboardInterrupt:
        log.line("Interrupted.", "red")
        return 130
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


def _int_list(text):
    return [int(v) for v in str(text).split(",") if v != ""]


def _driver_list(text):
    out = [d.strip() for d in str(text).split(",") if d.strip()]
    for d in out:
        if d not in ("lp", "hp"):
            raise argparse.ArgumentTypeError("drivers must be lp and/or hp")
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description="Voltage-glitch characterization fault map (round 31).")
    p.add_argument("--key", type=parse_block, default=sm4.KEY)
    p.add_argument("--input", type=parse_block, default=sm4.PLAINTEXT)
    # Coarse-to-fine: both drivers, repeats around the known 9/10 transition, wide widths.
    p.add_argument("--drivers", type=_driver_list, default="lp,hp")
    p.add_argument("--repeats", type=_int_list, default="8,9,10")
    p.add_argument("--widths", type=decimal_values, default="10,20,30,40,45")
    p.add_argument("--offsets", type=decimal_values, default="0")
    # A few delays so some cycle inside round 31 is actually hit.
    p.add_argument("--delays", type=delay_values, default="0:160:20")
    p.add_argument("--timeout", type=int, default=500)
    p.add_argument("--serial-number")
    args = p.parse_args(argv)
    for r in args.repeats:
        if not 1 <= r <= 10:
            p.error("repeats must be in 1..10")
    return run(args, _connect)


if __name__ == "__main__":
    raise SystemExit(main())

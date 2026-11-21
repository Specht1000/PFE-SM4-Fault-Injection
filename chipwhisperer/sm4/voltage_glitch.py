"""DFA attack on the SM4 chip via VOLTAGE glitching: recover the master key.

One of the two DFA attack entry points (the other is clock_glitch.py). It drives a
voltage crowbar glitch (glitch_only, LP/HP driver), collects instruction-skip /
stuck-at faults over rounds 31..28, and runs the stuck-at solver, which recovers
the full SM4 master key (verified by re-encryption) whenever clean single-byte
faults are obtained. On the project's board this route did not fault (every trial
was "correct"), so it did not recover the key; the solver is validated in the
Python simulation. The shared recovery engine is stuck_at_recover.py.

A crowbar needs a STRONG pulse, so this entry point injects wide-width defaults
(override them freely). If every trial is "correct" the pulse is too weak (raise
widths/repeat, try --driver hp); if many are "no-response" it is too strong. The
scope's Glitch SMA must be wired to the target's VCC-glitch path.

Run (board connected):
  python chipwhisperer/sm4/voltage_glitch.py --driver lp
Output: logs/voltage_glitch.txt / .html, plus the recovered key if found.
"""
import sys

import stuck_at_recover

# Voltage crowbar starting regime (wide positive widths, a few repeats). The clock
# The voltage fault zone is narrow and sits between "too weak" (all correct) and
# "too strong" (all no-response/reset). On the project's board repeat 8 was too
# weak and repeat 10 too strong, so the default brackets the zone at repeat 9 and
# sweeps a range of widths across the transition. Override freely while tuning.
VOLTAGE_DEFAULTS = {"--widths": "15,20,25,30,35,40,45", "--offsets": "0,20", "--repeat": "9"}


def configure_attack(scope, driver):
    # Keep the normal target clock. Route a short pulse to ONE crowbar MOSFET.
    # The scope's Glitch SMA must be connected to the target's intended VCC path.
    scope.io.hs2 = "clkgen"
    scope.glitch.output = "glitch_only"

    if driver == "hp":
        scope.io.glitch_hp = True
    else:
        scope.io.glitch_lp = True


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    for flag, value in VOLTAGE_DEFAULTS.items():
        if flag not in argv:
            argv = [flag, value] + argv
    return stuck_at_recover.main(argv, method="voltage", log_name="voltage_glitch")


if __name__ == "__main__":
    raise SystemExit(main())

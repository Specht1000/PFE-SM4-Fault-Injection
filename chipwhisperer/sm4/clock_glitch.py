"""DFA attack on the SM4 chip via CLOCK glitching: recover the master key.

One of the two DFA attack entry points (the other is voltage_glitch.py). It drives
a clock glitch (clock_xor on HS2), collects instruction-skip / stuck-at faults over
rounds 31..28, and runs the stuck-at solver, which recovers the full SM4 master
key (verified by re-encryption) whenever clean single-byte faults are obtained.
On the project's board this route reached the fault zone but produced only
multi-byte faults, so it did not recover the key there; the solver is validated in
the Python simulation. The shared recovery engine is stuck_at_recover.py.

Run (board connected):
  python chipwhisperer/sm4/clock_glitch.py
Output: logs/clock_glitch.txt / .html, plus the recovered key if found.
"""
import stuck_at_recover


def configure_attack(scope, driver):
    # Forward the scope-generated clock through its XOR glitch block.
    # The target must use the clock supplied on HS2, as in the normal client.
    scope.glitch.output = "clock_xor"
    scope.io.hs2 = "glitch"


def main(argv=None):
    return stuck_at_recover.main(argv, method="clock", log_name="clock_glitch")


if __name__ == "__main__":
    raise SystemExit(main())

"""Run every board attack in sequence and collect them in ONE combined log.

Each individual campaign still writes its own evidence files
(logs/clock_glitch.* and logs/voltage_glitch.*, CSV and recovery JSON). This
runner adds a single shared, colour-coded session log, logs/all_attacks.txt and
logs/all_attacks.html, that contains the clock campaign followed by the voltage
campaign, so all board attacks appear together.

All command-line options of the individual campaigns are accepted and forwarded
to both (``--driver`` is used only by the voltage campaign):

  python chipwhisperer/sm4/all_attacks.py --dry-run
  python chipwhisperer/sm4/all_attacks.py --round 31 --max-trials 200

The process exit code is nonzero if any campaign reported an error.
"""
import sys
import clock_glitch
import voltage_glitch
from glitch_common import run_campaign, SessionLog

# The board attacks to run, in order: (label, kind, configure function).
ATTACKS = (
    ("CLOCK GLITCH", "clock", clock_glitch.configure_attack),
    ("VOLTAGE GLITCH", "voltage", voltage_glitch.configure_attack),
)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)

    # One shared log for every attack in this run.
    log = SessionLog("all_attacks")
    status = 0

    try:
        log.line("ALL BOARD ATTACKS - combined session log", "green")
        log.line("Individual CSV/JSON evidence is still written per method.")

        for label, kind, configure in ATTACKS:
            log.line("")
            log.line("=" * 60)
            log.line(f">>> {label} CAMPAIGN", "green")
            log.line("=" * 60)
            # Pass the shared log so this campaign writes into the combined file.
            result = run_campaign(kind, configure, argv, log=log)
            if result != 0:
                status = result

        log.line("")
        log.line("=" * 60)
        if status == 0:
            log.line("All board attacks finished.", "green")
        else:
            log.line("At least one campaign reported an error; see above.", "red")
    finally:
        log.close()

    return status


if __name__ == "__main__":
    raise SystemExit(main())

"""Comparison of the two physical glitch campaigns (clock vs voltage).

Clock figures are parsed from the successful board run logs/clock_glitch.txt
(the per-round summary lines plus the final "Re-encryption check: PASS").
Voltage figures come from logs/voltage_glitch_recovery.json.

Result on the project's board:
  * CLOCK glitch recovered the full SM4 master key, verified by re-encryption.
  * VOLTAGE glitch did not fault (every trial "correct").

Run:  python analysis/glitch_results_compare.py
Out:  analysis/results/glitch/results_compare.{png,svg}
"""
import json
import os
import re

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(__file__)
LOGS = os.path.join(HERE, "..", "logs")
OUT = os.path.join(HERE, "results", "glitch")
os.makedirs(OUT, exist_ok=True)

INK = "#1b2430"
GRID = "#d7dee8"
C_CORRECT = "#9aa7b8"   # grey   = no effect (too weak)
C_RESET = "#b03a3a"     # red    = reset / no-response (too strong)
C_FAULT = "#17a398"     # teal   = fault landed (usable: key recovered on clock)


def clock_counts():
    """Totals from the successful clock run (per-round summary lines)."""
    t = open(os.path.join(LOGS, "clock_glitch.txt"), encoding="utf-8").read()
    tot = {"correct": 0, "reset": 0, "trials": 0}
    for m in re.finditer(r"Round \d+: \d+ distinct fault\(s\) from (\d+) trials "
                         r"\(correct=(\d+), no-response=(\d+), invalid=(\d+)\)", t):
        tr, c, nr, _ = map(int, m.groups())
        tot["trials"] += tr; tot["correct"] += c; tot["reset"] += nr
    tot["fault"] = tot["trials"] - tot["correct"] - tot["reset"]
    tot["recovered"] = "Re-encryption check: PASS" in t
    return tot


def voltage_counts():
    d = json.load(open(os.path.join(LOGS, "voltage_glitch_recovery.json")))
    c = d["counts"]
    total = len(d["trials"]) if isinstance(d.get("trials"), list) else sum(c.values())
    return {"correct": c.get("correct", 0),
            "reset": c.get("timeout_or_reset", 0),
            "fault": c.get("faulty_rejected", 0) + c.get("fault", 0),
            "trials": total,
            "recovered": bool(d.get("master_key_verified"))}


def main():
    clock = clock_counts()
    volt = voltage_counts()

    fig, ax = plt.subplots(figsize=(8.8, 5.0))
    labels = ["Clock glitch\n(clock_xor on HS2)", "Voltage glitch\n(crowbar, glitch_only)"]
    x = [0, 1]
    data = [clock, volt]

    segs = [("correct", C_CORRECT, "correct  (no effect - too weak)"),
            ("reset", C_RESET, "no-response / reset  (too strong)"),
            ("fault", C_FAULT, "fault landed  (single-byte - usable)")]

    bottoms = [0, 0]
    centers = {}
    for key, color, lab in segs:
        vals = [d[key] for d in data]
        ax.bar(x, vals, 0.55, bottom=bottoms, color=color, label=lab,
               edgecolor="white", linewidth=0.8)
        for i, v in enumerate(vals):
            centers[(key, i)] = bottoms[i] + v / 2
            if v >= 40:
                ax.text(i, bottoms[i] + v / 2, str(v), ha="center", va="center",
                        color="white", fontsize=11, weight="bold")
        bottoms = [bt + v for bt, v in zip(bottoms, vals)]

    for i, d in enumerate(data):
        ax.text(i, d["total"] if "total" in d else d["trials"], "", ha="center")
        ax.text(i, d["trials"] + 6, f"{d['trials']} trials", ha="center",
                va="bottom", color=INK, fontsize=10, weight="bold")

    ymax = max(clock["trials"], volt["trials"])

    # Clock: callout for the usable faults and the verified recovery.
    ax.annotate(f"{clock['fault']} faults landed, incl. clean single-byte faults\n"
                "-> all 16 key bytes recovered",
                xy=(0.275, centers[("fault", 0)]), xytext=(0.42, ymax * 0.70),
                fontsize=9, color=C_FAULT, va="center", ha="left", weight="bold",
                arrowprops=dict(arrowstyle="-", color=INK, lw=0.9))
    ax.annotate("MASTER KEY RECOVERED\n& verified (re-encryption PASS)",
                xy=(0.0, clock["trials"]), xytext=(0.0, ymax * 1.06),
                fontsize=10, color=C_FAULT, va="bottom", ha="center", weight="bold")

    # Voltage: crowbar works (resets at higher strength) but no usable fault window.
    ax.annotate("no usable fault\n(weak <-> reset knife-edge)",
                xy=(1.0, volt["trials"] * 0.5), xytext=(1.0, ymax * 1.06),
                fontsize=9.5, color=C_RESET, va="bottom", ha="center", weight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylabel("number of trials", color=INK)
    ax.set_ylim(0, ymax * 1.22)
    ax.set_facecolor("white")
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=INK)
    ax.grid(True, axis="y", color=GRID, linewidth=0.8, alpha=0.7)
    ax.set_axisbelow(True)
    ax.set_title("Physical glitch campaigns on STM32F303: outcome per trial",
                 fontsize=13.5, weight="bold", color=INK)
    ax.legend(frameon=False, fontsize=9, loc="upper center",
              bbox_to_anchor=(0.5, -0.14), ncol=3, columnspacing=1.6,
              handletextpad=0.5)

    note = ("Clock glitch (width ~ -7.8%, offset ~ -39.8%): 13 single-byte faults on round 31, reused for rounds "
            "30-28, recovered\nrk31..rk28 and the master key 0123456789ABCDEFFEDCBA9876543210 (verified). "
            "Voltage crowbar is wired and resets the target at higher strength, but the weak<->reset "
            "transition\nleaves no usable single-byte fault window at the available tuning.")
    ax.text(0.0, -0.28, note, transform=ax.transAxes, fontsize=9, color=INK, va="top")

    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(OUT, f"results_compare.{ext}"), dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("wrote", os.path.join(OUT, "results_compare.png"))
    print("clock:", clock)
    print("voltage:", volt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

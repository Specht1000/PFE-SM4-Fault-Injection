"""Honest comparison of the two physical glitch campaigns (clock vs voltage).

Reads the real campaign artifacts logs/clock_glitch_recovery.json and
logs/voltage_glitch_recovery.json and renders a single slide-ready figure
showing, for each route, the per-trial outcome distribution and whether any
exploitable single-byte fault / master-key recovery was obtained.

On the project's board NEITHER route recovered the master key: the clock route
reached the fault zone but every landed fault was multi-byte (not exploitable),
and the voltage route never faulted (every trial was 'correct' = too weak).

Run:  python analysis/glitch_results_compare.py
Out:  analysis/results/glitch/results_compare.{png,svg}
"""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(__file__)
LOGS = os.path.join(HERE, "..", "logs")
OUT = os.path.join(HERE, "results", "glitch")
os.makedirs(OUT, exist_ok=True)

INK = "#1b2430"
GRID = "#d7dee8"
C_CORRECT = "#9aa7b8"   # grey  = no effect (too weak)
C_RESET = "#b03a3a"     # red   = reset/crash (too strong)
C_FAULT = "#e8803a"     # orange = fault landed (but multi-byte / rejected)
C_USABLE = "#17a398"    # teal  = usable single-byte fault (none here)


def load(method):
    with open(os.path.join(LOGS, f"{method}_glitch_recovery.json")) as f:
        d = json.load(f)
    c = d["counts"]
    return {
        "correct": c.get("correct", 0),
        "reset": c.get("timeout_or_reset", 0),
        "fault": c.get("faulty_rejected", 0) + c.get("fault", 0),
        "usable": 0,  # exploitable single-byte faults actually used in recovery
        "verified": bool(d.get("master_key_verified")),
        "total": len(d["trials"]) if isinstance(d.get("trials"), list) else sum(c.values()),
    }


def main():
    clock = load("clock")
    volt = load("voltage")

    fig, ax = plt.subplots(figsize=(8.6, 4.8))
    labels = ["Clock glitch\n(clock_xor on HS2)", "Voltage glitch\n(crowbar, glitch_only)"]
    x = [0, 1]
    data = [clock, volt]

    segs = [("correct", C_CORRECT, "correct  (no effect - too weak)"),
            ("reset", C_RESET, "reset / timeout  (too strong)"),
            ("fault", C_FAULT, "fault landed  (multi-byte - rejected)"),
            ("usable", C_USABLE, "usable single-byte fault")]

    bottoms = [0, 0]
    for key, color, lab in segs:
        vals = [d[key] for d in data]
        bars = ax.bar(x, vals, 0.55, bottom=bottoms, color=color, label=lab,
                      edgecolor="white", linewidth=0.8)
        for i, (b, v) in enumerate(zip(bars, vals)):
            if v > 0:
                ax.text(i, bottoms[i] + v / 2, str(v), ha="center", va="center",
                        color="white", fontsize=10, weight="bold")
        bottoms = [bt + v for bt, v in zip(bottoms, vals)]

    for i, d in enumerate(data):
        ax.text(i, d_total := d["total"], f"{d['total']} trials", ha="center",
                va="bottom", color=INK, fontsize=10, weight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylabel("number of trials", color=INK)
    ax.set_ylim(0, max(clock["total"], volt["total"]) * 1.12)
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
    ax.legend(frameon=False, fontsize=9.5, loc="upper right")

    note = ("Neither route recovered the master key on the board.  Clock reached the fault zone "
            "(11 faults) but all were multi-byte\nand not single-byte exploitable;  voltage never "
            "faulted (every trial 'correct' = pulse too weak / wiring).")
    ax.text(0.0, -0.22, note, transform=ax.transAxes, fontsize=9, color=INK, va="top")

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

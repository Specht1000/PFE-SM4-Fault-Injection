"""Didactic analysis figures for the two SM4 glitch DFA attacks.

Generates four PNG/SVG figures into analysis/results/glitch/:
  1. sbox_ddt       - SM4 S-box Difference Distribution Table (why single-byte
                      faults prune well).
  2. dfa_pruning    - how many key candidates survive per byte vs number of
                      single-byte faults (our simulation), and the stuck-at case.
  3. fault_zone     - the clock and voltage "fault zones" reproduced from Zhang
                      et al., Electronics 2026, 15:5205 (the paper the project cites).
  4. fault_types    - fault-outcome distribution (single-byte / multi-byte / no
                      usable fault), coupled vs voltage-only, from the same paper.

Run:  python analysis/glitch_dfa_analysis.py
"""
import os
import sys

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import sm4

OUT = os.path.join(os.path.dirname(__file__), "results", "glitch")
os.makedirs(OUT, exist_ok=True)

# A small, consistent, accessible palette.
INK = "#1b2430"
GRID = "#d7dee8"
C_CLOCK = "#2f6fed"    # blue  = clock
C_VOLT = "#e8803a"     # orange = voltage
C_ACC = "#17a398"      # teal   = accent / ours
SBOX = sm4.SBOX


def _style(ax):
    ax.set_facecolor("white")
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK, labelsize=10)
    ax.yaxis.label.set_color(INK)
    ax.xaxis.label.set_color(INK)
    ax.title.set_color(INK)
    ax.grid(True, color=GRID, linewidth=0.8, alpha=0.7)
    ax.set_axisbelow(True)


def save(fig, name):
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(OUT, f"{name}.{ext}"), dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("wrote", os.path.join(OUT, name + ".png"))


# --------------------------------------------------------------------------- #
# 1. SM4 S-box Difference Distribution Table
# --------------------------------------------------------------------------- #
def figure_ddt():
    ddt = np.zeros((256, 256), dtype=int)
    for a in range(256):
        sa = SBOX[a]
        for din in range(256):
            ddt[din][sa ^ SBOX[a ^ din]] += 1

    # Drop the trivial din=0 row (all-zero input difference) so the real,
    # sparse structure is visible; cap the colour scale at the true maximum.
    body = ddt[1:, :]
    vmax = int(body.max())
    fig, ax = plt.subplots(figsize=(6.2, 5.4))
    im = ax.imshow(body, cmap="magma", origin="lower", interpolation="nearest",
                   vmin=0, vmax=vmax, extent=[0, 256, 1, 256])
    ax.set_title("SM4 S-box Difference Distribution Table", fontsize=13, weight="bold")
    ax.set_xlabel("output difference $\\Delta$out")
    ax.set_ylabel("input difference $\\Delta$in  (1..255)")
    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04, ticks=range(vmax + 1))
    cbar.set_label("# inputs hitting ($\\Delta$in, $\\Delta$out)", color=INK)
    ax.text(0.0, -0.16,
            f"Entries are only 0, 2 or {vmax} (max = {vmax}): for a known input "
            f"difference, each output difference comes from very few S-box\ninputs, so "
            f"one single-byte fault prunes the last-round key byte to a handful of "
            f"candidates.",
            transform=ax.transAxes, fontsize=9, color=INK, va="top")
    save(fig, "sbox_ddt")


# --------------------------------------------------------------------------- #
# 2. DFA candidate pruning: survivors per byte vs number of faults
# --------------------------------------------------------------------------- #
def figure_pruning(trials=400, max_faults=6, seed=7):
    rng = np.random.default_rng(seed)
    bits = (1, 2, 4, 8, 16, 32, 64, 128)

    def known_mask_survivors(q, k, masks):
        survivors = set(range(256))
        for e in masks:
            d = SBOX[q ^ k] ^ SBOX[q ^ k ^ e]
            fresh = {kk for kk in range(256) if SBOX[q ^ kk] ^ SBOX[q ^ kk ^ e] == d}
            survivors &= fresh
            if len(survivors) == 1:
                break
        return len(survivors)

    curve = np.zeros(max_faults + 1)
    curve[0] = 256
    for n in range(1, max_faults + 1):
        tot = 0
        for _ in range(trials):
            q = int(rng.integers(256)); k = int(rng.integers(256))
            masks = rng.choice(range(1, 256), size=n, replace=False)
            tot += known_mask_survivors(q, k, masks)
        curve[n] = tot / trials

    fig, ax = plt.subplots(figsize=(6.6, 4.4))
    xs = np.arange(max_faults + 1)
    ax.plot(xs, curve, "-o", color=C_CLOCK, lw=2.2, ms=7, label="Piret DFA (known-mask), mean survivors")
    ax.axhline(1, color=C_ACC, lw=1.6, ls="--")
    ax.plot([1], [1], "D", color=C_ACC, ms=9, label="Stuck-at model: 1 clean fault pins the byte")
    _style(ax)
    ax.set_yscale("log")
    ax.set_xlabel("number of single-byte faults on one key byte")
    ax.set_ylabel("surviving key-byte candidates (log)")
    ax.set_title("DFA candidate pruning per key byte", fontsize=13, weight="bold")
    ax.legend(frameon=False, fontsize=9)
    ax.set_xticks(xs)
    save(fig, "dfa_pruning")


# --------------------------------------------------------------------------- #
# 3. Fault zones (reproduced from Zhang et al., Electronics 2026, 15:5205)
# --------------------------------------------------------------------------- #
def figure_fault_zone():
    fig, (axc, axv) = plt.subplots(1, 2, figsize=(11.2, 4.3))

    # Clock FSR vs glitch width (Table 5), a few temperatures.
    widths = [50, 60, 70]
    clk = {25: [0.00, 0.17, 0.83], 85: [0.00, 0.33, 0.78], 125: [0.00, 0.31, 0.83]}
    for t, (temp, ys) in zip((0.45, 0.75, 1.0), clk.items()):
        axc.plot(widths, ys, "-o", color=C_CLOCK, alpha=t, lw=2, ms=6, label=f"{temp} C")
    axc.axvspan(60, 72, color=C_CLOCK, alpha=0.08)
    axc.text(66, 0.05, "fault zone", color=C_CLOCK, fontsize=9, ha="center")
    axc.text(60.5, 0.90, "80 ns: reset (too strong)", color="#b03a3a", fontsize=8.5, ha="left")
    _style(axc)
    axc.set_xlabel("clock glitch width (ns)  [clock period 250 ns]")
    axc.set_ylabel("fault success rate")
    axc.set_title("Clock glitch", fontsize=12, weight="bold")
    axc.legend(frameon=False, fontsize=8, title="temperature")

    # Voltage FSR vs amplitude (Table 4, width 300 ns), a few temperatures.
    amps = [1.6, 1.5, 1.4, 1.3, 1.2]
    volt = {25: [0.00, 0.09, 0.60, 0.89, 1.00], 85: [0.03, 0.34, 0.67, 0.97, np.nan],
            125: [0.14, 0.43, 0.73, 1.00, np.nan]}
    for t, (temp, ys) in zip((0.45, 0.75, 1.0), volt.items()):
        axv.plot(amps, ys, "-o", color=C_VOLT, alpha=t, lw=2, ms=6, label=f"{temp} C")
    axv.axvspan(1.2, 1.45, color=C_VOLT, alpha=0.08)
    axv.text(1.32, 0.05, "fault zone", color=C_VOLT, fontsize=9, ha="center")
    axv.invert_xaxis()  # deeper drop (lower V) to the right
    _style(axv)
    axv.set_xlabel("voltage glitch amplitude (V)  [deeper drop ->]")
    axv.set_ylabel("fault success rate")
    axv.set_title("Voltage glitch (wide 300 ns pulse)", fontsize=12, weight="bold")
    axv.legend(frameon=False, fontsize=8, title="temperature")

    fig.suptitle("Where each glitch actually faults (data: Zhang et al., Electronics 2026, 15:5205)",
                 fontsize=12, weight="bold", color=INK)
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    save(fig, "fault_zone")


# --------------------------------------------------------------------------- #
# 4. Fault-outcome distribution (same paper, Table 8 and voltage-only baseline)
# --------------------------------------------------------------------------- #
def figure_fault_types():
    cats = ["single-byte\n(usable for DFA)", "multi-byte\n(discarded)", "no fault / reset"]
    coupled = [14, 53, 33]        # Table 8 (optimal coupled)
    voltonly = [11, 48, 41]       # voltage-only @25 C
    x = np.arange(len(cats))
    w = 0.38

    fig, ax = plt.subplots(figsize=(7.4, 4.4))
    b1 = ax.bar(x - w/2, coupled, w, color=C_ACC, label="coupled V+C+T (optimal)")
    b2 = ax.bar(x + w/2, voltonly, w, color=C_VOLT, label="voltage-only, 25 C")
    for bars in (b1, b2):
        for b in bars:
            ax.text(b.get_x() + b.get_width()/2, b.get_height() + 1, f"{int(b.get_height())}%",
                    ha="center", fontsize=9, color=INK)
    _style(ax)
    ax.set_ylabel("share of all injections (%)")
    ax.set_xticks(x); ax.set_xticklabels(cats)
    ax.set_ylim(0, 62)
    ax.set_title("Only a small fraction of faults are usable single-byte faults",
                 fontsize=12.5, weight="bold")
    ax.legend(frameon=False, fontsize=9)
    ax.text(0.0, -0.26, "Data: Zhang et al., Electronics 2026, 15:5205. This matches our board: "
            "most faults are multi-byte or no-effect; the stuck-at\nsolver keeps the clean "
            "single-byte ones and votes away the rest.", transform=ax.transAxes, fontsize=9, color=INK, va="top")
    save(fig, "fault_types")


def main():
    figure_ddt()
    figure_pruning()
    figure_fault_zone()
    figure_fault_types()
    print("\nAll figures in", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

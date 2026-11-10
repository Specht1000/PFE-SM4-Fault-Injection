"""Explain subkey and master-key recovery from saved paired SM4 experiments."""
import csv
import json
import os
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import sm4
import piret_sm4
from terminal_log import run_with_log
from compare_sm4_attacks import MODELS, LABELS, COLORS

ROUNDS = (31, 30, 29, 28)


def extract_trial(trial, model):
    """Reconstruct words from unique observed survivors, then check every key."""
    history = trial["models"][model]["history"]
    recovered_bytes = {}
    costs = {}
    milestones = {}

    for number in ROUNDS:
        costs[number] = [0, 0, 0, 0]

    for query, event in enumerate(history, 1):
        number = event["round"]
        byte = event["byte"]
        costs[number][byte] += 1

        # Only a singleton intersection permits a byte to enter the subkey.
        if event["remaining"] == 1:
            recovered_bytes[number, byte] = event["survivors"][0]
            complete_word = True

            for position in range(4):
                if (number, position) not in recovered_bytes:
                    complete_word = False

            if complete_word:
                milestones[number] = query

    words = {}
    stages = []

    # Ground truth is used only after extraction, never to select a survivor.
    reference_key = bytes.fromhex(trial["simulation_key"])
    reference_schedule = sm4.key_expansion(reference_key)

    for number in ROUNDS:
        if number not in milestones:
            break

        word = 0

        for byte in range(4):
            word = (word << 8) | recovered_bytes[number, byte]

        if word != reference_schedule[number]:
            raise ValueError("An observed subkey differs from the reference schedule.")

        words[number] = word
        stages.append(dict(round=number, subkey=f"{word:08X}", byte_costs=costs[number], stage_queries=sum(costs[number]), cumulative_queries=milestones[number]))

    complete = len(words) == 4
    master_hex = None
    schedule_matches = 0

    if complete:
        tail = []

        for number in range(28, 32):
            tail.append(words[number])

        # Reverse the schedule using only the four extracted tail subkeys.
        master = piret_sm4.reverse_sm4(tail)
        regenerated = sm4.key_expansion(master)

        for number in range(32):
            if regenerated[number] == reference_schedule[number]:
                schedule_matches += 1

        plaintext = bytes.fromhex(trial["plaintext"])
        ciphertext = bytes.fromhex(trial["correct"])

        if master != reference_key or schedule_matches != 32:
            raise ValueError("Master-key or full schedule verification failed.")

        if sm4.sm4_encrypt_block(plaintext, master) != ciphertext or sm4.sm4_decrypt_block(ciphertext, master) != plaintext:
            raise ValueError("Recovered key failed encrypt/decrypt verification.")

        master_hex = master.hex().upper()

    return dict(trial=trial["trial"], model=model, stages=stages, complete=complete, master_key=master_hex, matching_schedule_words=schedule_matches)


def generate(out, report):
    """Export verified per-stage data and charts without repeating timing trials."""
    os.environ.setdefault("MPLCONFIGDIR", str(ROOT / ".build" / "matplotlib"))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages

    records = []

    for trial in report["trials"]:
        for model in MODELS:
            records.append(extract_trial(trial, model))

    (out / "key_recovery.json").write_text(json.dumps(records, indent=2), encoding="utf-8")

    with (out / "subkey_recovery.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["trial", "model", "round", "recovered_subkey", "byte0_queries", "byte1_queries", "byte2_queries", "byte3_queries", "stage_queries", "cumulative_queries"])

        for record in records:
            for stage in record["stages"]:
                writer.writerow([record["trial"], record["model"], stage["round"], stage["subkey"], *stage["byte_costs"], stage["stage_queries"], stage["cumulative_queries"]])

    figures = out / "figures"
    figures.mkdir(exist_ok=True)
    lines = ["# SM4 subkey and master-key recovery analysis", "", "These analyses reuse the saved paired experiments. No timing trial or target fault is rerun. Subkeys are reconstructed from singleton candidate intersections, not copied from the simulation key. The reference key is used afterwards for validation.", "", "## Stage costs and recovery milestones", "", "| Model | Subkey | Mean queries for this stage | Median cumulative queries | Cumulative range |", "| --- | --- | --- | --- | --- |"]
    metrics = {}

    for model in MODELS:
        metrics[model] = {}

        for number in ROUNDS:
            stages = []

            for record in records:
                if record["model"] == model:
                    for stage in record["stages"]:
                        if stage["round"] == number:
                            stages.append(stage)

            stage_costs = []
            cumulative = []
            byte_means = []

            for stage in stages:
                stage_costs.append(stage["stage_queries"])
                cumulative.append(stage["cumulative_queries"])

            for byte in range(4):
                values = []

                for stage in stages:
                    values.append(stage["byte_costs"][byte])

                byte_means.append(statistics.mean(values))

            metrics[model][number] = dict(mean=statistics.mean(stage_costs), median=statistics.median(cumulative), low=min(cumulative), high=max(cumulative), bytes=byte_means)
            item = metrics[model][number]
            lines.append(f"| {model} | rk{number} | {item['mean']:.2f} | {item['median']:g} | {item['low']}–{item['high']} |")

    with PdfPages(out / "key_recovery.pdf") as pdf:
        def save(fig, name):
            fig.tight_layout(rect=(0, 0, 1, 0.94))
            fig.savefig(figures / (name + ".png"), dpi=180)
            fig.savefig(figures / (name + ".svg"))
            pdf.savefig(fig)
            plt.close(fig)

        # Separate panels keep equal known-mask results visible.
        fig, axes = plt.subplots(2, 2, figsize=(12, 8), sharey=True)

        for index, model in enumerate(MODELS):
            ax = axes.flat[index]
            means = []

            for number in ROUNDS:
                means.append(metrics[model][number]["mean"])

            bars = ax.bar(["rk31", "rk30", "rk29", "rk28"], means, color=COLORS[index])
            ax.bar_label(bars, fmt="%.2f")
            ax.set_title(LABELS[index])
            ax.set_ylabel("Mean faulty queries for this subkey")
            ax.set_ylim(0, max(12, max(means) + 2))

        fig.suptitle("1. Cost of recovering each 32-bit subkey")
        save(fig, "04_subkey_cost")

        fig, axes = plt.subplots(2, 2, figsize=(12, 8), sharey=True)

        for index, model in enumerate(MODELS):
            ax = axes.flat[index]
            matrix = []

            for number in ROUNDS:
                matrix.append(metrics[model][number]["bytes"])

            heat = ax.imshow(matrix, vmin=1, vmax=3, cmap="YlGnBu")
            ax.set_xticks(range(4), ["Byte 0", "Byte 1", "Byte 2", "Byte 3"])
            ax.set_yticks(range(4), ["rk31", "rk30", "rk29", "rk28"])
            ax.set_title(LABELS[index])

            for row in range(4):
                for column in range(4):
                    ax.text(column, row, f"{matrix[row][column]:.2f}", ha="center", va="center", color="black", bbox=dict(facecolor="white", alpha=0.8, edgecolor="none"))

            fig.colorbar(heat, ax=ax, label="Mean queries per recovered byte")

        fig.suptitle("2. Where observations are spent: four bytes per subkey")
        save(fig, "05_byte_cost")

        fig, axes = plt.subplots(2, 2, figsize=(12, 8), sharey=True)

        for index, model in enumerate(MODELS):
            ax = axes.flat[index]
            medians, lows, highs = [], [], []

            for number in ROUNDS:
                item = metrics[model][number]
                medians.append(item["median"])
                lows.append(item["low"])
                highs.append(item["high"])

            ax.plot(range(1, 5), medians, marker="o", color=COLORS[index])
            ax.fill_between(range(1, 5), lows, highs, alpha=0.18, color=COLORS[index], label="Observed min–max")
            ax.set_xticks(range(1, 5), ["rk31", "+ rk30", "+ rk29", "+ rk28\nMaster key"])
            ax.set_ylabel("Cumulative faulty queries")
            ax.set_title(LABELS[index])
            ax.legend(fontsize=8)
            ax.grid(alpha=0.2)

        fig.suptitle("3. Recovery milestones: median and observed range")
        save(fig, "06_key_milestones")

        fig, axes = plt.subplots(2, 2, figsize=(12, 8), sharey=True)
        budget_rows = []

        for index, model in enumerate(MODELS):
            ax = axes.flat[index]
            series = [[], [], [], [], []]

            for budget in range(1, 9):
                achieved = [0, 0, 0, 0, 0]

                for trial in report["trials"]:
                    outcome = trial["models"][model]["budgets"][str(budget)]

                    for stage in range(4):
                        if outcome["completed_bytes"] >= 4 * (stage + 1):
                            achieved[stage] += 1

                    if outcome["complete"]:
                        achieved[4] += 1

                rates = []

                for stage in range(5):
                    rate = 100 * achieved[stage] / len(report["trials"])
                    series[stage].append(rate)
                    rates.append(rate)

                budget_rows.append([model, budget, *rates])

            # Grouped bars expose equal rates without drawing one over another.
            for stage in range(5):
                positions = []

                for budget in range(1, 9):
                    positions.append(budget + (stage - 2) * 0.15)

                ax.bar(positions, series[stage], width=0.14, label=["rk31", "rk30", "rk29", "rk28", "Master key"][stage])

            ax.set_title(LABELS[index])
            ax.set_xlabel("Maximum observations per target byte")
            ax.set_ylabel("Trials reaching this milestone (%)")
            ax.set_xticks(range(1, 9))
            ax.legend(fontsize=7, ncol=3)
            ax.set_ylim(0, 122)

        fig.suptitle("4. Partial subkey recovery versus complete master-key recovery")
        save(fig, "07_partial_recovery")

    with (out / "partial_recovery.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["model", "budget_per_byte", "rk31_percent", "rk30_percent", "rk29_percent", "rk28_percent", "master_percent"])
        writer.writerows(budget_rows)

    lines.extend(["", "## Figure 1: individual subkey cost", "", "![Subkey costs](figures/04_subkey_cost.png)", "", "Each bar is the mean number of faulty outputs spent on one 32-bit subkey, excluding previous stages. Four bytes must become unique before that subkey is usable. Compare each round across model panels: extra unknown-bit cost comes from additional candidate ambiguity, not a longer key. Stage means are averaged over reached stages; the present dataset completes all stages in every trial.", "", "## Figure 2: per-byte recovery cost", "", "![Byte costs](figures/05_byte_cost.png)", "", "Rows identify the attacked subkey and columns its big-endian byte position. Each cell is the mean number of observations required for that byte. The color scale is shared across models. This locates where extra queries occur; small differences in this sample do not establish an intrinsically weaker byte position.", "", "## Figure 3: cumulative recovery milestones", "", "![Recovery milestones](figures/06_key_milestones.png)", "", "The line is the median cumulative cost and the shaded area the observed minimum–maximum, not a confidence interval. The known-mask variants reach their four subkeys at 8, 16, 24 and 32 queries in this dataset. rk31 must be recovered before peeling round 31 to attack rk30; the same dependency continues down to rk28. These are recovered subkey words, not successive 32-bit pieces of the master key. Only after all four tail subkeys are known does the inverse schedule produce the complete master key, with no additional faulty outputs.", "", "## Figure 4: partial recovery under a restricted budget", "", "![Partial recovery](figures/07_partial_recovery.png)", "", "At each per-byte budget, grouped bars show the percentage of trials reaching each subkey milestone and the master key. Early stages can succeed while a later byte remains ambiguous. A stage bar means all previous stages also completed because the solver stops at the first unresolved byte. The rk28 and master-key bars coincide because inverse expansion needs no further oracle calls once the four tail words are unique. Zero-height bars represent no completed milestone, not missing data. These restricted-budget results use the recorded histories and the same early-stop reconstruction validated in the comparison tests.", "", "## Master-key and complete-schedule verification", "", "The analysis rebuilds rk31, rk30, rk29 and rk28 from the singleton survivors in each history. It checks every extracted subkey against the independently generated reference schedule, reverses the schedule from those four words, and regenerates all 32 subkeys. It then checks the full master key, encryption and decryption. Ground truth is never used to decide between candidates.", "", "| Model | Verified master keys | Matching regenerated schedule words |", "| --- | --- | --- |"])

    lines.extend(["", "### Restricted budget example: two observations per byte", "", "| Model | rk31 reached (%) | rk30 reached (%) | rk29 reached (%) | rk28 reached (%) | Master key (%) |", "| --- | --- | --- | --- | --- | --- |"])

    for row in budget_rows:
        if row[1] == 2:
            formatted = [row[0]]

            for value in row[2:]:
                formatted.append(f"{value:g}")

            lines.append("| " + " | ".join(formatted) + " |")

    lines.extend(["", "### Independently verified complete recoveries", "", "| Model | Verified master keys | Matching regenerated schedule words |", "| --- | --- | --- |"])

    for model in MODELS:
        verified = 0
        matching = 0

        for record in records:
            if record["model"] == model:
                verified += int(record["complete"])
                matching += record["matching_schedule_words"]

        lines.append(f"| {model} | {verified}/{len(report['trials'])} | {matching}/{32 * len(report['trials'])} |")

    lines.extend(["", "## Example: the first recorded trial", "", "These random demonstration values are simulation secrets, not keys captured from a board.", "", "| Model | rk31 | rk30 | rk29 | rk28 | Recovered master key |", "| --- | --- | --- | --- | --- | --- |"])

    for record in records[:4]:
        values = [record["model"]]

        for stage in record["stages"]:
            values.append(stage["subkey"])

        values.append(str(record["master_key"]))
        lines.append("| " + " | ".join(values) + " |")

    lines.extend(["", "## Reproduce", "", "```powershell", "python analysis/analyze_sm4_recovery.py", "```", "", "Outputs: `key_recovery.pdf`, `key_recovery.json`, `subkey_recovery.csv`, `partial_recovery.csv` and figures 04–07. TXT and colored HTML execution logs are overwritten on each run. These are controlled software experiments; physical fault reliability and acquisition time are not measured."])
    (out / "key_recovery_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Verified {len(records)} trial/model histories; exported subkey and master-key analysis.")


def main():
    out = ROOT / "analysis" / "results" / "sm4_comparison"
    report = json.loads((out / "measurements.json").read_text(encoding="utf-8"))
    generate(out, report)
    print(f"Report: {out / 'key_recovery_report.md'}")
    print(f"PDF: {out / 'key_recovery.pdf'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_with_log(main, "analyze_sm4_recovery"))

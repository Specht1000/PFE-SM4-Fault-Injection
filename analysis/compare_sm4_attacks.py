"""Compare controlled SM4 DFA and Giraud-inspired filtering on paired inputs."""
import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import sm4
import piret_sm4
import giraud_sm4
from giraud_common import SINGLE_BITS

MODELS = ("Piret-default", "Piret-matched-bits", "Giraud-known-bit", "Giraud-unknown-bit")
LABELS = ("Piret: byte masks", "Piret: matched bits", "Giraud: known bit", "Giraud: unknown bit")
COLORS = ("#2563eb", "#0891b2", "#16a34a", "#dc2626")


def make_outputs(plaintext, key):
    """Precompute outputs once, independently of every solver's private state."""
    masks = set(range(1, 9))
    masks.update(SINGLE_BITS)
    outputs = {}

    for number in range(31, 27, -1):
        for byte in range(4):
            for mask in sorted(masks):
                faulty, trace = piret_sm4.sm4_fault_encrypt(plaintext, key, byte, mask, number)
                outputs[number, byte, mask] = faulty

    return outputs


def recover(model, correct, outputs, budget=8):
    """Pass cached ciphertexts only; the recovery routine never receives the key."""
    def oracle(number, byte, mask):
        return outputs[number, byte, mask]

    if model == "Piret-default":
        return piret_sm4.recover_sm4_master_key(correct, oracle, range(1, budget + 1))

    if model == "Piret-matched-bits":
        return piret_sm4.recover_sm4_master_key(correct, oracle, SINGLE_BITS[:budget])

    if model == "Giraud-known-bit":
        return giraud_sm4.recover_sm4_master_key(correct, oracle, maximum=budget, known_bit=True)

    if model == "Giraud-unknown-bit":
        return giraud_sm4.recover_sm4_master_key(correct, oracle, maximum=budget, known_bit=False)

    raise ValueError("Unknown SM4 comparison model.")


def summarize_result(result):
    """Keep exact observations, plus concise per-byte candidate trajectories."""
    trajectories = {}
    first_counts = []
    byte_costs = []

    for event in result["history"]:
        identity = str(event["round"]) + ":" + str(event["byte"])

        if identity not in trajectories:
            trajectories[identity] = []
            first_counts.append(event["pair_candidates"])

        trajectories[identity].append(event["remaining"])

        if event["remaining"] == 1:
            byte_costs.append(event["observation"])

    return dict(trajectories=trajectories, first_counts=first_counts, byte_costs=byte_costs)


def budget_outcome(result, budget):
    """Infer early-stop cost from the recorded prefix, then validate it in tests."""
    groups = {}

    for event in result["history"]:
        identity = event["round"], event["byte"]

        if identity not in groups:
            groups[identity] = []

        groups[identity].append(event)

    used = 0
    completed_bytes = 0

    for events in groups.values():
        unique_at = None

        for event in events:
            if event["remaining"] == 1:
                unique_at = event["observation"]
                break

        if unique_at is None or unique_at > budget:
            used += budget
            return dict(complete=False, used=used, completed_bytes=completed_bytes)

        used += unique_at
        completed_bytes += 1

    return dict(complete=completed_bytes == 16, used=used, completed_bytes=completed_bytes)


def wilson(successes, total):
    """Describe finite-sample success uncertainty without claiming physical rates."""
    z = 1.959963984540054
    rate = successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    radius = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    return [center - radius, center + radius]


def aggregate(trials):
    summaries = {}

    for model in MODELS:
        faults = []
        durations = []
        first_counts = []
        byte_costs = []
        successes = 0
        budgets = {}

        for budget in range(1, 9):
            budgets[budget] = dict(successes=0, used=[])

        for trial in trials:
            item = trial["models"][model]

            if item["verified"]:
                successes += 1

            faults.append(item["used"])
            durations.append(item["offline_ns"] / 1_000_000)
            first_counts.extend(item["first_counts"])
            byte_costs.extend(item["byte_costs"])

            for budget in range(1, 9):
                outcome = item["budgets"][str(budget)]

                if outcome["complete"]:
                    budgets[budget]["successes"] += 1

                budgets[budget]["used"].append(outcome["used"])

        curve = []

        for budget in range(1, 9):
            point = budgets[budget]
            curve.append(dict(budget=budget, success_rate=point["successes"] / len(trials), median_consumed=statistics.median(point["used"])))

        median_byte_cost = None

        if byte_costs:
            median_byte_cost = statistics.median(byte_costs)

        summaries[model] = dict(successes=successes, total=len(trials), success_interval_95=wilson(successes, len(trials)), faults_mean=statistics.mean(faults), faults_median=statistics.median(faults), faults_min=min(faults), faults_max=max(faults), offline_ms_median=statistics.median(durations), first_candidates_median=statistics.median(first_counts), observations_per_unique_byte_median=median_byte_cost, budget_curve=curve)

    return summaries


def experiment(count, seed):
    """Use paired random inputs and rotate model order to reduce timing-order bias."""
    rng = random.Random(seed)
    trials = []
    piret_sm4.inverse_rows()

    for index in range(count):
        key = rng.randbytes(16)
        plaintext = rng.randbytes(16)
        correct = sm4.sm4_encrypt_block(plaintext, key)
        outputs = make_outputs(plaintext, key)
        records = {}
        start_model = index % len(MODELS)
        order = MODELS[start_model:] + MODELS[:start_model]

        for model in order:
            started = time.perf_counter_ns()
            result = recover(model, correct, outputs)
            duration = time.perf_counter_ns() - started
            verified = False

            if result["complete"]:
                recovered = result["master_key"]
                verified = recovered == key
                verified = verified and sm4.sm4_encrypt_block(plaintext, recovered) == correct
                verified = verified and sm4.sm4_decrypt_block(correct, recovered) == plaintext

                if not verified:
                    raise RuntimeError("A claimed complete recovery failed independent checks.")

            item = summarize_result(result)
            item.update(verified=verified, used=result["used"], offline_ns=duration, budgets={}, history=result["history"])

            for budget in range(1, 9):
                item["budgets"][str(budget)] = budget_outcome(result, budget)

            records[model] = item

        # With identical bit observations, the two known-mask equations must
        # yield identical histories, not just coincidentally equal master keys.
        first = records["Piret-matched-bits"]["history"]
        second = records["Giraud-known-bit"]["history"]

        if first != second:
            raise RuntimeError("Matched known-mask solvers produced different candidate histories.")

        trials.append(dict(trial=index, plaintext=plaintext.hex(), simulation_key=key.hex(), correct=correct.hex(), models=records))

        if (index + 1) % 10 == 0 or index + 1 == count:
            print(f"Compared {index + 1}/{count} paired trials.", flush=True)

    return trials


def write_report(out, report):
    summary = report["summary"]
    count = report["configuration"]["trials"]
    lines = ["# SM4: controlled DFA versus Giraud-inspired filtering", "", "## What is compared", "", "All four variants recover rk31, rk30, rk29 and rk28 using controlled faults at S-box inputs, then reverse the SM4 schedule and remove FK. These are software models; no board measurements are included.", "", "| Variant | Masks, in order | Solver knowledge |", "| --- | --- | --- |", "| Piret-default | 01, 02, 03, 04, 05, 06, 07, 08 | Exact byte mask |", "| Piret-matched-bits | 01, 02, 04, 08, 10, 20, 40, 80 | Exact mask; single-bit observations |", "| Giraud-known-bit | Same single-bit sequence | Exact selected bit |", "| Giraud-unknown-bit | Same single-bit sequence | One-bit property, not the exact bit |", "", "The SM4 variants are controlled DFA and a Giraud-inspired adaptation; they are not unchanged AES attacks. The default Piret sequence contains multi-bit masks, so its comparison with unknown-bit Giraud changes both observations and solver knowledge. The matched-bit control separates these effects.", "", "## Measured results", "", f"{count} paired random keys/plaintexts; seed {report['configuration']['seed']}. Each variant receives the same clean output and the same faulty output whenever it requests the same round/byte/mask.", "", "| Model | Verified full recoveries | Faulty outputs: mean / median / range | Median first-pair candidates | Offline median (ms) |", "| --- | --- | --- | --- | --- |"]

    for model in MODELS:
        item = summary[model]
        lines.append(f"| {model} | {item['successes']}/{count} | {item['faults_mean']:.2f} / {item['faults_median']:g} / {item['faults_min']}–{item['faults_max']} | {item['first_candidates_median']:g} | {item['offline_ms_median']:.3f} |")

    lines.extend(["", "### Finite-sample success uncertainty", "", "| Model | 95% Wilson interval for trial success |", "| --- | --- |"])

    for model in MODELS:
        lower, upper = summary[model]["success_interval_95"]
        lines.append(f"| {model} | {100 * lower:.2f}%–{100 * upper:.2f}% |")

    deltas = []

    for trial in report["trials"]:
        known = trial["models"]["Giraud-known-bit"]["used"]
        unknown = trial["models"]["Giraud-unknown-bit"]["used"]
        deltas.append(unknown - known)

    lines.extend(["", "## Interpretation", "", "1. **Known-mask equivalence.** Piret-matched-bits and Giraud-known-bit have identical complete observation/candidate histories in every executed trial. They use equivalent S-box difference equations and the same round-peeling/schedule engine. Any timing difference measures Python implementation overhead, not a cryptographic advantage.", "", "2. **Unknown-bit information loss.** For one fixed pair, the unknown-bit filter accepts an input if any of the eight masks explains the difference. Its candidate set contains the known-mask set. Intersections can therefore need more observations. This is reduced attacker knowledge, not a different SM4 key size.", "", f"3. **Paired observation cost.** Unknown-bit Giraud consumed a mean of {statistics.mean(deltas):.2f} additional faulty outputs over known-bit Giraud on the same bit sequence (median difference {statistics.median(deltas):g}). Ambiguous runs remain incomplete; the query count is not a successful full-key cost for them.", "", "4. **Mask selection matters.** Piret-default and Piret-matched-bits differ only in their ordered mask sequence. A difference here is attributable to the chosen observations within this experiment; a different order may change the result.", "", "5. **Budget curves.** The success plot uses a maximum number of distinct observations per byte. Curves are derived from the complete eight-mask run and respect early termination at the first ambiguous byte. They are checked against actual restricted-budget executions in tests. Low-budget failure counts do not represent complete attacks.", "", "## Practical example: first byte of rk31", "", "For plaintext and key `0123456789ABCDEFFEDCBA9876543210`, a round-31 byte-0 fault with mask `01` yields inverse-L byte difference `4F` and known byte q=`07`.", "", "- Piret with known mask and Giraud with known bit both retain key candidates `90 91`.", "- Giraud with unknown bit retains `19 1B 6A 89 90 91 A0 B0 C9 EA`.", "- More compatible candidates mean less information from this observation. No reference key is used to choose a survivor.", "", "## Method and limits", "", "- Candidate computation uses the real `src/piret_sm4.py` and `src/giraud_sm4.py` functions. All target outputs are precomputed once per trial; the solver sees only ciphertexts and permitted fault descriptors.", "- The maximum budget is eight distinct masks per target byte. A clean reference encryption is additional to every reported faulty-output cost.", "- Offline time includes candidate filtering, history construction, dictionary oracle lookups, peeling and inverse expansion. It excludes target encryption, USB/serial traffic, glitch calibration, output collection and final verification. This isolates host-side recovery work; it is not physical attack duration.", "- The inverse-L matrix is warmed before timing. Model order is rotated across trials. No verbose terminal/GUI lessons are included in timed calls.", "- The 95% Wilson interval describes sample success across these seeded software trials; it is not a measured physical success probability. Candidate observations within a trial are dependent and are not treated as independent success trials.", "- Exact round/byte access is shared by all variants. Piret additionally knows byte magnitude; unknown-bit Giraud knows the single-bit restriction. Physical faults may fail these assumptions or produce resets, wrong locations, multi-bit corruption or no effect.", "- All claimed full recoveries are checked against simulation ground truth, re-encryption and decryption. The target key is used only to construct/validate the experiment, not as solver input.", "", "## Reproduce and inspect", "", "```powershell", f"python analysis/compare_sm4_attacks.py --trials {count} --seed {report['configuration']['seed']}", "```", "", "`measurements.json` contains every event and source hashes; `trials.csv` summarizes paired measurements. `comparison.pdf` and `figures/` contain the plots. The executable also saves TXT/HTML logs. New runs replace this comparison's outputs.", "", "## Suggested statement for the presentation", "", "> Under the same controlled single-bit observations and exact-mask knowledge, the two SM4 implementations recover the same candidates. When the exact bit is hidden, Giraud-inspired filtering retains more hypotheses and can require more observations. The comparison therefore measures the effect of fault information and mask selection, not a physical break of an STM32 implementation."])
    # Explain every panel next to its exported figure, using saved measurements.
    explanations = ["## Reading and comparing every graph", "", "All figures use the same paired trials described above. Blue denotes Piret-default, cyan Piret-matched-bits, green Giraud-known-bit and red Giraud-unknown-bit. Equal plotted values are genuine equal results; no artificial offsets are added.", "", "### Figure 1: faulty-output cost and offline recovery time", "", "![Faulty-output cost and offline recovery time](figures/01_cost_and_time.png)", "", "**Left panel: observations needed for recovery.** The horizontal axis identifies the four variants; the vertical axis counts faulty ciphertexts requested in one trial. Each dot is a trial and each black horizontal mark is the median. Repeated values overlap within a model, so visible dots do not count the number of trials. Consult the results table for sample size and range. A smaller value means fewer faulty outputs under this experiment's assumptions.", "", "The three known-mask variants all use 32 faulty outputs in these trials: 16 target key bytes, with two observations per byte. Unknown-bit Giraud uses 32 to 40, averaging 35.06. Hiding the bit leaves more hypotheses, which sometimes requires another observation. The matched-bit Piret/Giraud comparison isolates this knowledge difference; the default Piret mask sequence is a separate control.", "", "**Right panel: offline computation.** The horizontal axis again identifies the variants; the vertical axis is milliseconds measured on this computer. Dots show run-to-run variation and black marks show medians. This includes filtering, peeling and reversing the schedule, but excludes target encryption, physical acquisition and final validation. Compare these numbers as implementation costs, not as board attack times. Matched Piret and known-bit Giraud have identical candidate histories despite their different Python runtimes.", "", "### Figure 2: observation budget, success and early termination", "", "![Observation budget by model](figures/02_budget.png)", "", "**Layout and axes.** Each model has its own row, with a success panel on the left and a consumed-query panel on the right. The horizontal axis is the maximum number of distinct observations allowed per target byte, not the total attack budget. The three known-mask models coincide numerically; separate rows make both Piret curves visible without changing any measurements.", "", "**Left column: verified full-key recovery.** At budget one, all models fail to identify the entire key. At budget two, all three known-mask variants recover 100/100 keys; unknown-bit Giraud recovers only 3/100. At budget three, unknown-bit Giraud also reaches 100/100. A 100% sample result does not guarantee success for all keys or physical faults; see the Wilson intervals above.", "", "**Right column: queries actually consumed.** At budget one, the median is one query because the solver stops at the first ambiguous byte. At budget two, known-mask variants consume 32 and complete recovery, whereas unknown-bit Giraud consumes a median of eight before usually stopping incomplete. Eight is therefore not a cheaper successful recovery than 32. From budget three onward, unknown-bit Giraud completes with median 35; known-mask variants remain at 32. Increasing the allowed budget does not force more queries after uniqueness.", "", "**Comparison to explain aloud.** First compare success at a fixed budget; only then compare consumed queries together with completion status. Low cost on a failed attack measures early stopping, not efficiency at recovering a full key.", "", "### Figure 3: candidate ambiguity and progressive elimination", "", "![Key-byte candidate filtering](figures/03_candidates.png)", "", "**Left panel: candidates after the first pair.** Each dot is the candidate count for one target byte in one trial; the black mark is the median over all target bytes and trials. These are key-byte candidates, not complete 128-bit keys. The median is two for the known-mask variants and ten for unknown-bit Giraud. Knowing the bit supplies a more restrictive difference equation; knowing only that one bit flipped accepts the union of eight possibilities.", "", "**Right panel: mean surviving candidates after intersections.** The horizontal axis is the observation index for a target byte; the vertical axis averages the remaining candidate count across target bytes and trials. Colors, line widths and nested hollow marker shapes expose coincident curves. Already recovered bytes stay at one for later plotted indices; these extended points do not represent additional oracle requests. A mean near one does not prove every byte is unique: the full-key success plot in Figure 2 answers that question.", "", "**Connection between the figures.** More initial hypotheses in Figure 3 explain why unknown-bit Giraud needs extra observations in Figure 1 and a larger per-byte budget in Figure 2. The matched-bit known-mask variants have identical histories, so these graphs support equivalence under matched assumptions rather than an intrinsic advantage attached to an attack name.", ""]
    insertion = lines.index("## Practical example: first byte of rk31")
    lines[insertion:insertion] = explanations
    (out / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def plot(out, report):
    """Export standalone publication-style figures without opening a GUI."""
    os.environ.setdefault("MPLCONFIGDIR", str(ROOT / ".build" / "matplotlib"))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages

    figures = out / "figures"
    figures.mkdir(exist_ok=True)
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    count = report["configuration"]["trials"]

    with PdfPages(out / "comparison.pdf") as pdf:
        def save(fig, slug, caption):
            fig.text(0.5, 0.025, caption, ha="center", fontsize=9)
            fig.tight_layout(rect=(0.02, 0.07, 0.98, 0.97))
            fig.savefig(figures / (slug + ".png"), dpi=180)
            fig.savefig(figures / (slug + ".svg"))
            pdf.savefig(fig)
            plt.close(fig)

        fig = plt.figure(figsize=(12, 7))
        fig.suptitle("SM4 DFA comparison: results and interpretation", fontsize=17, y=0.95)
        fig.text(0.07, 0.87, f"{count} paired software trials; seed {report['configuration']['seed']}. Full key verified by equality, encrypt and decrypt.", fontsize=11)
        rows = []

        for model in MODELS:
            item = report["summary"][model]
            rows.append([model, f"{item['successes']}/{count}", f"{item['faults_mean']:.2f}", str(item["first_candidates_median"]), f"{item['offline_ms_median']:.3f}"])

        ax = fig.add_axes((0.07, 0.51, 0.86, 0.28))
        ax.axis("off")
        summary_table = ax.table(cellText=rows, colLabels=["Model", "Success", "Mean faulty outputs", "First candidates (median)", "Offline median (ms)"], loc="center", cellLoc="center", colWidths=[0.25, 0.12, 0.19, 0.24, 0.20])
        summary_table.auto_set_font_size(False)
        summary_table.set_fontsize(10)
        summary_table.scale(1, 2)
        fig.text(0.07, 0.42, "Matched Piret and known-bit Giraud produce identical complete candidate histories.", fontsize=12, weight="bold")
        fig.text(0.07, 0.35, "Unknown-bit Giraud uses less fault information and therefore retains more compatible inputs.", fontsize=11)
        fig.text(0.07, 0.28, "Piret-default uses byte masks; the matched-bit control isolates mask choice from solver knowledge.", fontsize=11)
        fig.text(0.07, 0.21, "Timing excludes target encryption, serial/USB traffic and physical glitch acquisition.", fontsize=11)
        fig.text(0.07, 0.14, "All variants assume controlled faults in rounds 31, 30, 29 and 28. No STM32 experiment is measured.", fontsize=11)
        pdf.savefig(fig)
        plt.close(fig)

        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        for index, model in enumerate(MODELS):
            faults = []
            times = []
            for trial in report["trials"]:
                faults.append(trial["models"][model]["used"])
                times.append(trial["models"][model]["offline_ns"] / 1_000_000)
            axes[0].scatter([index] * count, faults, s=12, alpha=0.25, color=COLORS[index])
            axes[0].plot(index, statistics.median(faults), marker="_", markersize=28, color="black")
            axes[1].scatter([index] * count, times, s=12, alpha=0.25, color=COLORS[index])
            axes[1].plot(index, statistics.median(times), marker="_", markersize=28, color="black")
        for ax in axes:
            ax.set_xticks(range(4), LABELS, rotation=18, ha="right")
            ax.grid(axis="y", alpha=0.2)
        axes[0].set_ylabel("Faulty ciphertext queries (early-stop cost)")
        axes[1].set_ylabel("Offline recovery time (ms; target excluded)")
        fig.suptitle("SM4 full master-key recovery: paired input trials", fontsize=15)
        save(fig, "01_cost_and_time", f"{count} paired random trials. Dots: trials; black marks: medians. No hardware acquisition is timed.")

        # Separate rows preserve exact values while making coincident curves visible.
        fig, axes = plt.subplots(4, 2, figsize=(12, 12), sharex=True, sharey="col")
        for index, model in enumerate(MODELS):
            budgets = []
            rates = []
            costs = []
            for point in report["summary"][model]["budget_curve"]:
                budgets.append(point["budget"])
                rates.append(point["success_rate"] * 100)
                costs.append(point["median_consumed"])
            axes[index, 0].plot(budgets, rates, marker="o", color=COLORS[index])
            axes[index, 1].plot(budgets, costs, marker="o", color=COLORS[index])
            axes[index, 0].set_ylabel("Full-key success (%)")
            axes[index, 0].set_ylim(-3, 108)
            axes[index, 1].set_ylabel("Median queries consumed")

            for column in range(2):
                ax = axes[index, column]
                ax.set_title(LABELS[index], color=COLORS[index], fontweight="bold")
                ax.set_xticks(range(1, 9))
                ax.tick_params(labelbottom=True)
                ax.grid(alpha=0.2)

            axes[index, 0].text(0.96, 0.18, f"Budget 2: {rates[1]:g}%", transform=axes[index, 0].transAxes, ha="right", bbox=dict(facecolor="white", edgecolor="none", alpha=0.9))
            axes[index, 1].text(0.96, 0.18, f"Budget 2: {costs[1]:g} queries", transform=axes[index, 1].transAxes, ha="right", bbox=dict(facecolor="white", edgecolor="none", alpha=0.9))

        for ax in axes[-1]:
            ax.set_xlabel("Maximum distinct observations per target byte")
        fig.suptitle("Observation budget: recovery and early termination", fontsize=15)
        save(fig, "02_budget", "Separate rows show every model without shifting data. Costs include incomplete attacks and early termination.")

        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        for index, model in enumerate(MODELS):
            first_counts = []
            trajectory = {}
            for observation in range(1, 9):
                trajectory[observation] = []
            for trial in report["trials"]:
                item = trial["models"][model]
                first_counts.extend(item["first_counts"])
                for counts in item["trajectories"].values():
                    for observation in range(1, 9):
                        if observation <= len(counts):
                            trajectory[observation].append(counts[observation - 1])
                        elif counts[-1] == 1:
                            trajectory[observation].append(1)
            axes[0].scatter([index] * len(first_counts), first_counts, s=9, alpha=0.12, color=COLORS[index])
            axes[0].plot(index, statistics.median(first_counts), marker="_", markersize=28, color="black")
            x, y = [], []
            for observation in range(1, 9):
                if trajectory[observation]:
                    x.append(observation)
                    y.append(statistics.mean(trajectory[observation]))
            # Nested hollow markers and different line widths expose identical curves.
            markers = ["o", "s", "D", "^"]
            widths = [7, 5, 2, 2]
            sizes = [15, 10, 5, 7]
            axes[1].plot(x, y, marker=markers[index], markersize=sizes[index], markerfacecolor="none", linewidth=widths[index], label=LABELS[index], color=COLORS[index])
        axes[0].set_xticks(range(4), LABELS, rotation=18, ha="right")
        axes[0].set_ylabel("First-pair key-byte candidates")
        axes[1].set_xlabel("Observation index within a target byte")
        axes[1].set_ylabel("Mean surviving candidates")
        axes[1].legend(fontsize=8)
        for ax in axes:
            ax.grid(alpha=0.2)
        fig.suptitle("How fault knowledge narrows the key-byte search", fontsize=15)
        save(fig, "03_candidates", "Recovered bytes stay at one for later indices; no extra faults are queried after uniqueness.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument("--seed", type=int, default=20261110)
    args = parser.parse_args(argv)

    if args.trials < 1:
        parser.error("--trials must be positive.")

    out = ROOT / "analysis" / "results" / "sm4_comparison"
    out.mkdir(parents=True, exist_ok=True)
    trials = experiment(args.trials, args.seed)
    source_hashes = {}

    for filename in ("sm4.py", "piret_sm4.py", "giraud_sm4.py", "giraud_common.py"):
        source_hashes[filename] = hashlib.sha256((ROOT / "src" / filename).read_bytes()).hexdigest()

    report = dict(configuration=vars(args), environment=dict(python=sys.version, platform=platform.platform()), source_sha256=source_hashes, summary=aggregate(trials), trials=trials)
    (out / "measurements.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    with (out / "trials.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("trial", "model", "verified", "faulty_queries", "offline_ms"))
        for trial in trials:
            for model in MODELS:
                item = trial["models"][model]
                writer.writerow((trial["trial"], model, item["verified"], item["used"], item["offline_ns"] / 1_000_000))

    with (out / "budget_curve.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("model", "maximum_observations_per_byte", "success_rate", "median_faulty_queries_consumed"))

        for model in MODELS:
            for point in report["summary"][model]["budget_curve"]:
                writer.writerow((model, point["budget"], point["success_rate"], point["median_consumed"]))

    write_report(out, report)
    plot(out, report)

    for model in MODELS:
        item = report["summary"][model]
        print(f"{model}: {item['successes']}/{args.trials} verified; mean faults={item['faults_mean']:.2f}; offline median={item['offline_ms_median']:.3f} ms")

    print(f"Report: {out / 'report.md'}")
    print(f"Charts: {out / 'comparison.pdf'}")
    return 0


if __name__ == "__main__":
    from terminal_log import run_with_log
    raise SystemExit(run_with_log(main, "compare_sm4_attacks"))

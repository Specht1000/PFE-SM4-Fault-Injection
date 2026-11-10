"""Render saved measurements as PNG, SVG, a PDF and a standalone HTML gallery."""
import csv
from html import escape
import json
import os
from pathlib import Path
import statistics

HERE = Path(__file__).resolve().parent
os.environ.setdefault('MPLCONFIGDIR', str(HERE / '.mplconfig'))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np

COLORS = ['#2563eb', '#e87924']


def generate_plots(out=HERE / 'results'):
    report = json.loads((out / 'measurements.json').read_text(encoding='utf-8'))

    with (out / 'avalanche.csv').open(encoding='utf-8', newline='') as stream:
        rows = list(csv.DictReader(stream))

    figures = out / 'figures'

    figures.mkdir(exist_ok=True)

    plt.rcParams.update({'font.size': 10, 'axes.spines.top': False,
                         'axes.spines.right': False, 'figure.facecolor': 'white',
                         'axes.titleweight': 'bold', 'savefig.facecolor': 'white'})

    names = list(report['ciphers'])

    gallery = []

    with PdfPages(out / 'analysis_charts.pdf') as pdf:
        def save(fig, slug, title, caption):
            fig.suptitle(title, fontsize=16, fontweight='bold')
            fig.text(.5, .015, caption, ha='center', fontsize=9, color='#475569', wrap=True)
            fig.tight_layout(rect=(0, .07, 1, .94))
            fig.savefig(figures / (slug + '.png'), dpi=180)
            fig.savefig(figures / (slug + '.svg'))
            pdf.savefig(fig)
            plt.close(fig)
            gallery.append((slug, title, caption))

        fig, axes = plt.subplots(1, 2, figsize=(12, 5))

        for ax, mode, title in zip(axes, ['plaintext', 'key'], ['Plaintext bit flip', 'Key bit flip']):
            observed = []

            for row_2 in rows:
                if row_2['mode'] == mode:
                    observed.append(int(row_2['changed_bits']))

            bins = np.arange(2*(min(observed)//2), 2*(max(observed)//2)+4, 2)

            for name, color in zip(names, COLORS):
                values = []

                for row in rows:
                    if row['cipher'] == name and row['mode'] == mode:
                        values.append(int(row['changed_bits']))

                ax.hist(values, bins=bins, alpha=.52, color=color,
                        label=f'{name}: mean {statistics.mean(values):.2f}', density=True)

            ax.axvline(64, color='#334155', linestyle='--', label='Reference: 64 bits')
            ax.set(title=title, xlabel='Changed output bits (out of 128)', ylabel='Density')
            ax.legend(fontsize=8)

        save(fig, '01_avalanche', 'Avalanche effect: Hamming distance distributions',
             'One bit flipped at a time; 50% reference. Finite sample, not a security certification.')

        fig, axes = plt.subplots(2, 2, figsize=(12, 7))

        for i, name in enumerate(names):
            for j, mode in enumerate(['plaintext', 'key']):
                probabilities = report['ciphers'][name]['avalanche'][mode]['output_flip_probability']
                ax = axes[i, j]
                image = ax.imshow(np.array(probabilities).reshape(16, 8), vmin=.35, vmax=.65,
                                  cmap='RdBu_r', aspect='auto')

                if mode == 'plaintext':
                    computed_value = 'plaintext'
                else:
                    computed_value = 'key'

                ax.set(title=f'{name} — {computed_value}', xlabel='Bit within byte (LSB = 0)', ylabel='Output byte')
                ax.set_xticks(range(8))
                ax.set_yticks([0, 4, 8, 12, 15])
                fig.colorbar(image, ax=ax, label='Bit-flip probability')

        save(fig, '02_output_bits', 'Diffusion by output bit',
             'Probabilities pooled across input bits and trials; not a full SAC matrix.')

        fig, axes = plt.subplots(1, 3, figsize=(13, 5))

        for ax, metric, title, unit in [
            (axes[0], 'ns_per_block_median', 'Time per block', 'µs / block'),
            (axes[1], 'bytes_per_second', 'Throughput', 'KiB / s'),
            (axes[2], 'python_peak_bytes_one_call', 'Peak Python allocations', 'bytes')]:
            x = np.arange(len(names))

            for offset, operation, color in [(-.18, 'encrypt', COLORS[0]), (.18, 'decrypt', COLORS[1])]:
                values = []

                for candidate_name in names:
                    values.append(report['ciphers'][candidate_name]['benchmark'][operation][metric])

                if metric == 'ns_per_block_median':
                    values_values_2 = []

                    for value_6 in values:
                        values_values_2.append(value_6 / 1000)

                    values = values_values_2
                elif metric == 'bytes_per_second':
                    values_values = []

                    for value_5 in values:
                        values_values.append(value_5 / 1024)

                    values = values_values

                if operation == 'encrypt':
                    bars_2 = 'Encrypt'
                else:
                    bars_2 = 'Decrypt'

                bars = ax.bar(x + offset, values, 0.35, color=color, label=bars_2)
                ax.bar_label(bars, fmt='%.1f', fontsize=8, padding=3)

            ax.set(title=title, ylabel=unit, xticks=x, xticklabels=names)
            ax.margins(y=.2)
            ax.legend(fontsize=8)

        save(fig, '03_performance', 'Python implementation performance',
             'Key expansion included. Time: median of 5 batches. Memory measured separately; not process RSS.')

        models = ['Piret', 'Giraud-known', 'Giraud-unknown']

        labels = ['Piret', 'Giraud\nknown bit', 'Giraud\nunknown bit']

        fig, axes = plt.subplots(1, 2, figsize=(12, 5))

        for ax, name, color in zip(axes, names, COLORS):
            groups = []

            for candidate_model_3 in models:
                element_value_values_5 = []

                for t_9 in report['attacks']:
                    if t_9['cipher'] == name and t_9['model'] == candidate_model_3:
                        element_value_values_5.append(t_9)

                groups.append(element_value_values_5)

            values = []

            for candidate_group_4 in groups:
                element_value_values_4 = []

                for t_8 in candidate_group_4:
                    element_value_values_4.append(t_8['faults'])

                values.append(element_value_values_4)

            means = []

            for value_4 in values:
                means.append(statistics.mean(value_4))

            errors_values = []

            for m, value_2 in zip(means, values):
                errors_values.append(m - min(value_2))

            errors_values_2 = []

            for m_2, value_3 in zip(means, values):
                errors_values_2.append(max(value_3) - m_2)

            errors = [errors_values, errors_values_2]
            bars = ax.bar(range(3), means, color=color, alpha=.8, yerr=errors, capsize=5)

            for i, group in enumerate(groups):
                element_values_7 = []

                for index in range(len(group)):
                    element_values_7.append(i + (index - (len(group) - 1) / 2) * 0.018)

                ax.scatter(element_values_7, values[i], color='#0f172a', s=13, zorder=3)
                element_values_6 = []

                for t_7 in group:
                    element_values_6.append(t_7['verified'])

                ax.text(i, max(values[i]) + 1.5, f'{sum(element_values_6)}/{len(group)} verified', ha='center', fontsize=8)

            ax.set(title=name, xticks=range(3), xticklabels=labels, ylabel='Faulty ciphertext queries')
            element_values_5 = []

            for value in values:
                element_values_5.append(max(value))

            ax.set_ylim(0, max(element_values_5) * 1.23)

        save(fig, '04_fault_counts', 'Observations required for key recovery',
             'Bars: mean; whiskers: min–max; dots: trials. One additional correct ciphertext per trial.')

        fig, axes = plt.subplots(1, 2, figsize=(12, 5))

        for ax, name in zip(axes, names):
            groups = []

            for candidate_model_2 in models:
                element_value_values_3 = []

                for t_6 in report['attacks']:
                    if t_6['cipher'] == name and t_6['model'] == candidate_model_2:
                        element_value_values_3.append(t_6)

                groups.append(element_value_values_3)

            oracle = []

            for candidate_group_3 in groups:
                element_values_4 = []

                for t_5 in candidate_group_3:
                    element_values_4.append(t_5['oracle_ns'])

                oracle.append(statistics.mean(element_values_4) / 1000000.0)

            solver = []

            for candidate_group_2 in groups:
                element_values_3 = []

                for t_4 in candidate_group_2:
                    element_values_3.append(t_4['solver_excluding_oracle_ns'])

                solver.append(statistics.mean(element_values_3) / 1000000.0)

            ax.bar(range(3), oracle, label='Simulated oracle and traces', color='#94a3b8')
            ax.bar(range(3), solver, bottom=oracle, label='Solver', color='#2563eb')
            ax.set(title=name, ylabel='Mean time (ms)', xticks=range(3), xticklabels=labels)
            ax.legend(fontsize=8)

        save(fig, '05_attack_time', 'Attack time: simulation and solving',
             'Software timings do not estimate the duration of a physical fault-injection campaign.')

        fig, axes = plt.subplots(2, 3, figsize=(13, 7))

        for i, name in enumerate(names):
            for j, model in enumerate(models):
                ax = axes[i, j]
                matching_item = None

                matching_item_found = False

                for t_3 in report['attacks']:
                    if t_3['cipher'] == name and t_3['model'] == model:
                        matching_item = t_3
                        matching_item_found = True
                        break

                if not matching_item_found:
                    raise StopIteration()

                trial = matching_item
                groups = {}

                for event in trial['candidate_history']:
                    group = (event.get('round'), event.get('byte'), event.get('column'))
                    groups.setdefault(group, []).append(event)

                for events in groups.values():
                    first = events[0]
                    # Piret AES jointly filters 4 bytes: 2^32 initial tuples, not 256 bytes.
                    initial = first.get('before') or 2**32
                    element_values = []

                    for e in events:
                        element_values.append(e['observation'])

                    element_values_2 = []

                    for e_2 in events:
                        element_values_2.append(e_2['remaining'])

                    ax.plot([0] + element_values, [initial] + element_values_2, marker='o', markersize=3, alpha=0.55)

                ax.axhline(1, color='#334155', linestyle='--', linewidth=1)
                ax.set_yscale('log', base=2)
                ax.set(title=f'{name} / {model}', xlabel='Observations per group', ylabel='Remaining candidates')
                ax.grid(alpha=.15)

        save(fig, '06_candidates', 'Candidate reduction during the attack',
             'First trial of each model. Each curve tracks one key byte; AES Piret tracks a four-byte group.')

        fig, axes = plt.subplots(1, 2, figsize=(12, 5))

        for ax, name in zip(axes, names):
            groups = []

            for candidate_model in models:
                element_value_values_2 = []

                for t_2 in report['attacks']:
                    if t_2['cipher'] == name and t_2['model'] == candidate_model:
                        element_value_values_2.append(t_2)

                groups.append(element_value_values_2)

            values = []

            for candidate_group in groups:
                element_value_values = []

                for t in candidate_group:
                    for o in t['observations']:
                        element_value_values.append(o['changed_bits'])

                values.append(element_value_values)

            ax.boxplot(values, tick_labels=labels, showmeans=True)
            ax.set(title=name, ylabel='Different output bits (out of 128)')
            ax.grid(axis='y', alpha=.15)

        save(fig, '07_fault_propagation', 'Fault propagation to the ciphertext',
             'Distribution across observations; propagation depends on the round and injection point of each model.')

    formatted_values = []

    for candidate_slug, candidate_title, candidate_caption in gallery:
        formatted_values.append(f'<section><h2>{escape(candidate_title)}</h2><p>{escape(candidate_caption)}</p><a href="figures/{candidate_slug}.svg"><img src="figures/{candidate_slug}.png" alt="{escape(candidate_title)}"></a><p><a href="figures/{candidate_slug}.png">PNG</a> · <a href="figures/{candidate_slug}.svg">Vector SVG</a></p></section>')

    cards = ''.join(formatted_values)

    (out/'index.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1"><title>AES and SM4 analysis</title>'
        '<style>body{font:16px system-ui;background:#eef2f7;color:#172033;max-width:1200px;margin:auto;padding:32px}'
        'section{background:white;border-radius:16px;padding:24px;margin:24px 0}img{width:100%;height:auto}'
        'a{color:#2563eb}p{line-height:1.6}h1{font-size:32px}</style><h1>AES-128, SM4 and DFA attack analysis</h1>'
        '<p>Plots of measured results. <a href="analysis_charts.pdf">Download complete PDF</a> · '
        '<a href="report.md">Report</a> · <a href="measurements.json">Raw data</a></p>'
        f'<p>Seed: {report["configuration"]["seed"]}; {report["configuration"]["attack_trials"]} trials per attack. '
        'Measurements describe Python simulations and do not establish security or physical feasibility.</p>'+cards+'</html>', encoding='utf-8')

    path = out/'report.md'

    content = path.read_text(encoding='utf-8').split('\n<!-- generated-plots -->')[0]

    content += '\n<!-- generated-plots -->\n\n## Plots\n\n[Visual gallery](index.html) · [Complete PDF](analysis_charts.pdf)\n\n'

    for slug,title,caption in gallery:
        content += f'### {title}\n\n{caption}\n\n![{title}](figures/{slug}.png)\n\n'

    path.write_text(content, encoding='utf-8')

    print(f'Generated {len(gallery)} figures (PNG/SVG), PDF and gallery in {out}')


if __name__ == '__main__':
    generate_plots()

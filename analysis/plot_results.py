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
            observed = [int(row['changed_bits']) for row in rows if row['mode'] == mode]
            bins = np.arange(2*(min(observed)//2), 2*(max(observed)//2)+4, 2)
            for name, color in zip(names, COLORS):
                values = [int(row['changed_bits']) for row in rows if row['cipher'] == name and row['mode'] == mode]
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
                ax.set(title=f'{name} — {"plaintext" if mode == "plaintext" else "key"}',
                       xlabel='Bit within byte (LSB = 0)', ylabel='Output byte')
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
                values = [report['ciphers'][name]['benchmark'][operation][metric] for name in names]
                if metric == 'ns_per_block_median':
                    values = [v/1000 for v in values]
                elif metric == 'bytes_per_second':
                    values = [v/1024 for v in values]
                bars = ax.bar(x+offset, values, .35, color=color, label='Encrypt' if operation == 'encrypt' else 'Decrypt')
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
            groups = [[t for t in report['attacks'] if t['cipher']==name and t['model']==model] for model in models]
            values = [[t['faults'] for t in group] for group in groups]
            means = [statistics.mean(v) for v in values]
            errors = [[m-min(v) for m,v in zip(means, values)], [max(v)-m for m,v in zip(means, values)]]
            bars = ax.bar(range(3), means, color=color, alpha=.8, yerr=errors, capsize=5)
            for i, group in enumerate(groups):
                ax.scatter([i + (j-(len(group)-1)/2)*.018 for j in range(len(group))], values[i],
                           color='#0f172a', s=13, zorder=3)
                ax.text(i, max(values[i])+1.5, f"{sum(t['verified'] for t in group)}/{len(group)} verified", ha='center', fontsize=8)
            ax.set(title=name, xticks=range(3), xticklabels=labels, ylabel='Faulty ciphertext queries')
            ax.set_ylim(0, max(max(v) for v in values)*1.23)
        save(fig, '04_fault_counts', 'Observations required for key recovery',
             'Bars: mean; whiskers: min–max; dots: trials. One additional correct ciphertext per trial.')

        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        for ax, name in zip(axes, names):
            groups = [[t for t in report['attacks'] if t['cipher']==name and t['model']==model] for model in models]
            oracle = [statistics.mean(t['oracle_ns'] for t in group)/1e6 for group in groups]
            solver = [statistics.mean(t['solver_excluding_oracle_ns'] for t in group)/1e6 for group in groups]
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
                trial = next(t for t in report['attacks'] if t['cipher']==name and t['model']==model)
                groups = {}
                for event in trial['candidate_history']:
                    group = (event.get('round'), event.get('byte'), event.get('column'))
                    groups.setdefault(group, []).append(event)
                for events in groups.values():
                    first = events[0]
                    # Piret AES jointly filters 4 bytes: 2^32 initial tuples, not 256 bytes.
                    initial = first.get('before') or 2**32
                    ax.plot([0]+[e['observation'] for e in events],
                            [initial]+[e['remaining'] for e in events], marker='o', markersize=3, alpha=.55)
                ax.axhline(1, color='#334155', linestyle='--', linewidth=1)
                ax.set_yscale('log', base=2)
                ax.set(title=f'{name} / {model}', xlabel='Observations per group', ylabel='Remaining candidates')
                ax.grid(alpha=.15)
        save(fig, '06_candidates', 'Candidate reduction during the attack',
             'First trial of each model. Each curve tracks one key byte; AES Piret tracks a four-byte group.')

        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        for ax, name in zip(axes, names):
            groups = [[t for t in report['attacks'] if t['cipher']==name and t['model']==model] for model in models]
            values = [[o['changed_bits'] for t in group for o in t['observations']] for group in groups]
            ax.boxplot(values, tick_labels=labels, showmeans=True)
            ax.set(title=name, ylabel='Different output bits (out of 128)')
            ax.grid(axis='y', alpha=.15)
        save(fig, '07_fault_propagation', 'Fault propagation to the ciphertext',
             'Distribution across observations; propagation depends on the round and injection point of each model.')

    cards = ''.join(f'<section><h2>{escape(title)}</h2><p>{escape(caption)}</p>'
                    f'<a href="figures/{slug}.svg"><img src="figures/{slug}.png" alt="{escape(title)}"></a>'
                    f'<p><a href="figures/{slug}.png">PNG</a> · <a href="figures/{slug}.svg">Vector SVG</a></p></section>'
                    for slug,title,caption in gallery)
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

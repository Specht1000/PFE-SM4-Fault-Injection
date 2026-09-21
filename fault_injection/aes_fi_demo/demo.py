"""AES-128 with transient fault injection and an educational visualization.

Python 3.9+, standard library only. Internal state: state[column][row].
"""
import argparse
from dataclasses import dataclass
import html
import json
from pathlib import Path

import aes_reference as aes

KEY = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
PLAINTEXT = bytes.fromhex('00112233445566778899aabbccddeeff')
EXPECTED = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
STAGES = ('SubBytes', 'ShiftRows', 'MixColumns', 'AddRoundKey')


@dataclass(frozen=True)
class Fault:
    round: int = 9
    stage: str = 'MixColumns'
    row: int = 0
    column: int = 0
    mask: int = 1

    def __post_init__(self):
        if not 1 <= self.round <= 10:
            raise ValueError('Round must be between 1 and 10.')
        if self.stage not in STAGES:
            raise ValueError('Invalid operation.')
        if self.round == 10 and self.stage == 'MixColumns':
            raise ValueError('Round 10 has no MixColumns operation.')
        if not (0 <= self.row < 4 and 0 <= self.column < 4):
            raise ValueError('Row and column must be between 0 and 3.')
        if not 1 <= self.mask <= 255:
            raise ValueError('The XOR mask must be between 1 and 255.')


def encrypt_trace(key, plaintext, fault=None):
    """Inject once, BEFORE the selected operation; record state snapshots."""
    if len(key) != 16 or len(plaintext) != 16:
        raise ValueError('This demo requires a key and block of exactly 16 bytes each.')
    cipher = aes.AES(key)
    state = aes.bytes2matrix(plaintext)
    trace = []

    def record(label):
        trace.append({'label': label, 'state': list(aes.matrix2bytes(state))})

    record('Input')
    aes.add_round_key(state, cipher._key_matrices[0])
    record('R00 after AddRoundKey')
    for rnd in range(1, 11):
        for stage in STAGES:
            if rnd == 10 and stage == 'MixColumns':
                continue
            if fault and (rnd, stage) == (fault.round, fault.stage):
                # Perturb the data without modifying the key or instructions.
                state[fault.column][fault.row] ^= fault.mask
            record(f'R{rnd:02d} before {stage}')
            if stage == 'AddRoundKey':
                aes.add_round_key(state, cipher._key_matrices[rnd])
            else:
                {'SubBytes': aes.sub_bytes, 'ShiftRows': aes.shift_rows,
                 'MixColumns': aes.mix_columns}[stage](state)
            record(f'R{rnd:02d} after {stage}')
    return aes.matrix2bytes(state), trace


def compare(clean_trace, faulty_trace):
    result = []
    for a, b in zip(clean_trace, faulty_trace):
        delta = [x ^ y for x, y in zip(a['state'], b['state'])]
        result.append(dict(label=a['label'], clean=a['state'], faulty=b['state'],
                           delta=delta, bytes_changed=sum(x != 0 for x in delta),
                           bits_changed=sum(bin(x).count('1') for x in delta)))
    return result


def write_html(path, steps, fault, clean, faulty):
    title = (f'Round {fault.round}, before {fault.stage}, '
             f'row {fault.row}, column {fault.column}, XOR 0x{fault.mask:02x}')
    page = '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AES — fault injection lab</title>
<style>
body{font:18px system-ui;background:#101827;color:#eef2ff;max-width:1100px;margin:auto;padding:28px}
h1{font-size:32px}p{line-height:1.6}button,select{font:inherit;padding:10px;margin:4px}
input{width:100%}.boards{display:flex;flex-wrap:wrap;gap:28px}table{border-spacing:5px}
td{font:22px monospace;background:#24324b;padding:16px;border-radius:6px;text-align:center}
.hit{background:#a33b18;color:white;outline:2px solid #ffb890}code{overflow-wrap:anywhere}
.note{color:#bbc9df}h2{font-size:23px}button{cursor:pointer}
</style><h1>AES-128: tracing a fault</h1>
<p>__TITLE__</p><p class="note">Software simulation of a transient fault.
Both executions use the same input and key. Row and column indices: 0–3.</p>
<button id="prev">← Previous</button><button id="next">Next →</button>
<button id="jump">Jump to injection</button><select id="select" aria-label="Step"></select>
<input id="slider" type="range" min="0" aria-label="Navigate execution">
<h2 id="label"></h2><p id="counts"></p><div class="boards">
<section><h2>Correct execution</h2><table id="clean"></table></section>
<section><h2>Faulty execution</h2><table id="faulty"></table></section>
<section><h2>XOR difference</h2><table id="delta"></table></section></div>
<p id="explanation"></p><p class="note">Orange = differing position. Matrices display
the AES state by rows; byte index j corresponds to row j % 4 and column j // 4.</p>
<p>Correct C: <code>__CLEAN__</code><br>Faulty C: <code>__FAULTY__</code></p>
<p>FI introduces the perturbation. DFA exploits relationships between correct and faulty
outputs to narrow down key candidates. This demo illustrates FI and propagation;
it does not perform key recovery.</p>
<script>
const steps=__DATA__;
const first=steps.findIndex(s=>s.bytes_changed>0);
const slider=document.getElementById('slider'), select=document.getElementById('select');
slider.max=steps.length-1;
steps.forEach((s,i)=>{let o=document.createElement('option');o.value=i;o.textContent=s.label;select.append(o)});
function show(i){i=Math.max(0,Math.min(steps.length-1,Number(i)));slider.value=i;select.value=i;
const s=steps[i];document.getElementById('label').textContent=s.label;
document.getElementById('counts').textContent=`${s.bytes_changed}/16 differing bytes · ${s.bits_changed}/128 differing bits`;
for(const kind of ['clean','faulty','delta']){let out='';for(let r=0;r<4;r++){out+='<tr>';
for(let c=0;c<4;c++){const j=4*c+r;out+=`<td class="${s.delta[j]?'hit':''}">${s[kind][j].toString(16).padStart(2,'0')}</td>`}out+='</tr>'}
document.getElementById(kind).innerHTML=out}
document.getElementById('explanation').textContent=i<first?'Both executions are still identical.':i===first?
'Injection: one state byte was XORed with the selected mask.':
'MixColumns spreads differences within a column; ShiftRows changes their positions; SubBytes transforms their values. AddRoundKey preserves the XOR difference when both executions use the same round key.';
}
slider.oninput=()=>show(slider.value);select.onchange=()=>show(select.value);
document.getElementById('prev').onclick=()=>show(Number(slider.value)-1);
document.getElementById('next').onclick=()=>show(Number(slider.value)+1);
document.getElementById('jump').onclick=()=>show(first);
show(first);
</script></html>'''
    for token, value in {'__TITLE__': html.escape(title), '__CLEAN__': clean.hex(),
                         '__FAULTY__': faulty.hex(), '__DATA__': json.dumps(steps)}.items():
        page = page.replace(token, value)
    path.write_text(page, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--round', type=int, default=9, help='Round 1–10 (default: 9)')
    parser.add_argument('--stage', choices=STAGES, default='MixColumns', help='Inject BEFORE this operation')
    parser.add_argument('--row', type=int, default=0)
    parser.add_argument('--column', type=int, default=0)
    parser.add_argument('--mask', type=lambda s: int(s, 0), default=1, help='XOR mask, e.g. 0x01 or 0x55')
    parser.add_argument('--output', type=Path, default=Path(__file__).parent / 'output')
    args = parser.parse_args()
    try:
        fault = Fault(args.round, args.stage, args.row, args.column, args.mask)
    except ValueError as exc:
        parser.error(str(exc))
    clean, a = encrypt_trace(KEY, PLAINTEXT)
    if clean != EXPECTED:
        raise RuntimeError('AES validation failed against the FIPS 197 known-answer vector.')
    faulty, b = encrypt_trace(KEY, PLAINTEXT, fault)
    steps = compare(a, b)
    print('AES-128 | Transient XOR fault injection | Software simulation')
    print('FIPS 197 known-answer vector: OK')
    print(f'Public demonstration key: {KEY.hex()}')
    print(f'Input:                    {PLAINTEXT.hex()}')
    print(f'Fault: {fault}')
    print(f'Correct C:   {clean.hex()}\nFaulty C:    {faulty.hex()}')
    print(f'Delta XOR:   {bytes(steps[-1]["delta"]).hex()}')
    print('\nStep                               Differing bytes / Differing bits')
    first = next(i for i, s in enumerate(steps) if s['bytes_changed'])
    for s in steps[max(0, first - 1):]:
        print(f'{s["label"]:34} {s["bytes_changed"]:2}/16             {s["bits_changed"]:3}/128')
    args.output.mkdir(parents=True, exist_ok=True)
    write_html(args.output / 'demo.html', steps, fault, clean, faulty)
    report = dict(model=fault.__dict__, key=KEY.hex(), plaintext=PLAINTEXT.hex(),
                  ciphertext=clean.hex(), faulty_ciphertext=faulty.hex(), steps=steps)
    (args.output / 'trace.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f'\nVisualization: {(args.output / "demo.html").resolve()}')
    print('FI and propagation demonstrated; key recovery is not implemented.')


if __name__ == '__main__':
    main()

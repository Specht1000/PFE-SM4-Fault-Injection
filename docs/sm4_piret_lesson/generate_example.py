"""Generate reproducible SM4 lesson tables and source excerpts from the real code."""
import ast
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sm4
import piret_sm4
from line_notes import generate_line_guide

FOLDER = Path(__file__).resolve().parent / "generated"


def table(filename, columns, heading, rows):
    """Write a multipage table; all values come from this executed example."""

    text = "\\begingroup\\small\n\\begin{longtable}{" + columns + "}\n\\toprule\n"

    header = " & ".join(heading) + "\\\\\n\\midrule\n"

    text += header + "\\endfirsthead\n\\toprule\n" + header + "\\endhead\n"

    formatted_values = []

    for row in rows:
        formatted_values_2 = []

        for value in row:
            formatted_values_2.append(str(value))

        formatted_values.append(' & '.join(formatted_values_2) + '\\\\')

    text += '\n'.join(formatted_values)

    text += "\n\\bottomrule\n\\end{longtable}\n\\endgroup\n"

    (FOLDER / filename).write_text(text, encoding="utf-8")


def hx(value, size=8):
    return "\\texttt{" + f"{value:0{size}X}" + "}"


def escape(text):
    return text.replace("_", r"\_")


def generate():
    FOLDER.mkdir(parents=True, exist_ok=True)

    # Use a fixed public vector, so changing interactive defaults does not break
    # the worked numbers in the explanatory chapters.
    key = plaintext = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")

    correct, clean_trace = piret_sm4.sm4_fault_encrypt(plaintext, key)

    def oracle(number, byte, mask):
        return piret_sm4.sm4_fault_encrypt(plaintext, key, byte, mask, number)[0]

    result = piret_sm4.recover_sm4_master_key(correct, oracle, range(1, 9))

    if not result['complete'] or result['master_key'] != key:
        raise RuntimeError("The worked example failed full key recovery.")

    if sm4.sm4_decrypt_block(correct, result['master_key']) != plaintext:
        raise RuntimeError("The recovered example key failed decryption.")

    # Fail visibly if the example changes; do not silently publish stale numbers.
    assert correct.hex() == "681edf34d206965e86b3e94f536e4246"

    assert result['used'] == 32

    first, second = result['history'][:2]

    assert first['survivors'] == [0x90, 0x91] and second['survivors'] == [0x91]

    assert second['inputs'] == [0x75, 0x77, 0x94, 0x96]

    source_hashes = {}

    for candidate_name in ('sm4.py', 'piret_sm4.py', 'run.py', 'attack_steps.py', 'terminal_log.py', 'piret_aes.py'):
        source_hashes[candidate_name] = hashlib.sha256((ROOT / 'src' / candidate_name).read_bytes()).hexdigest()

    serializable = dict(plaintext=plaintext.hex(), simulation_key=key.hex(), ciphertext=correct.hex(), recovered_key=result['master_key'].hex(), used=result['used'], round_keys=result['round_keys'], observations=result['history'], clean_trace=clean_trace, source_sha256=source_hashes)

    (FOLDER / "example.json").write_text(json.dumps(serializable, indent=2), encoding="utf-8")

    element_values_6 = []

    for item in clean_trace:
        element_values_6.append((item['round'], hx(item['a']), hx(item['b']), hx(item['linear']), hx(item['new'])))

    table('encryption.tex', 'rllll', ['Round', '$A$', '$\\tau(A)$', '$L(\\tau(A))$', 'New word'], element_values_6)

    rows = []

    for event in result['history']:
        c = struct.unpack('>4I', bytes.fromhex(event['clean_view']))

        shift = 24-8*event['byte']

        q = ((c[1] ^ c[2] ^ c[3]) >> shift) & 255

        element_values_5 = set()

        for input_value in event['inputs']:
            element_values_5.add(input_value ^ q)

        fresh = sorted(element_values_5)

        formatted_values_2 = []

        for candidate_value_2 in fresh:
            formatted_values_2.append(hx(candidate_value_2, 2))

        formatted_values_3 = []

        for candidate_value_3 in event['survivors']:
            formatted_values_3.append(hx(candidate_value_3, 2))

        rows.append((event['round'], event['byte'], hx(event['mask'], 2), hx(event['delta_b'] >> shift & 255, 2), hx(q, 2), ' '.join(formatted_values_2), ' '.join(formatted_values_3)))

    table("observations.tex", "rrlllll", ["Round", "Byte", "$e$", "$d$", "$q$", "Fresh key guesses", "Intersection"], rows)

    # Show all rejected inputs as well as accepted inputs for both first masks.
    rows = []

    for a in range(256):
        d1 = sm4.SBOX[a] ^ sm4.SBOX[a ^ 1]

        d2 = sm4.SBOX[a] ^ sm4.SBOX[a ^ 2]

        if d1 == 79:
            element_values = 'ACCEPT'
        else:
            element_values = 'reject'

        if d2 == 129:
            element_values_2 = 'ACCEPT'
        else:
            element_values_2 = 'reject'

        rows.append((hx(a, 2), hx(sm4.SBOX[a], 2), hx(d1, 2), element_values, hx(d2, 2), element_values_2, hx(a ^ 7, 2)))

    table("all_candidates.tex", "lllllll", ["$a$", "$S(a)$", "$d$ for $e=01$", "$d=4F$?", "$d$ for $e=02$", "$d=81$?", "$a\\oplus07$"], rows)

    delta_x = 0x734E3D3D

    accumulator, rows = 0, []

    for bit in range(32):
        basis = piret_sm4.inverse_linear(1 << bit)

        if delta_x & 1 << bit:
            contribution = basis
        else:
            contribution = 0

        accumulator ^= contribution

        rows.append((bit, (delta_x >> bit) & 1, hx(basis), hx(contribution), hx(accumulator)))

    assert accumulator == 0x4F000000

    table("inverse_bits.tex", "rrlll", ["Bit", "Input", "Inverse basis", "Contribution", "Running XOR"], rows)

    # Trace schedule inversion using only the four keys recovered by the solver.
    words_values = []

    for row in range(28, 32):
        words_values.append(result['round_keys'][row])

    words = [None] * 32 + words_values

    rows = []

    def schedule_step(index, recovered):
        value = words[index+1] ^ words[index+2] ^ words[index+3] ^ sm4.CK[index]

        substituted = sm4.sbox(value)

        words[index] = recovered

        rows.append((index, hx(sm4.CK[index]), hx(value), hx(substituted), hx(sm4.linear_key(substituted)), hx(recovered)))

    master = piret_sm4.reverse_sm4(words[32:], schedule_step)

    assert master == key

    table("schedule.tex", "rlllll", ["$i$", "$CK_i$", "$U$", "$\\tau(U)$", "$L'(\\tau(U))$", "$K_i$"], rows)

    element_values_4 = []

    for candidate_index in range(4):
        element_values_4.append((candidate_index, hx(words[candidate_index]), hx(sm4.FK[candidate_index]), hx(words[candidate_index] ^ sm4.FK[candidate_index]), 'Master word'))

    table('fk.tex', 'rllll', ['$i$', '$K_i$', '$FK_i$', '$MK_i=K_i\\oplus FK_i$', 'Role'], element_values_4)

    # Record a concrete earlier-round example from the first round-30 observation.
    matching_item = None

    matching_item_found = False

    for e in result['history']:
        if e['round'] == 30:
            matching_item = e
            matching_item_found = True
            break

    if not matching_item_found:
        raise StopIteration()

    event = matching_item

    lines = ["FIRST ROUND-30 OBSERVATION (new fault, not reused round-31 data)"]

    for label in ('correct', 'faulty', 'clean_view', 'faulty_view'):
        lines.append(f"{label}: {event[label].upper()}")

    for label in ('correct', 'faulty'):
        w = struct.unpack('>4I', bytes.fromhex(event[label]))[::-1]

        recovered_rk31 = int(event['peeled_with']['31'], 16)

        a = w[0] ^ w[1] ^ w[2] ^ recovered_rk31

        b = sm4.sbox(a)

        old = w[3] ^ sm4.linear(b)

        formatted_values = []

        for candidate_value in w:
            formatted_values.append(f'{candidate_value:08X}')

        lines += [label.upper(), 'Chronological window: ' + ' '.join(formatted_values), f'A={a:08X}; tau(A)={b:08X}; L(tau(A))={sm4.linear(b):08X}', f'Restored older word={w[3]:08X} XOR {sm4.linear(b):08X}={old:08X}']

    (FOLDER / 'peeling.txt').write_text('\n'.join(lines), encoding='utf-8')

    # Source excerpts carry real first-line numbers and refresh on every build.
    selections = {
        'piret_aes.py': ['Terminal'],
        'sm4.py': ['observe', 'round', 'generate_round_key', 'key_expansion', 'sm4_process_block'],
        'attack_steps.py': ['sm4_observation', 'sm4_schedule', 'sm4_fault_trace', 'verification', 'emit'],
        'terminal_log.py': ['Tee', 'terminal_log', 'run_with_log']
    }

    sections = []

    for filename, names in selections.items():
        source = (ROOT / 'src' / filename).read_text(encoding='utf-8')

        source_lines = source.splitlines()

        nodes = {}

        for candidate_node in ast.parse(source).body:
            if isinstance(candidate_node, (ast.FunctionDef, ast.ClassDef)):
                nodes[candidate_node.name] = candidate_node

        sections.append(r'\section{Source excerpts: \texttt{' + escape(filename) + '}}')

        for name in names:
            node = nodes[name]
            element_values_3 = []

            for d in node.decorator_list:
                element_values_3.append(d.lineno)

            first_line = min([node.lineno] + element_values_3)
            output_name = filename[:-3] + '_' + name + '.txt'
            (FOLDER / output_name).write_text('\n'.join(source_lines[first_line-1:node.end_lineno]) + '\n', encoding='utf-8')
            sections += [r'\subsection{\texttt{' + escape(name) + '}}', f'Source lines {first_line}--{node.end_lineno}.', r'\VerbatimInput[firstnumber=' + str(first_line) + ']{generated/' + output_name + '}']

    (FOLDER / 'source_excerpts.tex').write_text('\n'.join(sections), encoding='utf-8')

    coverage = generate_line_guide(ROOT, FOLDER)

    (FOLDER / 'line_coverage.json').write_text(json.dumps(coverage, indent=2), encoding='utf-8')

    print(f"Authored line explanations cover {len(coverage)} executable source lines.")
    print(f"Validated SM4 worked example: {result['used']} faulty ciphertexts; master key {master.hex().upper()}.")
    print(f"Generated tables and current-code excerpts in {FOLDER}")


if __name__ == '__main__':
    from terminal_log import run_with_log

    raise SystemExit(run_with_log(generate, 'sm4_piret_example'))

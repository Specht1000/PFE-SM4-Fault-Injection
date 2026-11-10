"""Reproducible cipher/DFA measurements using the project's actual implementations."""
import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import random
import statistics
import sys
import time
import tracemalloc

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import aes
import sm4
import piret_aes
import piret_sm4
import giraud_aes
import giraud_sm4


def hd(a, b):
    element_values = []

    for x, y in zip(a, b):
        element_values.append(bin(x ^ y).count('1'))

    return sum(element_values)


def summary(values):
    if len(values) > 1:
        result_value_2 = statistics.stdev(values)
    else:
        result_value_2 = 0

    return dict(n=len(values), mean=statistics.mean(values), stdev=result_value_2, minimum=min(values), maximum=max(values))


def flip(data, bit):
    result = bytearray(data)

    # Convert a bit index to its containing byte and flip exactly that bit.
    result[bit // 8] ^= 1 << (bit % 8)

    return bytes(result)


def sbox_metrics(box):
    """Exact DDT and Walsh spectra; exclude zero input/output masks as appropriate."""

    ddt = []

    # For each nonzero input difference, count S-box output differences over all 256 inputs.
    for delta in range(1, 256):
        element_values = []

        for candidate_x_4 in range(256):
            element_values.append(box[candidate_x_4] ^ box[candidate_x_4 ^ delta])

        counts = Counter(element_values)

        ddt.append(max(counts.values()))

    walsh_max, degrees = 0, []

    for mask in range(1, 256):
        # Project the byte S-box output onto one Boolean component using a nonzero output mask.
        truth = []

        for candidate_x_3 in range(256):
            truth.append(bin(mask & box[candidate_x_3]).count('1') % 2)

        # Copy the truth table before the binary Mobius transform computes ANF coefficients.
        anf = truth[:]

        for bit in range(8):
            for x in range(256):
                if x & (1 << bit):
                    anf[x] ^= anf[x ^ (1 << bit)]

        element_values_3 = []

        for candidate_x_2, coefficient in enumerate(anf):
            if coefficient:
                element_values_3.append(bin(candidate_x_2).count('1'))

        degrees.append(max(element_values_3))

        # Map Boolean values to +1/-1 before the Walsh-Hadamard transform.
        spectrum = []

        for candidate_bit in truth:
            spectrum.append(1 - 2 * candidate_bit)

        width = 1

        while width < 256:
            for start in range(0, 256, 2 * width):
                for j in range(start, start + width):
                    a, b = spectrum[j], spectrum[j + width]
                    # Each butterfly computes sum and difference; doubling width covers the next input bit.
                    spectrum[j], spectrum[j + width] = a + b, a - b

            width *= 2

        element_values_2 = []

        for value in spectrum[1:]:
            element_values_2.append(abs(value))

        walsh_max = max(walsh_max, max(element_values_2))

    result_values = []

    for candidate_x in range(256):
        if box[candidate_x] == candidate_x:
            result_values.append(candidate_x)

    return dict(bijective=len(set(box)) == 256, fixed_points=result_values, differential_uniformity=max(ddt), maximum_differential_probability=max(ddt) / 256, maximum_absolute_walsh=walsh_max, maximum_linear_bias=walsh_max / 512, minimum_component_nonlinearity=128 - walsh_max // 2, component_degree_min=min(degrees), component_degree_max=max(degrees))


def cipher_metrics(name, encrypt, decrypt, box, rng, samples, avalanche_trials, rows):
    key = rng.randbytes(16)

    if name == 'AES-128':
        expected = '69c4e0d86a7b0430d8cdb78070b4c55a'
    else:
        expected = '681edf34d206965e86b3e94f536e4246'

    if name == 'AES-128':
        element_values_3 = aes.KEY
    else:
        element_values_3 = sm4.KEY

    vector_key = bytes.fromhex(element_values_3)

    if name == 'AES-128':
        element_values_2 = aes.PLAINTEXT
    else:
        element_values_2 = sm4.PLAINTEXT

    vector_pt = bytes.fromhex(element_values_2)

    # Fixed public vectors, independent of editable demonstration settings.
    if name == 'AES-128':
        vector_key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

        vector_pt = bytes.fromhex('00112233445566778899aabbccddeeff')
    else:
        vector_pt = vector_key = bytes.fromhex('0123456789abcdeffedcba9876543210')

    kat = encrypt(vector_pt, vector_key).hex() == expected

    assert kat, name + ' known-answer mismatch'

    avalanche = {}

    # Measure plaintext-bit and key-bit avalanche separately; they are different experiments.
    for mode in ('plaintext', 'key'):
        distances, bit_counts = [], [0] * 128

        for trial in range(avalanche_trials):
            pt, trial_key = rng.randbytes(16), rng.randbytes(16)
            clean = encrypt(pt, trial_key)

            # Change one input bit at a time while keeping the other input fixed.
            for bit in range(128):
                if mode == 'plaintext':
                    altered = encrypt(flip(pt, bit), trial_key)
                else:
                    altered = encrypt(pt, flip(trial_key, bit))

                distance = hd(clean, altered)
                distances.append(distance)

                for output in range(128):
                    bit_counts[output] += ((clean[output//8] ^ altered[output//8]) >> (output%8)) & 1

                rows.append(dict(cipher=name, mode=mode, trial=trial, input_bit=bit, changed_bits=distance))

        computed_value_values = []

        for count_3 in bit_counts:
            computed_value_values.append(count_3 / len(distances))

        avalanche[mode] = dict(**summary(distances), changed_fraction=statistics.mean(distances) / 128, output_flip_probability=computed_value_values)

    blocks = []

    for unused_index in range(samples):
        blocks.append(rng.randbytes(16))

    outputs = []

    for candidate_pt_2 in blocks:
        outputs.append(encrypt(candidate_pt_2, key))

    all_match = True

    for candidate_pt, ct in zip(blocks, outputs):
        if not decrypt(ct, key) == candidate_pt:
            all_match = False
            break

    roundtrips = all_match

    assert roundtrips

    # Estimate output-byte statistics from the sample; these are not proofs of randomness.
    counts = Counter(b''.join(outputs))

    n = 16 * samples

    element_values_5 = []

    for count_2 in counts.values():
        element_values_5.append(count_2 / n * math.log2(count_2 / n))

    entropy = -sum(element_values_5)

    element_values_4 = []

    for byte, count in counts.items():
        element_values_4.append(bin(byte).count('1') * count)

    ones = sum(element_values_4)

    benchmark = {}

    for operation, fn, inputs in [('encrypt', encrypt, blocks), ('decrypt', decrypt, outputs)]:
        fn(inputs[0], key)  # warmup outside measurement

        times, cpu_times = [], []

        for _ in range(5):
            cpu, start = time.process_time_ns(), time.perf_counter_ns()

            for block in inputs:
                fn(block, key)

            times.append((time.perf_counter_ns()-start)/samples)
            cpu_times.append((time.process_time_ns()-cpu)/samples)

        # Measure Python allocation separately so instrumentation does not distort timing batches.
        tracemalloc.start()

        fn(inputs[0], key)

        _, peak = tracemalloc.get_traced_memory()

        tracemalloc.stop()

        median = statistics.median(times)

        benchmark[operation] = dict(ns_per_block_median=median, ns_per_block_batches=times,
                                   cpu_ns_per_block_median=statistics.median(cpu_times),
                                   bytes_per_second=16e9/median, python_peak_bytes_one_call=peak)

    element_values = []

    for x in range(256):
        element_values.append((counts[x] - n / 256) ** 2 / (n / 256))

    return dict(known_answer_pass=kat, roundtrip_pass=roundtrips, key_bits=128, block_bits=128, exhaustive_key_space=str(2 ** 128), expected_classical_search_trials=str(2 ** 127), avalanche=avalanche, sbox=sbox_metrics(box), benchmark=benchmark, statistics=dict(blocks=samples, bytes=n, empirical_byte_entropy=entropy, byte_chi_square=sum(element_values), one_fraction=ones / (n * 8), monobit_normal_approx_p=math.erfc(abs(2 * ones - n * 8) / math.sqrt(2 * n * 8)), repeated_output_blocks=samples - len(set(outputs))))


def attack_trial(cipher, model, key, pt):
    if cipher == 'AES-128':
        encrypt = aes.aes_encrypt
    else:
        encrypt = sm4.sm4_encrypt_block

    correct = encrypt(pt, key)

    queries, history, oracle_ns = [], [], 0

    def oracle(number, byte, mask):
        nonlocal oracle_ns

        start = time.perf_counter_ns()

        if cipher == 'SM4':
            faulty = piret_sm4.sm4_fault_encrypt(pt, key, byte, mask, number)[0]
        elif model == 'Piret':
            faulty = piret_aes.encrypt_with_trace(pt, key, byte % 4, byte // 4, mask, number)[0]
        else:
            faulty = giraud_aes.aes_fault_encrypt(pt, key, byte, mask)[0]

        oracle_ns += time.perf_counter_ns()-start

        element_values = []

        for input_value, candidate_byte in zip(correct, faulty):
            element_values.append(input_value != candidate_byte)

        queries.append(dict(round=number, byte=byte, mask=mask, correct=correct.hex(), faulty=faulty.hex(), changed_bits=hd(correct, faulty), changed_bytes=sum(element_values)))

        return faulty

    start = time.perf_counter_ns()

    if cipher == 'SM4':
        # Select the SM4 candidate model while keeping the same controlled round/byte oracle.
        if model == 'Piret':
            solver = piret_sm4
        else:
            solver = giraud_sm4

        if model == 'Piret':
            options = {}
        else:
            options = dict(known_bit=model == 'Giraud-known')

        result = solver.recover_sm4_master_key(correct, oracle, **options)

        recovered = result['master_key']

        history = result['history']
    elif model == 'Piret':
        def outputs():
            for mask in range(1, 17):
                yield oracle(8, 0, mask)

        def record(observation, column, before, fresh, survivors):
            history.append(dict(observation=observation, column=column, before=before,
                                pair_candidates=fresh, remaining=len(survivors)))

        last, _ = piret_aes.recover_last_key(correct, outputs(), observer=record)

        # Reverse only a uniquely recovered AES final key; ambiguity must remain an explicit failure.
        if last is not None:
            recovered = piret_aes.reverse_key_schedule(last)
        else:
            recovered = None

    else:
        last, complete = bytearray(16), True

        for byte in range(16):
            survivors = set(range(256))

            for observation, mask in enumerate(giraud_aes.SINGLE_BITS, 1):
                faulty = oracle(10, byte, mask)

                if model == 'Giraud-known':
                    element_values = mask
                else:
                    element_values = None

                position, fresh = giraud_aes.aes_candidates(correct, faulty, element_values)
                before = len(survivors)
                survivors &= fresh
                history.append(dict(byte=byte, observation=observation, before=before,
                                    pair_candidates=len(fresh), remaining=len(survivors)))

                if len(survivors) == 1:
                    last[position] = next(iter(survivors))
                    break

            if len(survivors) != 1:
                complete = False
                break

        if complete:
            recovered = piret_aes.reverse_key_schedule(bytes(last))
        else:
            recovered = None

    elapsed = time.perf_counter_ns()-start

    # Check the simulation ground truth and re-encryption after recovery, never during filtering.
    verified = recovered == key and encrypt(pt, recovered) == correct

    if recovered:
        result_value = recovered.hex()
    else:
        result_value = None

    return dict(cipher=cipher, model=model, verified=verified, faults=len(queries), elapsed_ns=elapsed, oracle_ns=oracle_ns, solver_excluding_oracle_ns=elapsed - oracle_ns, plaintext=pt.hex(), simulation_key=key.hex(), recovered_key=result_value, observations=queries, candidate_history=history)


def main():
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument('--samples', type=int, default=1024)
    parser.add_argument('--avalanche-trials', type=int, default=4)
    parser.add_argument('--attack-trials', type=int, default=10)
    parser.add_argument('--seed', type=int, default=20261108)

    args = parser.parse_args()

    if min(args.samples, args.avalanche_trials, args.attack_trials) < 1:
        parser.error('All sample counts must be positive.')

    # Use one seeded generator so a repeated configuration produces the same sampled inputs.
    rng = random.Random(args.seed)

    out = ROOT / 'analysis' / 'results'

    out.mkdir(parents=True, exist_ok=True)

    # Record settings, environment and source hashes so measurements can be traced to this code version.
    report_values = {}

    for candidate_name in ('aes.py', 'sm4.py', 'piret_aes.py', 'piret_sm4.py', 'giraud_aes.py', 'giraud_sm4.py', 'giraud_common.py', 'giraud_terminal.py'):
        report_values[candidate_name] = hashlib.sha256((ROOT / 'src' / candidate_name).read_bytes()).hexdigest()

    report = dict(generated_utc=datetime.now(timezone.utc).isoformat(), configuration=vars(args), environment=dict(python=sys.version, platform=platform.platform(), processor=platform.processor()), source_sha256=report_values, ciphers={}, attacks=[])

    rows = []

    for name, enc, dec, box in [('AES-128', aes.aes_encrypt, aes.aes_decrypt, aes.SBOX),
                                ('SM4', sm4.sm4_encrypt_block, sm4.sm4_decrypt_block, sm4.SBOX)]:
        print('Measuring', name, flush=True)

        report['ciphers'][name] = cipher_metrics(name, enc, dec, box, rng, args.samples, args.avalanche_trials, rows)

        for model in ('Piret', 'Giraud-known', 'Giraud-unknown'):
            print('Attacking', name, model, flush=True)

            for _ in range(args.attack_trials):
                report['attacks'].append(attack_trial(name, model, rng.randbytes(16), rng.randbytes(16)))

    (out/'measurements.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')

    with (out/'avalanche.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))

        writer.writeheader()

        writer.writerows(rows)

    write_report(report, out)

    from plot_results import generate_plots

    generate_plots(out)

    print('Results:', out)

    all_match = True

    for trial in report['attacks']:
        if not trial['verified']:
            all_match = False
            break

    if not all_match:
        raise SystemExit('Some attacks did not recover the key; see results (no success assumed).')


def write_report(report, out):
    lines = ['# Análise experimental — AES-128, SM4 e DFA', '',
             'Resultados gerados por `python analysis/run_analysis.py`. Dados completos em `measurements.json`; amostras de avalanche em `avalanche.csv`.', '',
             f"Configuração: {report['configuration']}. Ambiente: {report['environment']['platform']}; Python {platform.python_version()}.", '',
             '## Algoritmos', '',
             '| Métrica | AES-128 | SM4 |', '|---|---:|---:|']

    ciphers = list(report['ciphers'].values())

    metrics = [('Vetor conhecido / round-trip', lambda c: f"{c['known_answer_pass']} / {c['roundtrip_pass']}"),
               ('Avalanche do texto (% bits)', lambda c: f"{100*c['avalanche']['plaintext']['changed_fraction']:.3f}"),
               ('Avalanche da chave (% bits)', lambda c: f"{100*c['avalanche']['key']['changed_fraction']:.3f}"),
               ('Entropia empírica (bits/byte)', lambda c: f"{c['statistics']['empirical_byte_entropy']:.5f}"),
               ('Fração de bits 1', lambda c: f"{c['statistics']['one_fraction']:.5f}"),
               ('Qui-quadrado bytes (255 graus de liberdade)', lambda c: f"{c['statistics']['byte_chi_square']:.2f}"),
               ('Monobit p aproximado', lambda c: f"{c['statistics']['monobit_normal_approx_p']:.4f}"),
               ('Uniformidade diferencial S-box', lambda c: str(c['sbox']['differential_uniformity'])),
               ('Não linearidade mínima S-box', lambda c: str(c['sbox']['minimum_component_nonlinearity'])),
               ('Grau algébrico das componentes S-box', lambda c: f"{c['sbox']['component_degree_min']}–{c['sbox']['component_degree_max']}"),
               ('Cifrar (µs/bloco, mediana)', lambda c: f"{c['benchmark']['encrypt']['ns_per_block_median']/1000:.2f}"),
               ('Decifrar (µs/bloco, mediana)', lambda c: f"{c['benchmark']['decrypt']['ns_per_block_median']/1000:.2f}"),
               ('Cifrar (KiB/s)', lambda c: f"{c['benchmark']['encrypt']['bytes_per_second']/1024:.2f}"),
               ('Pico alocações Python ao cifrar (bytes)', lambda c: str(c['benchmark']['encrypt']['python_peak_bytes_one_call']))]

    for label, fn in metrics:
        formatted_values = []

        for column in ciphers:
            formatted_values.append(fn(column))

        lines.append('| ' + label + ' | ' + ' | '.join(formatted_values) + ' |')

    lines += ['', '## Ataques', '', '| Cifra | Modelo | Recuperações verificadas | Falhas média [mín–máx] | Tempo total médio (ms) | Solver sem oráculo (ms) |', '|---|---|---:|---:|---:|---:|']

    for cipher in report['ciphers']:
        for model in ('Piret', 'Giraud-known', 'Giraud-unknown'):
            trials = []

            for t_5 in report['attacks']:
                if t_5['cipher'] == cipher and t_5['model'] == model:
                    trials.append(t_5)

            faults = []

            for t_4 in trials:
                faults.append(t_4['faults'])

            element_values = []

            for t in trials:
                element_values.append(t['verified'])

            element_values_2 = []

            for t_2 in trials:
                element_values_2.append(t_2['elapsed_ns'])

            element_values_3 = []

            for t_3 in trials:
                element_values_3.append(t_3['solver_excluding_oracle_ns'])

            lines.append(f'| {cipher} | {model} | {sum(element_values)}/{len(trials)} | {statistics.mean(faults):.2f} [{min(faults)}–{max(faults)}] | {statistics.mean(element_values_2) / 1000000.0:.3f} | {statistics.mean(element_values_3) / 1000000.0:.3f} |')

    lines += ['', '## Interpretação e limites', '',
              '- Cada cifra tem bloco e chave de 128 bits: espaço nominal 2^128 e busca clássica média de aproximadamente 2^127 tentativas para chave uniforme. Isso não mede a entropia de um gerador de chaves. O PRNG com seed serve apenas à reprodução dos experimentos.',
              '- Avalanche usa todos os 128 bits de entrada, um por vez, para cada texto/chave sorteado. A referência é 64 bits alterados (50%). Médias e probabilidades por bit não constituem um teste SAC completo nem prova de segurança.',
              '- Estatísticas usam textos aleatórios sob uma chave fixa por cifra. Entropia próxima de 8 e p monobit não certificam aleatoriedade ou segurança; não foi executada a suíte NIST SP 800-22. Amostras finitas e testes múltiplos exigem cautela.',
              '- DDT, espectro de Walsh, não linearidade e grau algébrico são exatos para a S-box de 8 bits. Não são limites de probabilidade para ataques à cifra completa nem uma criptoanálise linear/diferencial de todas as rodadas.',
              '- AES Piret: XOR em um byte antes de MixColumns da rodada 8, máscaras 1–16; o solver recebe apenas saídas e desconhece máscara/linha. Giraud AES: bit antes de SubBytes da rodada 10, todos os 16 bytes. Known compartilha a máscara; unknown testa os oito bits possíveis.',
              '- SM4: XOR na entrada da S-box, rodadas 31, 30, 29 e 28 (índices iniciando em zero), quatro bytes por rodada. Piret conhece a máscara e usa 1–8; Giraud usa oito máscaras de um bit, conhecido ou desconhecido. A recuperação completa exige acesso às quatro rodadas, retiradas com subchaves já recuperadas.',
              '- As contagens incluem somente saídas falhas consultadas e há uma saída correta adicional por ensaio. Cada observação traz XOR implícito nas duas saídas, bits/bytes alterados e histórico de candidatos no JSON. Não há falhas descartadas, ruído ou tentativas físicas sem efeito neste modelo ideal.',
              '- Taxa de sucesso é a proporção nos ensaios executados, sem garantia de generalização. Verifica-se igualdade da chave e recifragem. Casos ambíguos contam como falha de recuperação.',
              '- Tempo inclui expansão de chave a cada bloco, cinco lotes após aquecimento, sem tracemalloc ativo. Memória é pico de alocações Python de uma chamada separada, não RSS, RAM de microcontrolador ou memória total do processo. Tempo do oráculo inclui instrumentação e traces; solver sem oráculo é a diferença dos tempos.',
              '- Para blocos independentes, o trabalho cresce linearmente com a quantidade de blocos; o estado de cifra tem tamanho constante. Os tempos descrevem estas implementações didáticas em Python, sem comparação com AES acelerado. CPU por bloco está no JSON; ciclos/byte, energia, clock e tensão não foram medidos.',
              '- Ponto lógico de injeção é conhecido no simulador. Janela temporal física, localização no chip, glitches de tensão/clock, laser e EM dependem de equipamento e calibração. Estes resultados não demonstram viabilidade física nem resistência a canais laterais.', '',
              '## Referências primárias', '',
              '- [NIST FIPS 197 — AES](https://doi.org/10.6028/NIST.FIPS.197-upd1)',
              '- [RFC 8998 — uso de SM4](https://www.rfc-editor.org/rfc/rfc8998.html)',
              '- Modelos e equações executados: `src/piret_aes.py`, `src/piret_sm4.py`, `src/giraud_aes.py` e `src/giraud_sm4.py`; documentação local em `docs/`.', '']

    (out/'report.md').write_text('\n'.join(lines), encoding='utf-8')


if __name__ == '__main__':
    from terminal_log import run_with_log

    raise SystemExit(run_with_log(main, "analysis"))

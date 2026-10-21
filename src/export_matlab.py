"""Export reproducible simulated AES/SM4 fault campaigns for MATLAB.

No third-party Python packages. Candidate solvers receive only the observations
allowed by each model; the key is used only by the simulated target and checks.
"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import struct
import aes
import sm4
import piret
import run as demo

ROOT = Path(__file__).resolve().parents[1]
DELTA_FIELDS = [f"delta_{index:02d}" for index in range(16)]


def difference_row(algorithm, trial, stage, label, scope, correct, faulty):
    if len(correct) != len(faulty) or len(correct) not in (4, 16):
        raise ValueError("A compared scope must contain 4 or 16 bytes.")
    delta = bytes(a ^ b for a, b in zip(correct, faulty))
    row = dict(algorithm=algorithm, trial=trial, stage=stage, label=label, scope=scope, valid_bytes=len(delta), correct_hex=correct.hex(), faulty_hex=faulty.hex(), changed_bits=sum(bin(v).count("1") for v in delta), changed_bytes=sum(bool(v) for v in delta))
    row.update({field: delta[index] if index < len(delta) else 0 for index, field in enumerate(DELTA_FIELDS)})
    return row


def propagation_rows(plaintext, aes_key, sm4_key, trial, row, column, byte, mask):
    _, clean = piret.trace_round8(plaintext, aes_key, fault_round=9)
    _, faulty = piret.trace_round8(plaintext, aes_key, row, column, mask, fault_round=9)
    lookup = {(number, op): state for number, op, state in clean}
    stages = [(9, "ShiftRows", "R9 before fault"), (9, "Fault point", "R9 injected XOR"), (9, "MixColumns", "R9 MixColumns"), (9, "AddRoundKey", "R9 AddRoundKey"), (10, "SubBytes", "R10 SubBytes"), (10, "ShiftRows", "R10 ShiftRows"), (10, "AddRoundKey", "Ciphertext")]
    rows = []
    fault_lookup = {(number, op): state for number, op, state in faulty}
    for index, (number, operation, label) in enumerate(stages):
        rows.append(difference_row("AES", trial, index, label, "state128", lookup[number, operation], fault_lookup[number, operation]))
    # Each algorithm uses the same trial plaintext, but a different target key.
    correct, clean = demo.sm4_encrypt(plaintext, sm4_key)
    faulty_output, faulty = demo.sm4_encrypt(plaintext, sm4_key, byte, mask)
    a = clean[-1]["a"].to_bytes(4, "big")
    rows.append(difference_row("SM4", trial, 0, "Before fault A [32b]", "sbox_input32", a, a))
    for index, (field, label, scope) in enumerate([("a", "Injected A [32b]", "sbox_input32"), ("b", "S-box B [32b]", "sbox_output32"), ("linear", "L(B) [32b]", "linear_output32"), ("new", "X35 [32b]", "new_word32")], 1):
        rows.append(difference_row("SM4", trial, index, label, scope, clean[-1][field].to_bytes(4, "big"), faulty[-1][field].to_bytes(4, "big")))
    rows.append(difference_row("SM4", trial, 5, "Ciphertext [128b]", "ciphertext128", correct, faulty_output))
    return rows


def recovery_rows(algorithm, plaintext, key, trial, fault_row, maximum, rng):
    """One sequence per group, with explicit observations and absorbing success."""
    correct = piret.aes_target_encrypt(plaintext, key) if algorithm == "AES" else demo.sm4_encrypt(plaintext, key)[0]
    true_key = aes.state_to_bytes(aes.key_expansion(key)[10]) if algorithm == "AES" else sm4.key_expansion(key)[31].to_bytes(4, "big")
    rows, recovered = [], bytearray(len(true_key))
    all_unique, total_used = True, 0
    for group in range(4):
        survivors, last_faulty = None, ""
        prior = 2 ** 32 if algorithm == "AES" else 256
        masks = ([1, 2] + rng.sample(list(range(3, 256)), maximum - 2)) if maximum >= 2 else [1]
        rows.append(dict(algorithm=algorithm, trial=trial, group=group, observation=0, candidate_count=prior, evaluated=0, mask=0, correct_hex=correct.hex(), faulty_hex="", true_key_survives=1))
        for observation, mask in enumerate(masks, 1):
            evaluated = survivors is None or len(survivors) != 1
            if evaluated:
                if algorithm == "AES":
                    faulty = piret.trace_round8(plaintext, key, fault_row, group, mask, fault_round=9)[0]
                    fresh = piret.key_candidates(correct, faulty, group)
                    truth = tuple(true_key[position] for position in piret.output_positions(group))
                else:
                    faulty = demo.sm4_encrypt(plaintext, key, group, mask)[0]
                    fresh = demo.sm4_byte_candidates(correct, faulty, group, mask)[0]
                    truth = true_key[group]
                survivors = fresh if survivors is None else survivors & fresh
                if truth not in survivors:
                    raise RuntimeError("True target key was eliminated by the observation model.")
                total_used += 1
                last_faulty = faulty.hex()
            rows.append(dict(algorithm=algorithm, trial=trial, group=group, observation=observation, candidate_count=len(survivors), evaluated=int(evaluated), mask=mask if evaluated else 0, correct_hex=correct.hex(), faulty_hex=last_faulty if evaluated else "", true_key_survives=1))
        all_unique = all_unique and len(survivors) == 1
        if len(survivors) == 1:
            if algorithm == "AES":
                for position, value in zip(piret.output_positions(group), next(iter(survivors))):
                    recovered[position] = value
            else:
                recovered[group] = next(iter(survivors))
    if all_unique and bytes(recovered) != true_key:
        raise RuntimeError("Recovered target does not match the simulation truth.")
    if all_unique and algorithm == "AES" and piret.reverse_key_schedule(recovered) != key:
        raise RuntimeError("AES master-key reversal failed.")
    return rows, dict(algorithm=algorithm, trial=trial, target="K10_128bits" if algorithm == "AES" else "rk31_32bits", all_groups_unique=int(all_unique), evaluated_faults=total_used)


def write_csv(path, rows):
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def export_campaign(output, trials=32, observations=8, seed=2026):
    if trials < 2 or not 1 <= observations <= 255:
        raise ValueError("Use at least 2 trials and 1..255 observations per group.")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    # Mark interrupted exports; MATLAB accepts only a completed manifest.
    manifest = output / "manifest.json"
    manifest.write_text(json.dumps(dict(status="running")), encoding="utf-8")
    aes_key, sm4_key = demo.block(aes.KEY), demo.block(sm4.KEY)
    rng = random.Random(seed)
    propagation, candidates, recovery, inputs = [], [], [], []
    for trial in range(1, trials + 1):
        plaintext = demo.block(aes.PLAINTEXT) if trial == 1 else bytes(rng.randrange(256) for _ in range(16))
        fault_row, column, byte, mask = (0, 0, 0, 1) if trial == 1 else (rng.randrange(4), rng.randrange(4), rng.randrange(4), rng.randrange(1, 256))
        inputs.append(dict(trial=trial, plaintext_hex=plaintext.hex(), aes_fault_row=fault_row, aes_fault_column=column, sm4_fault_byte=byte, propagation_mask=mask))
        propagation.extend(propagation_rows(plaintext, aes_key, sm4_key, trial, fault_row, column, byte, mask))
        for algorithm, key in [("AES", aes_key), ("SM4", sm4_key)]:
            history, result = recovery_rows(algorithm, plaintext, key, trial, fault_row, observations, rng)
            candidates.extend(history)
            recovery.append(result)
    tables = dict(propagation=propagation, candidates=candidates, recovery=recovery, inputs=inputs)
    for name, rows in tables.items():
        write_csv(output / (name + ".csv"), rows)
    source_files = [Path(__file__), ROOT / "src/aes.py", ROOT / "src/sm4.py", ROOT / "src/piret.py", ROOT / "src/run.py"]
    metadata = dict(status="complete", schema_version=1, created_utc=datetime.now(timezone.utc).isoformat(), trials=trials, observations_per_group=observations, seed=seed, fixed_aes_key=aes_key.hex(), fixed_sm4_key=sm4_key.hex(), data_kind="software_simulation", aes_model="unknown byte XOR before round-9 MixColumns", sm4_model="known byte XOR at S-box input in zero-based round 31", scope_note="SM4 intermediate scopes are 32 bits; ciphertext is 128 bits. Compare model-specific trajectories, not relative security.", candidate_note="AES count is per 32-bit K10 quartet; SM4 count is per 8-bit rk31 byte. log2(count) is not measured Shannon entropy.", completed_note="Candidate count 1 is carried forward after success; evaluated=0 marks no additional query.", sources_sha256={path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in source_files}, csv_sha256={name + ".csv": hashlib.sha256((output / (name + ".csv")).read_bytes()).hexdigest() for name in tables})
    manifest.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"Exported {trials} paired trials to {output.resolve()}")
    print("Targets: AES K10/master key; SM4 rk31 only. No physical traces are simulated.")
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "matlab/results/data")
    parser.add_argument("--trials", type=int, default=32)
    parser.add_argument("--observations", type=int, default=8)
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()
    if args.trials < 2 or not 1 <= args.observations <= 255:
        parser.error("Use at least 2 trials and 1..255 observations.")
    export_campaign(args.output, args.trials, args.observations, args.seed)


if __name__ == "__main__":
    main()

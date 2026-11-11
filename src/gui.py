"""AES / SM4 / Piret / Giraud lessons. Run: python src/gui.py."""
import json
import queue
import random
import struct
import threading
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import aes
import sm4
import run as console
import giraud_aes
import giraud_sm4
from giraud_common import masks_for, intersect_candidates, SINGLE_BITS
import attack_steps

AES_KEY = "000102030405060708090a0b0c0d0e0f"
AES_INPUT = "00112233445566778899aabbccddeeff"
SM4_VECTOR = "0123456789abcdeffedcba9876543210"
BG, PANEL, CELL, TEXT, MUTED, ACCENT, ORANGE, RED = "#0b0f14", "#121822", "#1b2636", "#e6edf3", "#8ea0b8", "#4fd1c5", "#ffb454", "#ff7373"
INV_SBOX = []

for input_i_2 in range(256):
    INV_SBOX.append(aes.SBOX.index(input_i_2))


def parse_block(value):
    # Convert user-entered hexadecimal into raw bytes before validating block length.
    data = bytes.fromhex(value)

    if len(data) != 16:
        raise ValueError("Enter exactly 16 bytes (32 hexadecimal digits).")

    return data


def snapshot(number, title, explanation, state, detail="", reference=None):
    if reference is None:
        result_value_5 = None
    else:
        result_value_5 = bytes(reference).hex()

    return dict(round=number, title=title, explanation=explanation, state=bytes(state).hex(), detail=detail, reference=result_value_5)


def aes_trace(block, key, decrypt=False, fault=None):
    """Display the actual cipher execution; fault injection stays in piret_aes.py."""

    # Store independent timeline records; GUI navigation must not re-run the cipher.
    if decrypt:
        element_values_12 = 10
    else:
        element_values_12 = 0

    steps = [snapshot(element_values_12, 'Input', 'AES byte index = 4*column + row.', block)]

    # Round keys are used for the teacher view, never supplied to the candidate solver.
    keys = aes.key_expansion(key)

    descriptions = {"SubBytes": "Replace each byte through the nonlinear S-box.", "ShiftRows": "Rotate row r left by r positions.", "MixColumns": "Mix each column in GF(2^8).", "AddRoundKey": "XOR the state with the current round key.", "InvSubBytes": "Undo the nonlinear substitution.", "InvShiftRows": "Rotate rows right to undo ShiftRows.", "InvMixColumns": "Multiply columns by the inverse mixing matrix."}

    if fault:
        if decrypt:
            raise ValueError("Piret fault injection is an encryption experiment.")

        ciphertext, trace = console.piret_aes.encrypt_with_trace(block, key, fault[1], fault[2], fault[3], fault_round=fault[0])

        initial = aes.bytes_to_state(block)

        aes.add_round_key(initial, keys[0])

        steps.append(snapshot(0, "AddRoundKey", descriptions["AddRoundKey"], aes.state_to_bytes(initial)))

        for number, operation, state in trace:
            if operation == 'Fault point':
                title = 'Injected XOR'
            else:
                title = operation

            if operation == 'Fault point':
                element_values_11 = 'External Piret callback changes one byte before MixColumns.'
            else:
                element_values_11 = descriptions[operation]

            steps.append(snapshot(number, title, element_values_11, state))

        return ciphertext, steps

    def observer(number, operation, state):
        # Take snapshots after the real transformation, rather than duplicating cipher equations.
        if operation.startswith("After "):
            title = operation[6:]

            if title == 'AddRoundKey':
                detail = 'Round key: ' + aes.state_to_bytes(keys[number]).hex()
            else:
                detail = ''

            steps.append(snapshot(number, title, descriptions[title], aes.state_to_bytes(state), detail))

    if decrypt:
        function = aes.aes_decrypt
    else:
        function = aes.aes_encrypt

    output = function(block, key, observer=observer)

    return output, steps


def sm4_trace(block, key, decrypt=False):
    """Build visual steps from the actual SM4 engine, without reimplementing it."""

    steps = [snapshot(0, "Input", "Each displayed row is a big-endian 32-bit word.", block)]

    keys, current, values = sm4.key_expansion(key), block, {}

    def observer(index, operation, value):
        nonlocal current

        # Track the current rolling window while scalar SM4 intermediate values are displayed separately.
        if operation == "State input":
            current = struct.pack(">4I", *value)
        elif operation == "Sbox input":
            values["a"] = value

            if decrypt:
                key_index = 31 - index
            else:
                key_index = index

            steps.append(snapshot(index+1, "Round XOR", "XOR the three newest words with the round key.", current, f"A = {value:08X}; rk[{key_index}] = {keys[key_index]:08X}"))
        elif operation == "Sbox output":
            values["b"] = value
            steps.append(snapshot(index+1, "S-box / tau", "Substitute the four bytes; the rolling state is unchanged yet.", current, f"tau({values['a']:08X}) = {value:08X}"))
        elif operation == "Linear output":
            steps.append(snapshot(index+1, "Linear transform", "XOR rotations 2, 10, 18 and 24 for data diffusion.", current, f"L({values['b']:08X}) = {value:08X}"))
        elif operation == "State output":
            current = struct.pack(">4I", *value)
            steps.append(snapshot(index+1, "Shift / new word", "Discard the oldest word and append the new word.", current))
        elif operation == "Ciphertext":
            steps.append(snapshot(32, "Output reversal", "Reverse the four final words.", value))

    if decrypt:
        function = sm4.sm4_decrypt_block
    else:
        function = sm4.sm4_encrypt_block

    output = function(block, key, observer=observer)

    return output, steps


def positions(column):
    """Presentation alias for the attack's final-ShiftRows position mapping."""

    return console.piret_aes.output_positions(column)


def candidates(correct, faulty, column):
    """Candidate filtering belongs to the attack module, not the GUI."""

    return console.piret_aes.key_candidates(correct, faulty, column)


def reverse_schedule(last_key):
    return console.piret_aes.reverse_key_schedule(last_key)


def recover_key(correct, observations):
    """Translate the attack observer into the GUI's candidate-history format."""

    history = []

    def record(index, column, before, fresh, survivors):
        history.append((index, column, fresh, len(survivors)))

    key, used = console.piret_aes.recover_last_key(correct, observations, observer=record)

    return key, history, used


def piret_lesson(block, key, row, column, mask, maximum):
    """Teacher trace plus ciphertext-only recovery, joined into one timeline."""

    clean_ct, clean_steps = aes_trace(block, key)

    first_ct, faulty_steps = aes_trace(block, key, fault=(8, row, column, mask))

    lookup = {}

    for s in clean_steps:
        lookup[s['round'], s['title']] = s

    steps = []

    for step in faulty_steps:
        if step["round"] >= 8:
            if step['title'] == 'Injected XOR':
                reference = lookup[8, 'ShiftRows']
            else:
                reference = lookup[step['round'], step['title']]

            steps.append(dict(step, reference=reference["state"]))

    steps.append(snapshot(10, "DFA equations", "Guess a final-round key byte, remove its XOR and undo the S-box. Four differences must share one unknown error.", first_ct, "d[r] = InvSbox[C[p] XOR k] XOR InvSbox[Cfault[p] XOR k]\nFor error row 0: d = [2e, e, e, 3e] in GF(2^8).\nTry all 4 rows and 255 nonzero e values.\nIntersect FOUR-BYTE tuples across observations.\nThe effective round-9 error differs from the original round-8 mask.", clean_ct))

    element_values = []

    for value in range(1, 256):
        if value != mask:
            element_values.append(value)

    masks = [mask] + random.Random(42).sample(element_values, maximum - 1)

    outputs_values = []

    for value_2 in masks[1:]:
        outputs_values.append(aes_trace(block, key, fault=(8, row, column, value_2))[0])

    outputs = [first_ct] + outputs_values

    last_key, history, used = recover_key(clean_ct, outputs)

    # Maintain separate intersection histories for the four AES key quartets.
    previous_groups = {}

    for index, group, count, remaining in history:
        pair = outputs[index-1]

        steps.extend(attack_steps.aes_piret(clean_ct, pair, group, previous_groups.get(group)))

        fresh = console.piret_aes.key_candidates(clean_ct, pair, group)

        if group not in previous_groups:
            computed_value = fresh
        else:
            computed_value = previous_groups[group] & fresh

        previous_groups[group] = computed_value

        detail = f"Correct: {clean_ct.hex()}\nFaulty #{index}: {outputs[index-1].hex()}\nGroup {group} output positions: {positions(group)}\nCandidates from this pair: {count}\nCandidates after intersection: {remaining}\nSolver inputs: ciphertexts only; no key, mask or intermediate states."

        steps.append(snapshot(10, f"Observation {index} / group {group}", "Each independent fault filters candidate tuples. A unique tuple reveals four K10 bytes.", outputs[index-1], detail, clean_ct))

    recovered = None

    if last_key is not None:
        recovered, schedule_steps = attack_steps.aes_schedule(last_key)

        steps.extend(schedule_steps)

    if recovered is not None:
        steps.extend(attack_steps.verification("aes", block, recovered, clean_ct))

    if recovered is not None and (aes_trace(block, recovered)[0] != clean_ct or recovered != key):
        raise RuntimeError("Recovered key verification failed.")

    if recovered is None:
        detail = 'Ambiguous candidates remain. Increase the observation count.'
    else:
        detail = f'Recovered K10: {last_key.hex()}\nRecovered K0:  {recovered.hex()}\nKnown-plaintext verification: PASS\nSimulation ground-truth check: PASS\nUsed {used} faulty ciphertexts.'

    steps.append(snapshot(10, "Recovery result", "Reverse the AES-128 key schedule once all four groups are unique. This simplified Piret-style solver does not guarantee two faults.", clean_ct, detail))

    if recovered is None:
        result_value_4 = None
    else:
        result_value_4 = recovered.hex()

    return dict(steps=steps, output=first_ct.hex(), correct=clean_ct.hex(), recovered_key=result_value_4, used=used, history=history, verified=recovered is not None)


def pdf_aes_lesson(block, key, row, column, mask, maximum):
    """PDF round-9 model: recover four groups with independent column faults."""

    correct, clean_steps = aes_trace(block, key)

    steps = list(clean_steps)

    lookup = {}

    for candidate_step in clean_steps:
        lookup[candidate_step['round'], candidate_step['title']] = candidate_step

    masks_values = []

    for candidate_value in range(1, 256):
        if candidate_value != mask:
            masks_values.append(candidate_value)

    masks = [mask] + masks_values[:maximum - 1]

    last_key, history, used = bytearray(16), [], 0

    first_faulty = None

    # Start with the chosen column but process all four groups to recover the full AES key.
    computed_value_values = []

    for offset in range(4):
        computed_value_values.append((column + offset) % 4)

    for group in computed_value_values:
        survivors = None

        for observation, value in enumerate(masks, 1):
            faulty, trace = aes_trace(block, key, fault=(9, row, group, value))
            first_faulty = first_faulty or faulty
            used += 1

            for step in trace:
                if step["round"] >= 9:
                    if step['title'] == 'Injected XOR':
                        reference = lookup[9, 'ShiftRows']
                    else:
                        reference = lookup[step['round'], step['title']]

                    steps.append(dict(step, title=f"Column {group} / {step['title']}", reference=reference["state"]))

            # Add exhaustive numerical tables before the concise candidate-count summary.
            steps.extend(attack_steps.aes_piret(correct, faulty, group, survivors))
            fresh = console.piret_aes.key_candidates(correct, faulty, group)

            if survivors is None:
                before = None
            else:
                before = len(survivors)

            if survivors is None:
                survivors = fresh
            else:
                survivors = survivors & fresh

            if not survivors:
                raise ValueError("No compatible AES candidates.")

            history.append((observation, group, len(fresh), len(survivors)))
            formatted_values = []

            for candidate in sorted(survivors)[:4]:
                formatted_values.append(bytes(candidate).hex())

            detail = f'd = InvSbox[C[p] XOR k] XOR InvSbox[F[p] XOR k]\nMatch one of 1020 MixColumns difference patterns.\nOutput positions: {positions(group)}\nSimulator: round 9 / row {row} / column {group} / mask {value:02X}\nCandidates from pair: {len(fresh)}\nIntersection: {before} -> {len(survivors)}\nFirst candidates: ' + ' | '.join(formatted_values) + '\nSolver receives ciphertexts and column group, not the key or mask.'
            steps.append(snapshot(10, f"Column {group} / observation {observation}", "One round-9 fault affects four output bytes. Intersect four-byte key tuples for this group.", faulty, detail, correct))

            if len(survivors) == 1:
                for position, byte in zip(positions(group), next(iter(survivors))):
                    last_key[position] = byte

                break
        else:
            steps.append(snapshot(10, "Ambiguous recovery", "Increase maximum observations per column. No master key is claimed.", correct))
            return dict(steps=steps, output=first_faulty.hex(), correct=correct.hex(), recovered_key=None, used=used, history=history, verified=False, model="AES round-9 Piret")

    recovered, schedule_steps = attack_steps.aes_schedule(last_key)

    steps.extend(schedule_steps)

    steps.extend(attack_steps.verification("aes", block, recovered, correct))

    if aes_trace(block, recovered)[0] != correct or recovered != key:
        raise RuntimeError("AES recovered-key verification failed.")

    steps.append(snapshot(10, "Recovered AES master key", "Reverse the AES-128 key expansion after all four K10 groups become unique.", correct, f"Recovered K10: {last_key.hex()}\nRecovered K0: {recovered.hex()}\nVerification: PASS\nUsed {used} faulty ciphertexts."))

    return dict(steps=steps, output=first_faulty.hex(), correct=correct.hex(), recovered_key=recovered.hex(), used=used, history=history, verified=True, model="AES round-9 Piret")


def sm4_master_lesson(block, key, start_byte, mask, maximum, giraud_mode=False, known_bit=False):
    """Show output-only full recovery; no reference subkeys are supplied."""

    correct, target_trace = console.piret_sm4.sm4_fault_encrypt(block, key)

    _, steps = sm4_trace(block, key)

    if giraud_mode:
        model = 'Giraud-inspired SM4 / full master-key recovery'
    else:
        model = 'SM4 controlled DFA / full master-key recovery'

    steps.append(snapshot(31, "Full recovery fault model", "Extend the PDF model to faults in rounds 31, 30, 29 and 28.", correct, "Recover the latest subkey first; undo only rounds with previously recovered keys. No reference subkeys."))

    def oracle(number, byte, value):
        if giraud_mode:
            target = giraud_sm4.sm4_fault_encrypt
        else:
            target = console.piret_sm4.sm4_fault_encrypt

        faulty, fault_trace = target(block, key, byte, value, number)

        steps.extend(attack_steps.sm4_fault_trace(target_trace, fault_trace, number, byte, value))

        return faulty

    # Keep SM4 candidate intersections indexed by both round and byte.
    candidate_history = {}

    # Translate solver observations into visual steps without modifying the solver state.
    def show(event):
        identity = (event["round"], event["byte"])

        if giraud_mode:
            element_values_10 = known_bit
        else:
            element_values_10 = None

        steps.extend(attack_steps.sm4_observation(event, candidate_history.get(identity), element_values_10))

        candidate_history[identity] = set(event["survivors"])

        all_match = True

        for byte_2 in range(4):
            if not len(candidate_history.get((event['round'], byte_2), set())) == 1:
                all_match = False
                break

        if all_match:
            byte_values = []

            for byte in range(4):
                byte_values.append(next(iter(candidate_history[event['round'], byte])))

            recovered_word = bytes(byte_values)
            formatted_values_2 = []

            for value_2 in recovered_word:
                formatted_values_2.append(f'{value_2:02X}')

            steps.append(snapshot(event['round'], f"Assemble rk{event['round']}", 'All four bytes are unique; concatenate in big-endian order.', bytes.fromhex(event['clean_view']), ' || '.join(formatted_values_2) + ' = ' + recovered_word.hex().upper()))

        formatted_values = []

        for value in event['survivors']:
            formatted_values.append(f'{value:02X}')

        detail = f"Round {event['round']}, byte {event['byte']}, observation {event['observation']}\nAlready recovered keys: {event['peeled_with']}\nOriginal correct: {event['correct']}\nOriginal faulty: {event['faulty']}\nL-inverse difference: {event['delta_b']:08X}\nCandidates: {event['before']} -> {event['remaining']}\nSurvivors: " + ' '.join(formatted_values)

        steps.append(snapshot(event['round'], f"rk{event['round']} / byte {event['byte']} / observation {event['observation']}", "Undo later rounds with recovered subkeys, then filter candidates from the restored difference.", bytes.fromhex(event['faulty_view']), detail, bytes.fromhex(event['clean_view'])))

    if giraud_mode:
        result = giraud_sm4.recover_sm4_master_key(correct, oracle, mask, maximum, known_bit, start_byte, show)
    else:
        masks_values = []

        for candidate_value in range(1, 256):
            if candidate_value != mask:
                masks_values.append(candidate_value)

        masks = [mask] + masks_values[:maximum - 1]

        result = console.piret_sm4.recover_sm4_master_key(correct, oracle, masks, start_byte, observer=show)

    complete, recovered = result['complete'], result['master_key']

    if complete:
        displayed, schedule_steps = attack_steps.sm4_schedule(result['round_keys'])

        if displayed != recovered:
            raise RuntimeError('Displayed SM4 schedule disagrees with recovery.')

        steps.extend(schedule_steps)

        steps.extend(attack_steps.verification("sm4", block, recovered, correct))

    # Compare with simulation ground truth only after output-based recovery has completed.
    if complete and (recovered != key or sm4.sm4_encrypt_block(block, recovered) != correct):
        raise RuntimeError("SM4 full master-key verification failed.")

    keys = {}

    for row_2, candidate_value_4 in result['round_keys'].items():
        keys[str(row_2)] = f'{candidate_value_4:08X}'

    detail = "DFA-recovered subkeys: " + str(keys)

    if complete:
        computed_value = f'\nMaster key: {recovered.hex()}\nVerification: PASS'
    else:
        computed_value = f"\nAmbiguous at round {result['blocked_round']}. Increase observations."

    detail += computed_value

    if complete:
        element_values_9 = 'Recovered SM4 master key'
    else:
        element_values_9 = 'Ambiguous recovery'

    steps.append(snapshot(28, element_values_9, 'All four final subkeys come from fault observations, not reference values. Reverse the schedule after uniqueness.', correct, detail))

    if result['history']:
        first_faulty = result['history'][0]['faulty']
    else:
        first_faulty = correct.hex()

    if recovered is None:
        result_value_3 = None
    else:
        result_value_3 = recovered.hex()

    result_values = []

    for row in range(31, 27, -1):
        for candidate_byte in range(4):
            result_values.append(result['candidate_counts'].get(f'{row}:{candidate_byte}', 256))

    return dict(steps=steps, output=first_faulty, correct=correct.hex(), recovered_key=result_value_3, recovered_subkey=keys.get('31'), recovered_round_keys=keys, used=result['used'], history=result['history'], remaining_candidates=result_values, verified=complete, model=model, known_bit=known_bit, fault=dict(row=start_byte, mask=mask, maximum=maximum))


def pdf_sm4_lesson(block, key, start_byte, mask, maximum):
    """Controlled-byte PDF model extended to four target rounds."""

    return sm4_master_lesson(block, key, start_byte, mask, maximum)


# Giraud target simulation and visual explanations belong to this GUI module.

def aes_giraud_encrypt(plaintext, key, byte=0, mask=None):
    """GUI adapter only; giraud_aes.py performs the external cipher intervention."""

    return giraud_aes.aes_fault_encrypt(plaintext, key, byte, mask)


def giraud_lesson(algorithm, plaintext, key, row=0, column=0, mask=1, maximum=8, known_bit=False):
    """Build the GUI's visual steps under the chapter-7 fault models.

    Coordinates choose which byte is demonstrated first; all target bytes are
    processed. A unique candidate is required before a recovered value is used.
    """

    if algorithm not in ('AES-128', 'SM4') or not 0 <= row < 4 or (not 0 <= column < 4):
        raise ValueError('Choose AES-128 or SM4, with row/column in 0..3.')

    aes.validate_block(plaintext)

    aes.validate_block(key, 'Key')

    masks = masks_for(mask, maximum)

    if algorithm == 'SM4':
        return sm4_master_lesson(plaintext, key, row, mask, maximum, True, known_bit)

    count = 16

    first = 4 * column + row

    correct, clean_trace = aes_giraud_encrypt(plaintext, key)

    if correct != console.piret_aes.aes_target_encrypt(plaintext, key):
        raise RuntimeError('AES simulator differs from aes.py.')

    if known_bit:
        element_values_8 = 'KNOWN'
    else:
        element_values_8 = 'UNKNOWN'

    steps = [snapshot(10, 'Giraud fault model', 'One bit before the last nonlinear layer. The bit is ' + element_values_8 + ' to the candidate solver.', correct, 'AES: no final MixColumns; one altered output byte.\nSM4 adaptation: invert L to isolate one S-box output difference.\nPDF chapter 7. Target location is not sufficient to identify the bit.\nThe simulator key and internal states are not solver inputs.')]

    recovered, remaining, history = (bytearray(count), [256] * count, [])

    used, first_faulty = (0, None)

    descriptions = {'Before fault': 'Clean final-round input before injection.', 'Injected bit': 'Flip exactly one bit before final SubBytes.', 'SubBytes': 'The S-box changes the difference nonlinearly, within the same byte.', 'ShiftRows': 'Move the changed byte to its final output position; no byte diffusion occurs.', 'Ciphertext': 'The final key XOR preserves the one-byte difference.'}

    computed_value_values = []

    for offset in range(count):
        computed_value_values.append((first + offset) % count)

    for target in computed_value_values:
        survivors = None

        for observation, actual_mask in enumerate(masks, 1):
            faulty, fault_trace = aes_giraud_encrypt(plaintext, key, target, actual_mask)

            if known_bit:
                element_values_7 = actual_mask
            else:
                element_values_7 = None

            position, fresh = giraud_aes.aes_candidates(correct, faulty, element_values_7)
            # Map the pre-SubBytes input location through final ShiftRows to the output key byte.
            input_column, input_row = divmod(target, 4)
            expected = 4 * ((input_column - input_row) % 4) + input_row

            if position != expected:
                raise RuntimeError('Final ShiftRows output mapping is inconsistent.')

            if known_bit:
                detail_2 = f'Require d(k) = {actual_mask:02X}.'
            else:
                detail_2 = 'Require Hamming weight of d(k) = 1; test all eight bit positions.'

            detail = f'Input byte {target}: row {input_row}, column {input_column}. Output position: {position}.\nSimulator bit mask: {actual_mask:02X}. Solver knows this mask: {known_bit}.\nd(k) = InvSbox[{correct[position]:02X} XOR k] XOR InvSbox[{faulty[position]:02X} XOR k]\n' + detail_2

            for name, state in fault_trace.items():
                steps.append(snapshot(10, f'Input byte {target} / {name}', descriptions[name], state, detail, clean_trace[name]))

            used += 1
            first_faulty = first_faulty or faulty

            if survivors is None:
                before = 256
            else:
                before = len(survivors)

            if known_bit:
                element_values_6 = actual_mask
            else:
                element_values_6 = None

            steps.extend(attack_steps.aes_giraud(correct, faulty, position, survivors, element_values_6))
            survivors = intersect_candidates(survivors, fresh)
            remaining[position] = len(survivors)
            history.append(dict(observation=observation, target=position, before=before, pair_candidates=len(fresh), remaining=len(survivors), simulator_mask=actual_mask))
            formatted_values = []

            for value_2 in sorted(survivors):
                formatted_values.append(f'{value_2:02X}')

            detail += f'\nKey-byte candidates in this pair: {len(fresh)}\nIntersection: {before} -> {len(survivors)}\nSurvivors: ' + ' '.join(formatted_values)
            steps.append(snapshot(10, f'Key byte {position} / observation {observation}', 'Intersect candidate byte values across independent single-bit observations.', faulty, detail, correct))

            if len(survivors) == 1:
                recovered[position] = next(iter(survivors))
                break

    all_match = True

    for value in remaining:
        if not value == 1:
            all_match = False
            break

    unique = all_match

    report = dict(steps=steps, output=first_faulty.hex(), correct=correct.hex(), recovered_key=None, recovered_subkey=None, used=used, history=history, remaining_candidates=remaining, verified=unique, model='Giraud AES / final SubBytes', known_bit=known_bit, fault=dict(row=row, column=column, mask=mask, maximum=maximum))

    if not unique:
        steps.append(snapshot(10, 'Ambiguous recovery', 'Additional independent observations are required. No unique key is claimed.', correct, f'Candidate counts by output key byte: {remaining}\nAt most eight distinct bit faults are available for a fixed state.'))

        return report

    master, schedule_steps = attack_steps.aes_schedule(recovered)

    steps.extend(schedule_steps)

    steps.extend(attack_steps.verification("aes", plaintext, master, correct))

    if master != key or console.piret_aes.aes_target_encrypt(plaintext, master) != correct:
        raise RuntimeError('Giraud AES recovered-key verification failed.')

    report.update(recovered_key=master.hex(), recovered_last_key=recovered.hex())

    detail = f'Recovered K10: {recovered.hex()}\nRecovered K0: {master.hex()}\nRe-encryption and target-key checks: PASS'

    explanation = 'All 16 K10 bytes are unique. Reverse the AES-128 key schedule to recover K0.'

    steps.append(snapshot(10, 'Verified recovery result', explanation, correct, detail + f'\nUsed {used} faulty outputs.'))

    return report


def log_report(report):
    """Mirror a completed GUI lesson to the terminal and the active session log."""

    terminal = console.LessonTerminal("always")

    terminal.section(f"GUI: {report['algorithm']} / {report['operation']}")

    print(f"Input: {report['input']}\nKey: {report['key']}")

    previous = report['input']

    # Log every computed timeline step, even if the user never selects it in the GUI.
    for index, event in enumerate(report['steps'], 1):
        print(f"GUI step {index}/{len(report['steps'])}; round {event['round']}")
        print(event['explanation'])
        print(f"Displayed state: {event['state']}")

        console.attack_steps.emit(terminal, [dict(event, reference=event['reference'] or previous)])

        previous = event['state']

    print(f"Output: {report['output']}")

    if report.get('recovered_key'):
        print(f"Recovered master key: {report['recovered_key']}")

    if report['verified']:
        element_values_5 = 'PASS'
    else:
        element_values_5 = 'AMBIGUOUS'

    print('Verification: ' + element_values_5)


class CryptoLab:
    def __init__(self, root):
        self.root, self.report, self.index, self.timer, self.busy = root, None, 0, None, False

        # Worker results cross this queue; only the Tk main thread may update widgets.
        self.messages = queue.Queue()

        root.title("Crypto Lab | AES · SM4 · Piret DFA")

        root.geometry("1280x900")

        root.minsize(1130, 780)

        root.configure(bg=BG)

        self.algorithm = tk.StringVar(value="AES-128")

        self.operation = tk.StringVar(value="Encrypt")

        self.key, self.value = tk.StringVar(value=AES_KEY), tk.StringVar(value=AES_INPUT)

        self.row, self.column = tk.IntVar(value=0), tk.IntVar(value=0)

        self.mask, self.maximum = tk.StringVar(value="01"), tk.IntVar(value=6)

        self.known_bit = tk.BooleanVar(value=False)

        self.status = tk.StringVar(value="Ready · choose an algorithm and load the example")

        self.speed = tk.IntVar(value=1000)

        style = ttk.Style(root)

        style.theme_use("clam")

        style.configure("TNotebook", background=BG, borderwidth=0)

        style.configure("TNotebook.Tab", background=CELL, foreground=TEXT, padding=(18, 10))

        style.map("TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", ACCENT)])

        self.build()

        # Reconfigure controls when a selector changes; this does not recompute an existing lesson.
        self.algorithm.trace_add("write", self.selection_changed)

        # Keep input hints and fault options consistent with the selected operation.
        self.operation.trace_add("write", self.selection_changed)

        def handle_event_2(event):
            if not isinstance(root.focus_get(), (tk.Entry, ttk.Combobox)):
                callback_result_2 = self.move(-1)
            else:
                callback_result_2 = None

            return callback_result_2

        root.bind('<Left>', handle_event_2)

        def handle_event(event):
            if not isinstance(root.focus_get(), (tk.Entry, ttk.Combobox)):
                callback_result = self.move(1)
            else:
                callback_result = None

            return callback_result

        root.bind('<Right>', handle_event)

        root.protocol("WM_DELETE_WINDOW", self.close)

        self.poll_id = root.after(100, self.poll)

        self.selection_changed()

    def label(self, parent, text, size=11, color=TEXT):
        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color, font=("Segoe UI", size), anchor="w")

    def button(self, parent, title, action, primary=False):
        if primary:
            result_value = ACCENT
        else:
            result_value = CELL

        if primary:
            result_value_2 = BG
        else:
            result_value_2 = TEXT

        return tk.Button(parent, text=title, command=action, bg=result_value, fg=result_value_2, relief='flat', padx=12, pady=8, font=('Segoe UI', 10), cursor='hand2')

    def build(self):
        # Build the header separately from the parameter sidebar and the lesson panels.
        header = tk.Frame(self.root, bg=BG, padx=22, pady=16)

        header.pack(fill="x")

        self.label(header, "CRYPTO LAB", 24, ACCENT).pack(side="left")

        self.label(header, "AES / SM4 / Piret · Learn one transformation at a time", 12, MUTED).pack(side="left", padx=24)

        body = tk.Frame(self.root, bg=BG)

        body.pack(fill="both", expand=True, padx=22)

        sidebar = tk.Frame(body, bg=PANEL, padx=16, pady=16, width=295)

        sidebar.pack(side="left", fill="y", padx=(0, 16))

        sidebar.pack_propagate(False)

        # Collect editable widgets so computation can disable them as a group.
        self.controls = []

        for title, variable, values in [("Algorithm", self.algorithm, ("AES-128", "SM4")), ("Lesson", self.operation, ("Encrypt", "Decrypt", "Fault analysis", "Giraud attack"))]:
            self.label(sidebar, title, color=MUTED).pack(anchor="w", pady=(0, 5))
            widget = ttk.Combobox(sidebar, textvariable=variable, values=values, state="readonly")
            widget.pack(fill="x", pady=(0, 14))
            self.controls.append(widget)

        for title, variable in [("128-bit key · hex", self.key), ("Input block · hex", self.value)]:
            self.label(sidebar, title, color=MUTED).pack(anchor="w")
            widget = tk.Entry(sidebar, textvariable=variable, bg=CELL, fg=TEXT, insertbackground=ACCENT, relief="flat", font=("Consolas", 10))
            widget.pack(fill="x", ipady=8, pady=(5, 14))
            self.controls.append(widget)

        self.hint = self.label(sidebar, "", 10, MUTED)

        self.hint.configure(wraplength=255, justify="left")

        self.hint.pack(fill="x", pady=(0, 10))

        fault_panel = tk.Frame(sidebar, bg=PANEL)

        fault_panel.pack(fill="x")

        self.fault_title = self.label(fault_panel, "", 10, ORANGE)

        self.fault_title.pack(anchor="w")

        row = tk.Frame(fault_panel, bg=PANEL)

        row.pack(fill="x", pady=8)

        # Keep references so these labels can track the selected attack's fault model.
        self.coordinate_labels = {}

        for index, (name, title, variable) in enumerate([("row", "Row / byte", self.row), ("column", "Start column", self.column)]):
            label = self.label(row, title, 10, MUTED)
            label.grid(row=0, column=index, sticky="w")
            self.coordinate_labels[name] = label
            widget = ttk.Combobox(row, textvariable=variable, values=(0, 1, 2, 3), width=8, state="readonly")
            widget.grid(row=1, column=index, padx=(0, 12), pady=5)
            self.controls.append(widget)

        self.fault_labels = {}

        for name, title, variable in [("mask", "First XOR mask · hex 01..FF", self.mask), ("maximum", "Maximum faulty observations · 1..20", self.maximum)]:
            label = self.label(fault_panel, title, 9, MUTED)
            label.pack(anchor="w")
            self.fault_labels[name] = label
            widget = tk.Entry(fault_panel, textvariable=variable, bg=CELL, fg=TEXT, insertbackground=ACCENT, relief="flat", font=("Consolas", 11))
            widget.pack(fill="x", ipady=5, pady=(3, 10))
            self.controls.append(widget)

        self.known_bit_control = tk.Checkbutton(fault_panel, text="Giraud: exact bit known to solver", variable=self.known_bit, bg=PANEL, fg=TEXT, selectcolor=CELL, activebackground=PANEL, activeforeground=TEXT, font=("Segoe UI", 9), anchor="w")

        self.known_bit_control.pack(fill="x", pady=(0, 5))

        self.controls.append(self.known_bit_control)

        self.example_button = self.button(sidebar, "Load standard example", self.load_example)

        self.example_button.pack(fill="x", pady=(12, 5))

        self.run_button = self.button(sidebar, "Build lesson", self.run, True)

        self.run_button.pack(fill="x", pady=5)

        self.export_button = self.button(sidebar, "Export lesson JSON", self.export)

        self.export_button.pack(fill="x", pady=5)

        self.export_button.configure(state="disabled")

        self.label(sidebar, "Offline simulation · no board needed", 9, MUTED).pack(anchor="w", pady=10)

        right = tk.Frame(body, bg=BG)

        right.pack(side="left", fill="both", expand=True)

        # Separate step exploration from the final result and reading guide.
        self.tabs = ttk.Notebook(right)

        self.tabs.pack(fill="both", expand=True)

        computed_value_values = []

        for unused_index in range(2):
            computed_value_values.append(tk.Frame(self.tabs, bg=PANEL, padx=16, pady=14))

        explorer, summary_tab = computed_value_values

        self.tabs.add(explorer, text="Step-by-step explorer")

        self.tabs.add(summary_tab, text="Results & reading guide")

        self.title = self.label(explorer, "Build a lesson to begin", 18, ACCENT)

        self.title.pack(anchor="w")

        self.explanation = self.label(explorer, "Choose AES or SM4, then Encrypt, Decrypt, Fault analysis or Giraud attack.", 11, MUTED)

        self.explanation.configure(wraplength=740, justify="left")

        self.explanation.pack(fill="x", pady=(10, 12))

        self.metrics = self.label(explorer, "", 10, ORANGE)

        self.metrics.pack(anchor="w")

        matrices = tk.Frame(explorer, bg=PANEL)

        matrices.pack(fill="x", pady=8)

        self.cells, self.matrix_titles = [], []

        for title in ("Current state", "Comparison state", "XOR difference"):
            frame = tk.Frame(matrices, bg=PANEL)
            frame.pack(side="left", fill="x", expand=True)
            heading = self.label(frame, title, 10)
            heading.pack(anchor="center", pady=4)
            self.matrix_titles.append(heading)
            grid = tk.Frame(frame, bg=PANEL)
            grid.pack()
            cells = []

            for row in range(4):
                row_cells = []

                for column in range(4):
                    cell = tk.Label(grid, text="--", bg=CELL, fg=TEXT, width=3, height=2, font=("Consolas", 13, "bold"))
                    cell.grid(row=row, column=column, padx=2, pady=2)
                    row_cells.append(cell)

                cells.append(row_cells)

            self.cells.append(cells)

        self.layout_label = self.label(explorer, "", 10, MUTED)

        self.layout_label.pack(anchor="w", pady=6)

        # Keep long candidate tables scrollable instead of truncating the numerical explanation.
        details_panel = tk.Frame(explorer, bg=BG)

        details_panel.pack(fill="both", expand=True, pady=8)

        self.details = tk.Text(details_panel, height=8, bg=BG, fg=TEXT, relief="flat", font=("Consolas", 10), wrap="word", padx=10, pady=10)

        scrollbar = ttk.Scrollbar(details_panel, orient="vertical", command=self.details.yview)

        self.details.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")

        self.details.pack(side="left", fill="both", expand=True)

        navigation = tk.Frame(explorer, bg=PANEL)

        navigation.pack(fill="x", pady=6)

        self.previous = self.button(navigation, "← Previous", lambda: self.move(-1))

        self.previous.pack(side="left")

        self.play_button = self.button(navigation, "▶ Play", self.play)

        self.play_button.pack(side="left", padx=8)

        self.next_button = self.button(navigation, "Next →", lambda: self.move(1))

        self.next_button.pack(side="left")

        self.progress = self.label(navigation, "0 / 0", 10, MUTED)

        self.progress.pack(side="right")

        seek = tk.Frame(explorer, bg=PANEL)

        seek.pack(fill="x")

        # The slider selects an existing timeline index; it never injects another fault.
        self.seek = tk.Scale(seek, from_=0, to=1, orient="horizontal", command=self.seek_to, bg=PANEL, fg=TEXT, highlightthickness=0, showvalue=False)

        self.seek.pack(side="left", fill="x", expand=True)

        ttk.Combobox(seek, textvariable=self.speed, values=(300, 600, 1000, 1800), width=6, state="readonly").pack(side="right")

        self.label(seek, "ms / step", 9, MUTED).pack(side="right", padx=5)

        self.step_list = ttk.Combobox(explorer, state="readonly")

        self.step_list.pack(fill="x", pady=(6, 0))

        self.step_list.bind("<<ComboboxSelected>>", lambda event: self.select(self.step_list.current()))

        scrollbar = ttk.Scrollbar(summary_tab)

        scrollbar.pack(side="right", fill="y")

        self.summary = tk.Text(summary_tab, bg=BG, fg=TEXT, font=("Consolas", 11), wrap="word", relief="flat", padx=14, pady=14, yscrollcommand=scrollbar.set)

        self.summary.pack(fill="both", expand=True)

        scrollbar.configure(command=self.summary.yview)

        tk.Label(self.root, textvariable=self.status, bg=BG, fg=MUTED, anchor="w", padx=22, pady=12).pack(fill="x")

        self.navigation()

    def selection_changed(self, *_):
        # Ignore new requests while a worker is computing, preventing overlapping lessons.
        if self.busy:
            return

        is_giraud = self.operation.get() == "Giraud attack"

        attack = self.operation.get() in ("Fault analysis", "Giraud attack")

        is_sm4 = self.algorithm.get() == "SM4"

        self.controls[1].configure(values=("Encrypt", "Decrypt", "Fault analysis", "Giraud attack"))

        if is_giraud:
            if is_sm4:
                computed_value_4 = 'SM4 single-bit / round 31'
            else:
                computed_value_4 = 'AES Giraud / final SubBytes'
        else:
            if is_sm4:
                computed_value_4 = 'SM4 DFA / round 31 / S-box input'
            else:
                computed_value_4 = 'AES Piret / round 9 / MixColumns'

        self.fault_title.configure(text=computed_value_4)

        if is_giraud:
            if is_sm4:
                message = 'Single-bit SM4: recover rk31 through rk28, then the full master key.'
            else:
                message = 'Single bit before final SubBytes. Filter K10 bytes with HW(delta)=1. Unknown bit by default.'
        else:
            if is_sm4:
                message = 'Known XOR faults in rounds 31 through 28 recover the full SM4 master key.'
            else:
                message = 'Piret recovers all four AES key groups. Row selects the fault row; all columns are processed.'

        if attack:
            computed_value_3 = message
        else:
            computed_value_3 = 'One raw 16-byte block. Decrypt expects ciphertext; no text padding is applied.'

        self.hint.configure(text=computed_value_3)

        for widget in self.controls[4:]:
            if attack and isinstance(widget, ttk.Combobox):
                computed_value_2 = 'readonly'
            else:
                if attack:
                    computed_value_2 = 'normal'
                else:
                    computed_value_2 = 'disabled'

            widget.configure(state=computed_value_2)

        if is_sm4:
            self.controls[5].configure(state="disabled")

        if is_giraud:
            computed_value = 'normal'
        else:
            computed_value = 'disabled'

        self.known_bit_control.configure(state=computed_value)

        # Retune the fault-parameter labels to the selected attack's model.
        if is_giraud:
            self.fault_labels["mask"].configure(text="Single-bit mask · 01 02 04 08 10 20 40 80")
            self.fault_labels["maximum"].configure(text="Max observations · 1..8 (eight bit positions)")

            if is_sm4:
                self.coordinate_labels["row"].configure(text="Start byte · 0..3")
                self.coordinate_labels["column"].configure(text="Column (AES only)")
            else:
                self.coordinate_labels["row"].configure(text="Start byte · 0..3")
                self.coordinate_labels["column"].configure(text="Start column · 0..3")

            # Giraud flips one bit: snap an incompatible Piret mask back to a valid single bit.
            try:
                current_mask = int(self.mask.get(), 16)
            except ValueError:
                current_mask = None

            if current_mask not in SINGLE_BITS:
                self.mask.set("01")

            # Only eight distinct single-bit faults exist per byte.
            try:
                if self.maximum.get() > 8:
                    self.maximum.set(8)
            except tk.TclError:
                self.maximum.set(8)
        else:
            self.fault_labels["mask"].configure(text="First XOR mask · hex 01..FF")
            self.fault_labels["maximum"].configure(text="Maximum faulty observations · 1..20")
            self.coordinate_labels["row"].configure(text="Row / byte")

            if is_sm4:
                self.coordinate_labels["column"].configure(text="Column (AES only)")
            else:
                self.coordinate_labels["column"].configure(text="Start column")

        if self.report:
            self.status.set("Settings changed · Build lesson to apply. Timeline retains its original inputs.")

    def load_example(self):
        # Ignore new requests while a worker is computing, preventing overlapping lessons.
        if self.busy:
            return

        is_sm4 = self.algorithm.get() == "SM4"

        if is_sm4:
            element_values_4 = SM4_VECTOR
        else:
            element_values_4 = AES_KEY

        self.key.set(element_values_4)

        if self.operation.get() == 'Decrypt':
            if is_sm4:
                element_values_3 = '681edf34d206965e86b3e94f536e4246'
            else:
                element_values_3 = '69c4e0d86a7b0430d8cdb78070b4c55a'
        else:
            if is_sm4:
                element_values_3 = SM4_VECTOR
            else:
                element_values_3 = AES_INPUT

        self.value.set(element_values_3)

        self.status.set("Standard vector loaded · press Build lesson")

    def set_text(self, widget, text):
        # Temporarily unlock the read-only text area to replace its contents.
        widget.configure(state="normal")

        # Replace the previous explanation instead of accumulating unrelated steps.
        widget.delete("1.0", "end")

        widget.insert("1.0", text)

        widget.configure(state="disabled")

    def run(self):
        # Ignore new requests while a worker is computing, preventing overlapping lessons.
        if self.busy:
            return

        self.stop()

        try:
            key, block = parse_block(self.key.get()), parse_block(self.value.get())
            # Fault coordinates and masks are required only for attack lessons.
            attack = self.operation.get() in ("Fault analysis", "Giraud attack")
            row, column, mask, maximum = 0, 0, 1, 6

            if attack:
                row, column, mask, maximum = self.row.get(), self.column.get(), int(self.mask.get(), 16), self.maximum.get()

                if not (0 <= row < 4 and 0 <= column < 4):
                    raise ValueError("Row and column must be 0..3.")

                if self.operation.get() == "Giraud attack":
                    # Giraud injects a single bit: validate the mask and the 1..8 bound together.
                    masks_for(mask, maximum)
                elif not (1 <= mask <= 255 and 1 <= maximum <= 20):
                    raise ValueError("Piret settings: mask 01..FF, observations 1..20.")
        except (ValueError, tk.TclError) as error:
            messagebox.showerror("Invalid input", str(error), parent=self.root)
            return

        algorithm, operation = self.algorithm.get(), self.operation.get()

        # Disable edits until the queued result is delivered to the Tk main thread.
        self.busy = True

        self.navigation()

        for widget in self.controls:
            widget.configure(state="disabled")

        self.run_button.configure(state="disabled", text="Computing…")

        self.example_button.configure(state="disabled")

        self.status.set("Building the lesson and checking its result…")

        # Run expensive candidate filtering off the Tk event loop so the interface stays responsive.
        threading.Thread(target=self.compute, args=(algorithm, operation, key, block, row, column, mask, maximum, self.known_bit.get()), daemon=True).start()

    def compute(self, algorithm, operation, key, block, row, column, mask, maximum, known_bit=False):
        try:
            # Choose a lesson builder; the GUI presents attack logic rather than reimplementing it.
            if operation == "Giraud attack":
                report = giraud_lesson(algorithm, block, key, row, column, mask, maximum, known_bit)
            elif operation == "Fault analysis":
                if algorithm == 'SM4':
                    report = pdf_sm4_lesson(block, key, row, mask, maximum)
                else:
                    report = pdf_aes_lesson(block, key, row, column, mask, maximum)

                report.update(fault=dict(row=row, column=column, mask=mask, maximum=maximum))
            else:
                if algorithm == 'SM4':
                    function = sm4_trace
                else:
                    function = aes_trace

                output, steps = function(block, key, operation == "Decrypt")
                recovered = function(output, key, operation != "Decrypt")[0]

                if recovered != block:
                    raise RuntimeError("Inverse verification failed.")

                report = dict(steps=steps, output=output.hex(), recovered=recovered.hex(), verified=True)

            # Attach the exact inputs used by this computation, independent of later widget changes.
            report.update(algorithm=algorithm, operation=operation, key=key.hex(), input=block.hex())
            # Mirror the complete lesson to the terminal and session log before notifying the GUI.
            log_report(report)
            self.messages.put((report, None))
        except Exception as error:
            traceback.print_exc()
            self.messages.put((None, str(error)))

    def poll(self):
        try:
            # Poll without blocking Tk; a missing result simply means the worker is still running.
            report, error = self.messages.get_nowait()
        # Keep polling on the scheduled timer without freezing the interface.
        except queue.Empty:
            pass
        else:
            self.busy = False

            for widget in self.controls:
                if isinstance(widget, ttk.Combobox):
                    computed_value = 'readonly'
                else:
                    computed_value = 'normal'

                widget.configure(state=computed_value)

            self.run_button.configure(state="normal", text="Build lesson")
            self.example_button.configure(state="normal")
            self.selection_changed()

            if error:
                self.status.set("Error · " + error)
                messagebox.showerror("Lesson error", error, parent=self.root)
            else:
                self.report, self.index = report, 0
                # Rebuild navigation bounds from the completed lesson, not the previous one.
                self.seek.configure(to=len(report["steps"]) - 1)
                computed_value_values = []

                for index, s in enumerate(report['steps']):
                    computed_value_values.append(f"{index + 1}. R{s['round']:02d} · {s['title']}")

                self.step_list.configure(values=computed_value_values)
                self.render()
                self.fill_summary()
                self.export_button.configure(state="normal")

                if report['verified']:
                    element_values_2 = 'verification PASS'
                else:
                    element_values_2 = 'key recovery ambiguous; increase observations'

                self.status.set('Lesson ready · ' + element_values_2)
                self.tabs.select(0)

            self.navigation()

        self.poll_id = self.root.after(100, self.poll)

    def render(self):
        if not self.report:
            return

        step = self.report["steps"][self.index]

        if self.index:
            previous = self.report['steps'][self.index - 1]['state']
        else:
            previous = step['state']

        # Fault lessons compare against the clean execution; ordinary traces compare against the previous step.
        reference = step["reference"] or previous

        state, comparison = bytes.fromhex(step["state"]), bytes.fromhex(reference)

        # Compute byte differences once for both red highlighting and changed-bit statistics.
        byte_values = []

        for input_value, byte_3 in zip(state, comparison):
            byte_values.append(input_value ^ byte_3)

        delta = bytes(byte_values)

        sm4_layout = self.report["algorithm"] == "SM4"

        self.title.configure(text=f"Round {step['round']:02d} · {step['title']}")

        self.explanation.configure(text=step["explanation"])

        if step['reference']:
            computed_value_4 = 'Correct state'
        else:
            computed_value_4 = 'Previous state'

        self.matrix_titles[1].configure(text=computed_value_4)

        if sm4_layout:
            computed_value_3 = 'SM4: each row is one word, bytes MSB → LSB'
        else:
            computed_value_3 = 'AES: row/column matrix; byte index = 4 × column + row'

        self.layout_label.configure(text=computed_value_3)

        element_values = []

        for byte in delta:
            element_values.append(bool(byte))

        element_values_2 = []

        for byte_2 in delta:
            element_values_2.append(bin(byte_2).count('1'))

        self.metrics.configure(text=f'Changed: {sum(element_values)} / 16 bytes · {sum(element_values_2)} / 128 bits')

        for panel, data in enumerate((state, comparison, delta)):
            for row in range(4):
                for column in range(4):
                    if sm4_layout:
                        position = 4 * row + column
                    else:
                        position = 4 * column + row

                    # Mark only nonzero byte differences in red; the reference panel stays neutral.
                    changed = bool(delta[position]) and panel != 1

                    if changed:
                        computed_value = '#482121'
                    else:
                        computed_value = CELL

                    if changed:
                        computed_value_2 = RED
                    else:
                        computed_value_2 = TEXT

                    self.cells[panel][row][column].configure(text=f'{data[position]:02X}', bg=computed_value, fg=computed_value_2)

        self.set_text(self.details, step["detail"] or "Follow the highlighted bytes. The middle panel provides the comparison state; XOR shows which bits differ.")

        self.progress.configure(text=f"{self.index+1} / {len(self.report['steps'])}")

        self.seek.set(self.index)

        self.step_list.current(self.index)

        self.navigation()

    def navigation(self):
        # Navigation is valid only after a report exists and no replacement is being computed.
        ready = bool(self.report) and not self.busy

        if ready and self.index > 0:
            computed_value_9 = 'normal'
        else:
            computed_value_9 = 'disabled'

        self.previous.configure(state=computed_value_9)

        if ready and self.index < len(self.report['steps']) - 1:
            computed_value_8 = 'normal'
        else:
            computed_value_8 = 'disabled'

        self.next_button.configure(state=computed_value_8)

        if ready:
            computed_value_7 = 'normal'
        else:
            computed_value_7 = 'disabled'

        self.play_button.configure(state=computed_value_7)

        if ready:
            computed_value_6 = 'readonly'
        else:
            computed_value_6 = 'disabled'

        self.step_list.configure(state=computed_value_6)

        if ready:
            computed_value = 'normal'
        else:
            computed_value = 'disabled'

        self.seek.configure(state=computed_value)

    def select(self, index):
        if self.report and not self.busy:
            self.stop()
            self.index = index
            self.render()

    def seek_to(self, value):
        index = int(float(value))

        if self.report and index != self.index:
            self.select(index)

    def move(self, direction):
        if self.report:
            # Clamp previous/next navigation to the first and last valid timeline indices.
            self.select(max(0, min(len(self.report["steps"]) - 1, self.index + direction)))

    def play(self):
        if self.timer is not None:
            self.stop()
            return

        if not self.report or self.busy:
            return

        if self.index == len(self.report["steps"]) - 1:
            self.index = 0

        self.play_button.configure(text="Ⅱ Pause")

        self.render()

        # Schedule playback without sleep; Tk remains available for pause and navigation.
        self.timer = self.root.after(self.speed.get(), self.tick)

    def tick(self):
        self.timer = None

        self.index += 1

        self.render()

        if self.index < len(self.report["steps"]) - 1:
            # Schedule playback without sleep; Tk remains available for pause and navigation.
            self.timer = self.root.after(self.speed.get(), self.tick)
        else:
            self.stop()

    def stop(self):
        if self.timer is not None:
            # Cancel the outstanding timer to prevent an extra step after pausing.
            self.root.after_cancel(self.timer)
            self.timer = None

        self.play_button.configure(text="▶ Play")

    def fill_summary(self):
        report = self.report

        lines = [report["algorithm"] + " / " + report["operation"], "", "Input:  " + report["input"], "Key:    " + report["key"], "Output: " + report["output"], ""]

        if report["operation"] in ("Fault analysis", "Giraud attack"):
            lines.extend(["Model: " + report["model"], "Correct ciphertext: " + report["correct"], f"Faulty observations consumed: {report['used']}", ""])

            if report["algorithm"] == "SM4":
                lines.extend(["DFA-recovered subkeys: " + str(report.get("recovered_round_keys")), "DFA-recovered master key: " + str(report.get("recovered_key")), "All four final subkeys came from observations, not references."])
            else:
                if report['operation'] == 'Giraud attack':
                    element_values = 'Single-bit faults before final SubBytes filter all 16 K10 bytes.'
                else:
                    element_values = 'Round-9 faults affect one key quartet at a time. All four groups are processed.'

                lines.extend(['DFA-recovered master key: ' + str(report['recovered_key']), element_values])

            if report["operation"] == "Giraud attack":
                lines.extend(["Exact bit known to solver: " + str(report["known_bit"]), "Remaining candidates per key byte: " + str(report["remaining_candidates"]), "SM4 is an adaptation of Giraud's filtering idea, not the unchanged AES attack."])

            lines.extend(["", "Red highlights show all fault-modified bytes and XOR differences.", "No unique key is claimed when candidates remain ambiguous."])

        else:
            lines.extend(["Inverse verification: PASS", "Recovered input: " + report["recovered"], "", "AES: initial key XOR, 9 full rounds, final round without MixColumns.", "SM4: 32 rounds, four 32-bit words, final word reversal.", "SM4 decryption reverses the round-key order.", "", "Select a step from the dropdown or drag the slider.", "For SM4, intermediate scalar calculations appear below the state."])

        lines.extend(["", "Offline software simulation on one raw block.", "JSON export includes the teaching key and internal states."])

        self.set_text(self.summary, "\n".join(lines))

    def export(self):
        if not self.report:
            return

        # Ask for a JSON destination only when the user explicitly exports the computed report.
        filename = filedialog.asksaveasfilename(parent=self.root, title="Export lesson", defaultextension=".json", filetypes=[("JSON lesson", "*.json")], initialfile="crypto-lab-lesson.json")

        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as output:
                    # Export the already computed lesson, including intermediate steps and recovery history.
                    json.dump(self.report, output, indent=2)

                self.status.set("Lesson exported · " + filename)
            except OSError as error:
                messagebox.showerror("Export error", str(error), parent=self.root)

    def close(self):
        self.stop()

        self.root.after_cancel(self.poll_id)

        self.root.destroy()


def main():
    """Keep one overwritten log per GUI session, including every built lesson."""

    window = tk.Tk()

    # Route exceptions from Tk callbacks to stderr so the session log captures them.
    window.report_callback_exception = traceback.print_exception

    CryptoLab(window)

    window.mainloop()


if __name__ == "__main__":
    from terminal_log import run_with_log

    raise SystemExit(run_with_log(main, "gui"))

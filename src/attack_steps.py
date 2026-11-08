"""Shared numerical attack lessons for the terminal and GUI; no secret keys enter filtering."""
from itertools import product
import struct
import aes
import sm4
import piret_aes
import piret_sm4


def step(number, title, lines, correct, faulty=None):
    """Use the GUI timeline format without importing Tkinter."""
    return dict(round=number, title=title, explanation="Follow the numerical equations below; all tested values are shown.", detail="\n".join(lines), state=bytes(correct if faulty is None else faulty).hex(), reference=bytes(correct).hex())


def values(items):
    return " ".join(f"{value:02X}" for value in sorted(items)) or "EMPTY"


def tuples(items):
    return "\n".join(bytes(item).hex().upper() for item in sorted(items)) or "EMPTY"


def aes_piret(correct, faulty, column, previous=None):
    """Enumerate all 1024 byte guesses, 1020 fault patterns and candidate tuples."""
    positions = piret_aes.output_positions(column)
    yield step(10, f"Group {column}: ciphertexts and ShiftRows mapping", [f"C = {correct.hex().upper()}", f"F = {faulty.hex().upper()}", f"C XOR F = {bytes(a ^ b for a, b in zip(correct, faulty)).hex().upper()}", f"Pre-ShiftRows rows 0..3 map to output positions {positions}.", "The solver receives neither the fault mask nor the target key."], correct, faulty)
    # Rebuild the public equation tables for teaching; do not consult the target secret.
    tables = []
    for row, position in enumerate(positions):
        table = [[] for _ in range(256)]
        lines = [f"Row {row}; ciphertext/key position {position}. Test every k=00..FF."]
        for guess in range(256):
            left = piret_aes.INV_SBOX[correct[position] ^ guess]
            right = piret_aes.INV_SBOX[faulty[position] ^ guess]
            delta = left ^ right
            # Group guesses by their predicted difference so each MixColumns pattern can look them up.
            table[delta].append(guess)
            lines.append(f"k={guess:02X}: InvS[{correct[position] ^ guess:02X}] XOR InvS[{faulty[position] ^ guess:02X}] = {left:02X} XOR {right:02X} = {delta:02X}")
        tables.append(table)
        yield step(10, f"Group {column}: all guesses for row {row}", lines, correct, faulty)
    fresh = set()
    for fault_row in range(4):
        lines = [f"Unknown error row = {fault_row}. Test every nonzero e=01..FF.", "All four equations must share the SAME row and error; independent byte sets are insufficient."]
        for error in range(1, 256):
            pattern = [piret_aes.gf_multiply(piret_aes.MIX_MATRIX[row][fault_row], error) for row in range(4)]
            choices = [tables[row][pattern[row]] for row in range(4)]
            # A pattern contributes the Cartesian product of its four compatible byte lists.
            count = 1
            for choice in choices:
                count *= len(choice)
            lines.append(f"e={error:02X}; matrix coefficients={[piret_aes.MIX_MATRIX[row][fault_row] for row in range(4)]}; d=" + " ".join(f"{value:02X}" for value in pattern) + "; byte choices=" + " / ".join(values(choice) for choice in choices) + f"; tuples={count} / " + ("ACCEPT" if count else "REJECT"))
            # Collect every matching quartet; a set merges duplicates across equivalent patterns.
            fresh.update(product(*choices))
        yield step(10, f"Group {column}: all patterns for fault row {fault_row}", lines, correct, faulty)
    # The display uses exactly the same set intersection as the attack solver.
    survivors = fresh if previous is None else previous & fresh
    lines = [f"All {len(fresh)} tuples compatible with this pair:", tuples(fresh), "Previous intersection: " + ("UNCONSTRAINED" if previous is None else tuples(previous)), "Removed previous tuples:", tuples(set() if previous is None else previous - fresh), f"Intersection: {len(survivors)} tuples", tuples(survivors)]
    if len(survivors) == 1:
        lines += [f"RECOVERED K10[{position}] = {value:02X}" for position, value in zip(positions, next(iter(survivors)))]
    yield step(10, f"Group {column}: complete tuple intersection", lines, correct, faulty)


def aes_giraud(correct, faulty, position, previous=None, known_mask=None):
    """Show both accepted and rejected key guesses, followed by exact intersection."""
    # Use one known error or all eight single-bit errors; never infer the secret simulator bit.
    allowed = (known_mask,) if known_mask is not None else (1, 2, 4, 8, 16, 32, 64, 128)
    lines = [f"Output/K10 byte {position}; allowed input errors: {values(allowed)}", "Unknown-bit mode tests all eight single-bit errors; the simulator mask is not an input."]
    fresh = set()
    for guess in range(256):
        left = piret_aes.INV_SBOX[correct[position] ^ guess]
        right = piret_aes.INV_SBOX[faulty[position] ^ guess]
        delta = left ^ right
        accepted = delta in allowed
        if accepted:
            fresh.add(guess)
        lines.append(f"k={guess:02X}: InvS[{correct[position] ^ guess:02X}] XOR InvS[{faulty[position] ^ guess:02X}] = {left:02X} XOR {right:02X} = {delta:02X}; HW={delta.bit_count()} / " + ("ACCEPT" if accepted else "REJECT"))
    yield step(10, f"Giraud byte {position}: all 256 key guesses", lines, correct, faulty)
    # The display uses exactly the same set intersection as the attack solver.
    survivors = fresh if previous is None else previous & fresh
    lines = ["Fresh: " + values(fresh), "Previous: " + ("00..FF" if previous is None else values(previous)), "Removed: " + values((set(range(256)) if previous is None else previous) - fresh), "Intersection: " + values(survivors)]
    if len(survivors) == 1:
        lines.append(f"RECOVERED K10[{position}] = {next(iter(survivors)):02X}")
    yield step(10, f"Giraud byte {position}: intersection", lines, correct, faulty)


def sm4_observation(event, previous=None, known_bit=None):
    """Explain every peeling operation, inverse-L contribution and candidate test."""
    number, byte = event['round'], event['byte']
    correct, faulty = bytes.fromhex(event['correct']), bytes.fromhex(event['faulty'])
    # Decode only keys already recovered at this point in the attack history.
    keys = {int(r): int(value, 16) for r, value in event['peeled_with'].items()}
    for title, ciphertext in (("Correct", correct), ("Faulty", faulty)):
        # Undo ciphertext reversal before evaluating the reverse round recurrence.
        words = list(struct.unpack('>4I', ciphertext))[::-1]
        lines = [f"Ciphertext = {ciphertext.hex().upper()}", "Undo ciphertext word reversal: " + " ".join(f"{word:08X}" for word in words)]
        # Peel only rounds later than the target; each uses an already recovered subkey.
        for r in range(31, number, -1):
            value = words[0] ^ words[1] ^ words[2] ^ keys[r]
            substituted = sm4.sbox(value)
            diffused = sm4.linear(substituted)
            restored = words[3] ^ diffused
            lines += [f"Undo round {r}, using recovered rk{r}={keys[r]:08X}", f"A = {words[0]:08X} XOR {words[1]:08X} XOR {words[2]:08X} XOR {keys[r]:08X} = {value:08X}", f"tau(A)={substituted:08X}; L(tau(A))={diffused:08X}", f"Old word = {words[3]:08X} XOR {diffused:08X} = {restored:08X}"]
            words = [restored, words[0], words[1], words[2]]
            lines.append("Restored chronological window: " + " ".join(f"word={word:08X}" for word in words))
        if number == 31:
            lines.append("No later round needs to be undone.")
        yield step(number, f"rk{number} byte {byte}: {title} round peeling", lines, correct, faulty)
    clean, fault = bytes.fromhex(event['clean_view']), bytes.fromhex(event['faulty_view'])
    c, f = struct.unpack('>4I', clean), struct.unpack('>4I', fault)
    delta_x = c[0] ^ f[0]
    lines = [f"DeltaX = {c[0]:08X} XOR {f[0]:08X} = {delta_x:08X}", "L is linear over GF(2). Apply inverse L to each set bit, then XOR contributions."]
    # Start the inverse-L result at zero and XOR each active input bit contribution.
    accumulated = 0
    for bit in range(32):
        basis = piret_sm4.inverse_linear(1 << bit)
        # An unset input bit contributes nothing; a set bit contributes its inverse basis image.
        contribution = basis if delta_x & (1 << bit) else 0
        accumulated ^= contribution
        lines.append(f"bit {bit:02d}: input={(delta_x >> bit) & 1}; inverse basis={basis:08X}; contribution={contribution:08X}; running XOR={accumulated:08X}")
    if accumulated != event['delta_b'] or sm4.linear(accumulated) != delta_x:
        raise RuntimeError("Inverse-L lesson does not match the attack observation.")
    shift = 24 - byte * 8
    delta = (accumulated >> shift) & 255
    q = ((c[1] ^ c[2] ^ c[3]) >> shift) & 255
    lines += [f"DeltaB = {accumulated:08X}; L(DeltaB) = {sm4.linear(accumulated):08X} / CHECK PASS", f"Select big-endian byte {byte}: delta={delta:02X}", f"q = byte {byte} of ({c[1]:08X} XOR {c[2]:08X} XOR {c[3]:08X}) = {q:02X}"]
    yield step(number, f"rk{number} byte {byte}: inverse linear transform", lines, clean, fault)
    allowed = (1, 2, 4, 8, 16, 32, 64, 128) if known_bit is False else (event['mask'],)
    fresh = set()
    lines = [f"Allowed errors = {values(allowed)}", "For every a=00..FF test S(a) XOR S(a XOR e) = delta. Then key byte = a XOR q."]
    for value in range(256):
        # Print every permitted error for this unknown input byte, including rejected tests.
        tests = [(error, sm4.SBOX[value] ^ sm4.SBOX[value ^ error]) for error in allowed]
        accepted = any(result == delta for _, result in tests)
        if accepted:
            # Convert the compatible S-box input a to a round-key byte using public q.
            fresh.add(value ^ q)
        calculations = "; ".join(f"e={error:02X}: {sm4.SBOX[value]:02X} XOR S[{value ^ error:02X}]={sm4.SBOX[value]:02X} XOR {sm4.SBOX[value ^ error]:02X}={result:02X}" for error, result in tests)
        lines.append(f"a={value:02X}; {calculations}; expected={delta:02X}; key={value ^ q:02X} / " + ("ACCEPT" if accepted else "REJECT"))
    yield step(number, f"rk{number} byte {byte}: all 256 S-box inputs", lines, clean, fault)
    # The display uses exactly the same set intersection as the attack solver.
    survivors = fresh if previous is None else previous & fresh
    if sorted(survivors) != event['survivors']:
        raise RuntimeError("Displayed SM4 candidate intersection disagrees with the solver.")
    lines = ["Fresh key bytes: " + values(fresh), "Previous: " + ("00..FF" if previous is None else values(previous)), "Removed: " + values((set(range(256)) if previous is None else previous) - fresh), "Intersection: " + values(survivors)]
    if len(survivors) == 1:
        lines.append(f"UNIQUE rk{number}[{byte}] = {next(iter(survivors)):02X}")
    yield step(number, f"rk{number} byte {byte}: complete intersection", lines, clean, fault)


def aes_schedule(last_key):
    """Reverse all 40 AES words, including each schedule-core byte operation."""
    words = [None] * 40 + [bytes(last_key[i:i+4]) for i in range(0, 16, 4)]
    events = [step(10, "Assemble K10", [f"K10[{i}]={value:02X}" for i, value in enumerate(last_key)] + [f"K10 = {bytes(last_key).hex().upper()}"], last_key)]
    def record(index, current, transformed, previous):
        source = words[index-1]
        lines = [f"w[{index}]={current.hex().upper()}; w[{index-1}]={source.hex().upper()}"]
        # Only every fourth AES schedule word uses RotWord, SubWord and Rcon.
        if index % 4 == 0:
            rotated = source[1:] + source[:1]
            lines.append(f"RotWord: {source.hex().upper()} -> {rotated.hex().upper()}")
            lines += [f"SubWord byte {i}: S[{value:02X}]={aes.SBOX[value]:02X}" for i, value in enumerate(rotated)]
            lines.append(f"Rcon[{index//4}]={aes.RCON[index//4]:02X}; first byte {aes.SBOX[rotated[0]]:02X} XOR Rcon = {transformed[0]:02X}")
        else:
            lines.append("No schedule core: T is the identity.")
        lines += [f"w[{index-4}][{i}] = {a:02X} XOR {b:02X} = {a ^ b:02X}" for i, (a, b) in enumerate(zip(current, transformed))]
        words[index-4] = previous
        lines.append(f"w[{index-4}] = w[{index}] XOR T(w[{index-1}]) = {current.hex().upper()} XOR {transformed.hex().upper()} = {previous.hex().upper()}")
        if (index-4) % 4 == 0:
            lines.append(f"DERIVED K{(index-4)//4} = {b''.join(words[index-4:index]).hex().upper()}")
        events.append(step((index-4)//4, f"Reverse AES schedule: w[{index-4}]", lines, last_key))
    master = piret_aes.reverse_key_schedule(last_key, record)
    events.append(step(0, "Assemble AES master key", ["K0 = w[0] || w[1] || w[2] || w[3]", master.hex().upper()], master))
    return master, events


def sm4_schedule(keys):
    """Reverse every SM4 schedule word, substitute each byte and remove FK."""
    words = [None] * 32 + [keys[r] for r in range(28, 32)]
    state = struct.pack('>4I', *words[32:])
    events = [step(31, "Assemble SM4 recovered round keys", [f"K[{r+4}] = rk{r} = {keys[r]:08X}" for r in range(28, 32)], state)]
    def record(index, recovered):
        value = words[index+1] ^ words[index+2] ^ words[index+3] ^ sm4.CK[index]
        substituted = sm4.sbox(value)
        # Keep rotations within 32 bits because Python integers have arbitrary precision.
        r13 = ((substituted << 13) | (substituted >> 19)) & 0xffffffff
        r23 = ((substituted << 23) | (substituted >> 9)) & 0xffffffff
        transformed = substituted ^ r13 ^ r23
        lines = [f"U = {words[index+1]:08X} XOR {words[index+2]:08X} XOR {words[index+3]:08X} XOR CK[{index}]({sm4.CK[index]:08X}) = {value:08X}"]
        lines += [f"tau byte {i}: S[{byte:02X}]={sm4.SBOX[byte]:02X}" for i, byte in enumerate(value.to_bytes(4, 'big'))]
        lines += [f"B={substituted:08X}; rol13={r13:08X}; rol23={r23:08X}", f"L'(B) = {substituted:08X} XOR {r13:08X} XOR {r23:08X} = {transformed:08X}", f"K[{index}] = K[{index+4}] XOR L'(tau(U)) = {words[index+4]:08X} XOR {transformed:08X} = {recovered:08X}"]
        words[index] = recovered
        if index >= 4:
            lines.append(f"DERIVED rk{index-4} = {recovered:08X}")
        events.append(step(index, f"Reverse SM4 schedule: K[{index}]", lines, state))
    master = piret_sm4.reverse_sm4(words[32:], record)
    for i in range(4):
        events.append(step(0, f"Remove FK[{i}]", [f"MK[{i}] = K[{i}] XOR FK[{i}] = {words[i]:08X} XOR {sm4.FK[i]:08X} = {words[i] ^ sm4.FK[i]:08X}"], master))
    events.append(step(0, "Assemble SM4 master key", ["MK = MK[0] || MK[1] || MK[2] || MK[3]", master.hex().upper()], master))
    return master, events


def sm4_fault_trace(clean_trace, fault_trace, number, byte, mask):
    """Teacher-only propagation; these internal values never enter the solver."""
    for r in range(number, 32):
        clean, fault = clean_trace[r], fault_trace[r]
        lines = ["TEACHER VIEW: target internals shown for explanation only."]
        if r == number:
            lines.append(f"Inject at round {r}, byte {byte}: A' = {clean['a']:08X} XOR {mask << (24-8*byte):08X} = {fault['a']:08X}")
        for label, field in (("S-box input", 'a'), ("S-box output", 'b'), ("Linear output", 'linear'), ("New word", 'new')):
            lines.append(f"{label}: correct={clean[field]:08X}; faulty={fault[field]:08X}; XOR={clean[field] ^ fault[field]:08X}")
        for title, item in (("Correct", clean), ("Faulty", fault)):
            lines += [f"{title} S-box byte {i}: S[{value:02X}]={sm4.SBOX[value]:02X}" for i, value in enumerate(item['a'].to_bytes(4, 'big'))]
            b = item['b']
            rotations = [((b << n) | (b >> (32-n))) & 0xffffffff for n in (2, 10, 18, 24)]
            lines.append(f"{title} L: {b:08X} XOR " + " XOR ".join(f"{value:08X}" for value in rotations) + f" = {item['linear']:08X}")
        # These display rows are A, tau(A), L(tau(A)), and the new word, not a rolling cipher state.
        clean_state = struct.pack('>4I', *(clean[field] for field in ('a', 'b', 'linear', 'new')))
        fault_state = struct.pack('>4I', *(fault[field] for field in ('a', 'b', 'linear', 'new')))
        lines.append("Displayed rows: A, tau(A), L(tau(A)), new word.")
        yield step(r, f"Fault propagation: SM4 round {r}", lines, clean_state, fault_state)


def verification(algorithm, plaintext, key, expected):
    """Check the recovered key by both forward and inverse block operations."""
    encrypt = aes.aes_encrypt if algorithm == 'aes' else sm4.sm4_encrypt_block
    decrypt = aes.aes_decrypt if algorithm == 'aes' else sm4.sm4_decrypt_block
    # Validate recovered key material through both forward and inverse block operations.
    actual = encrypt(plaintext, key)
    recovered = decrypt(expected, key)
    if actual != expected or recovered != plaintext:
        raise RuntimeError('Recovered key failed encryption/decryption verification.')
    return [step(0, "Verify recovered key: encrypt and decrypt", [f"Recovered key = {key.hex().upper()}", f"P = {plaintext.hex().upper()}", f"Expected C = {expected.hex().upper()}", f"Encrypt(P, recovered key) = {actual.hex().upper()} / PASS", f"Decrypt(C, recovered key) = {recovered.hex().upper()} / PASS", "This verifies the observed pair; simulation ground-truth equality is checked separately."], expected)]


def emit(terminal, events):
    """Print the same timeline as the GUI; preserve red changed bytes in logs."""
    for event in events:
        terminal.section(event['title'])
        correct, faulty = bytes.fromhex(event['reference']), bytes.fromhex(event['state'])
        # Color changes against the paired clean state; do not color all bytes indiscriminately.
        if correct != faulty:
            if hasattr(terminal, 'pair'):
                terminal.pair(correct, faulty)
            else:
                terminal.compare(correct, faulty)
        print(event['detail'])
        terminal.pause()

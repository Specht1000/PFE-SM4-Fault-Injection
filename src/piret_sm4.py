"""Round-input-byte SM4 DFA: faults, candidate filtering and full key recovery.

The solver receives ciphertexts and controlled fault descriptors, never a secret
key. Four recovered consecutive tail subkeys are required to reverse the schedule.
Run: python src/piret_sm4.py --step
"""
import argparse
import html
import re
from pathlib import Path
import sys
import struct
import sm4


# User settings: edit these two constants before running the terminal lesson.
FAULT_MASK = 0x01  # First XOR error: 0x01..0xFF. Further masks resolve ambiguity.
FAULT_BYTE = 0     # First target byte: 0..3, most significant byte first.


def sm4_fault_encrypt(plaintext, key, byte=None, mask=0, fault_round=31, word=1):
    
    if byte is not None and not (0 <= byte < 4 and 1 <= mask <= 255):
        raise ValueError("SM4 fault requires byte 0..3 and mask 1..255.")

    if not 0 <= fault_round < 32 or word not in (1, 2, 3):
        raise ValueError("Use round 0..31 and input word 1, 2 or 3.")

    keys = sm4.key_expansion(key)
    trace = []

    for index in range(32):
        trace.append(dict(round=index, rk=keys[index]))

    fields = {"Sbox input": "a", "Sbox output": "b", "Linear output": "linear", "New word": "new"}

    def observer(number, operation, value):
        # State input is emitted before ANY operation in the round.
        if operation == "State input":
            trace[number]["before"] = tuple(value)
            state = list(value)

            if number == fault_round and byte is not None:
                # Big-endian byte zero occupies bits 31..24.
                state[word] ^= mask << (24 - 8 * byte)

            value = tuple(state)
            trace[number]["state"] = value

        if operation == "State output":
            trace[number]["output"] = tuple(value)

        if operation in fields:
            trace[number][fields[operation]] = value

        return value

    ciphertext = sm4.sm4_encrypt_block(plaintext, key, observer=observer)
    return ciphertext, trace


def inverse_linear(value):
    """Compute L^-1(value) = ROR_8(L(L(L(value)))) on a 32-bit word.

    SM4's data transformation satisfies L^4(x) = ROL_8(x).
    For value = L(x), three more applications leave ROL_8(x).
    Rotating right by eight then returns x. This identity is for the data
    transformation L, not the key-schedule transformation L-prime.
    """
    # First application: transform the supplied output difference.
    result = sm4.linear(value)

    # Second application: feed the previous result back into L.
    result = sm4.linear(result)

    # Third application: the result is now the original input rotated left by 8.
    result = sm4.linear(result)

    # ROR_8 on 32 bits: wrap the low byte into the most significant byte.
    # The mask discards bits above position 31 in Python's unbounded integers.
    result = (result >> 8) | ((result << 24) & 0xFFFFFFFF)

    return result


def sm4_byte_candidates(correct, faulty, byte, mask):
    """Test all 256 KEY-byte guesses using only public, possibly peeled outputs.

    Output order: X[i+4], X[i+3], X[i+2], X[i+1].
    q and q_faulty are observable. Unchanged X[i] cancels in the newest-word XOR.
    """
    if len(correct) != 16 or len(faulty) != 16 or not 0 <= byte < 4 or not 1 <= mask <= 255:
        raise ValueError("Invalid SM4 output or known-fault descriptor.")

    c = struct.unpack(">4I", correct)
    f = struct.unpack(">4I", faulty)
    shift = 24 - 8 * byte
    expected_error = mask << shift
    changed_words = 0

    # One pass-through word must carry exactly the selected input-byte fault.
    for index in range(1, 4):
        difference = c[index] ^ f[index]

        if difference != 0:
            if difference != expected_error:
                raise ValueError("Unexpected pass-through word difference.")

            changed_words += 1

    if changed_words != 1:
        raise ValueError("Expected one changed round-input word in the output.")

    delta_b = inverse_linear(c[0] ^ f[0])

    if not delta_b or delta_b & ~(255 << shift):
        raise ValueError("Difference does not match a single-byte input fault.")

    delta = (delta_b >> shift) & 255
    q = ((c[1] ^ c[2] ^ c[3]) >> shift) & 255
    q_faulty = ((f[1] ^ f[2] ^ f[3]) >> shift) & 255
    key_candidates = set()
    inputs = set()

    # Guess rk directly; no secret key or teacher trace is consulted.
    for candidate_key in range(256):
        clean_input = q ^ candidate_key
        faulty_input = q_faulty ^ candidate_key
        predicted = sm4.SBOX[clean_input] ^ sm4.SBOX[faulty_input]

        if predicted == delta:
            key_candidates.add(candidate_key)
            inputs.add(clean_input)

    return key_candidates, inputs, delta_b


def reverse_sm4(final_keys, observer=None):
    """Turn the four last round keys rk28..rk31 back into the 16-byte master key.

    WHY FOUR KEYS: SM4's key schedule is the SAME sliding-window recurrence as the
    cipher. Each round key K[i+4] = K[i] xor T'(K[i+1] xor K[i+2] xor K[i+3] xor CK[i]).
    To run that recurrence BACKWARDS you need four consecutive known keys as a
    seed - one is not enough. rk28..rk31 are exactly K32..K35, the last window.
    """

    if len(final_keys) != 4:
        raise ValueError("SM4 reversal requires four consecutive final subkeys.")

    # Lay the 36 schedule words K0..K35 out; only the last four are known so far.
    words = [None] * 32 + list(final_keys)

    for index in range(31, -1, -1):
        # Solve the recurrence for K[index] using the four words to its right,
        # which are always already known because we go from 31 down to 0.
        # CK is the PUBLIC schedule constant; T' uses linear_key (L'), which is a
        # DIFFERENT linear map from the cipher's L (do not mix them up).
        value = words[index+1] ^ words[index+2] ^ words[index+3] ^ sm4.CK[index]

        words[index] = words[index+4] ^ sm4.linear_key(sm4.sbox(value))

        if observer:
            observer(index, words[index])

    # K0..K3 are the master key XORed with the fixed FK whitening constant; undo it.
    master_words = []

    for word_index in range(4):
        master_word = words[word_index] ^ sm4.FK[word_index]
        master_words.append(master_word)

    # Re-serialize the four recovered master-key words into 16 bytes.
    return struct.pack(">4I", *master_words)


def peel_sm4(ciphertext, target_round, recovered_keys):
    """Undo only rounds whose subkeys have ALREADY been recovered by DFA.

    Return a reversed four-word output at the end of target_round. This lets
    the same last-round equations analyze rounds 30, 29 and 28 in succession.
    No reference round keys or secret intermediate values are accepted.
    """

    sm4.validate_block(ciphertext, "SM4 ciphertext")

    if not 28 <= target_round <= 31:
        raise ValueError("Full SM4 recovery targets rounds 28..31.")

    # WHY PEELING: the last-round equations in sm4_byte_candidates only work on the
    # state as it was at the end of round `target_round`. To attack round 30 we must
    # first strip rounds 31 (and later 31,30 for round 29, etc.) using the subkeys we
    # ALREADY recovered - we never guess or borrow a key we have not solved.

    # SM4 outputs the final four words in REVERSE order; undo that to get the real
    # chronological window [oldest, ..., newest].
    words = list(struct.unpack(">4I", ciphertext))[::-1]

    for number in range(31, target_round, -1):
        if number not in recovered_keys:
            raise ValueError(f"Cannot undo round {number} before recovering its subkey.")

        # One round pushed a new word in and dropped the oldest. Recompute that round
        # function with the known key and XOR it into the newest word to recover the
        # word that was dropped - i.e. run the round backwards by one step.
        previous = words[3] ^ sm4.linear(sm4.sbox(words[0] ^ words[1] ^ words[2] ^ recovered_keys[number]))

        # Slide the window back one round: the recovered word becomes the oldest.
        words = [previous, words[0], words[1], words[2]]

    # Re-reverse to ciphertext-style order so sm4_byte_candidates can treat this
    # peeled state exactly like a fresh last-round ciphertext.
    return struct.pack(">4I", *words[::-1])


def recover_sm4_master_key(correct, fault_oracle, masks=(3, 1, 2, 4, 5, 6, 7, 8), start_byte=0, candidate_filter=None, observer=None):
    """Recover rk31 -> rk28 and reverse the schedule, using outputs only.

    fault_oracle(round, byte, mask) returns a faulty ciphertext. It represents
    a target capable of a controlled fault in EACH of the final four rounds.
    The solver receives no master key, schedule, or reference subkeys.
    Faults change one state-input word, including its pass-through output.
    """

    sm4.validate_block(correct, "Correct SM4 ciphertext")

    masks = tuple(masks)

    if not masks:
        raise ValueError("Use distinct nonzero byte masks and start_byte 0..3.")

    if len(set(masks)) != len(masks):
        raise ValueError("Use distinct nonzero byte masks and start_byte 0..3.")

    for candidate_mask in masks:
        if not 1 <= candidate_mask <= 255:
            raise ValueError("Use distinct nonzero byte masks and start_byte 0..3.")

    if not 0 <= start_byte < 4:
        raise ValueError("Use distinct nonzero byte masks and start_byte 0..3.")

    # keys: round -> recovered 32-bit subkey. history/counts/used are for reporting.
    keys, history, counts, used = {}, [], {}, 0

    # Attack the four tail rounds newest-first (31, 30, 29, 28). Newest-first is
    # mandatory: peeling round N needs every later round key already recovered.
    for number in range(31, 27, -1):
        # Strip the already-solved later rounds so this round looks like a fresh
        # last round to the solver (keys holds only DFA-recovered subkeys).
        clean_view = peel_sm4(correct, number, keys)

        subkey = bytearray(4)

        # Visit the four bytes of this subkey in a rotated order starting at
        # start_byte (purely which byte we demonstrate first; all four are solved).
        byte_order = []

        for offset in range(4):
            byte_order.append((start_byte + offset) % 4)

        for byte in byte_order:
            # survivors = running intersection of candidate values for THIS byte.
            survivors = None

            # None means no observation yet, not an empty or failed candidate set.
            for observation, mask in enumerate(masks, 1):
                # Ask the target for a faulty ciphertext (same input, chosen fault).
                faulty = bytes(fault_oracle(number, byte, mask))
                # The oracle knows the target secret, but returns only ciphertext.
                faulty_view = peel_sm4(faulty, number, keys)

                if candidate_filter is None:
                    # Check the observable input difference and test all key bytes.
                    fresh, inputs, delta = sm4_byte_candidates(clean_view, faulty_view, byte, mask)
                else:
                    position, fresh, inputs, delta = candidate_filter(clean_view, faulty_view, mask)

                    if position != byte:
                        raise ValueError("Fault observation does not match the requested byte.")

                # Intersect: each independent fault can only REMOVE wrong guesses,
                # never add them, so the set shrinks toward the single true byte.
                if survivors is None:
                    before = 256
                    survivors = set(fresh)
                else:
                    before = len(survivors)
                    survivors = survivors & fresh

                # Independent observations can remove candidates, never add them.
                if not survivors:
                    raise ValueError("SM4 candidate intersection is empty; fault model is incompatible.")

                used += 1
                counts[f"{number}:{byte}"] = len(survivors)
                recovered_key_labels = {}

                for index, value in keys.items():
                    recovered_key_labels[str(index)] = f'{value:08X}'

                event = dict(round=number, byte=byte, observation=observation, mask=mask, before=before, pair_candidates=len(fresh), remaining=len(survivors), survivors=sorted(survivors), inputs=sorted(inputs), delta_b=delta, correct=correct.hex(), faulty=faulty.hex(), clean_view=clean_view.hex(), faulty_view=faulty_view.hex(), peeled_with=recovered_key_labels)
                history.append(event)

                if observer is not None:
                    # Copy event metadata so presentation code cannot edit solver state.
                    observer(dict(event))

                if len(survivors) == 1:
                    # Only uniqueness permits using this byte in a recovered round key.
                    subkey[byte] = next(iter(survivors))
                    break
            else:
                # The loop exhausted its budget without a unique byte; do not peel
                # an earlier round with a guessed key or claim a complete master key.
                return dict(master_key=None, round_keys=keys, history=history, candidate_counts=counts, used=used, complete=False, blocked_round=number)

        # All four bytes of this round key are now unique: assemble the 32-bit key.
        keys[number] = int.from_bytes(subkey, "big")

    # All four tail keys now come from observations; invert the schedule once to
    # get the master key (needs rk28..rk31, in ascending order, as the seed).
    final_keys = []

    for candidate_number in range(28, 32):
        final_keys.append(keys[candidate_number])

    master = reverse_sm4(final_keys)

    return dict(master_key=master, round_keys=keys, history=history, candidate_counts=counts, used=used, complete=True)


class LessonLog:
    """Write identical lesson text to the terminal, TXT and a colored HTML file."""

    def __init__(self, path, color="auto"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.html = self.path.open("w", encoding="utf-8")
        self.txt = self.path.with_suffix(".txt").open("w", encoding="utf-8")
        self.color = color == "always" or (color == "auto" and sys.stdout.isatty())
        self.html.write('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>SM4 DFA terminal log</title>')
        # One continuous terminal transcript: no cards, panels or hidden sections.
        self.html.write('<style>html{color-scheme:dark}body{background:#0b0f14;color:#e6edf3;margin:24px}pre{font:14px/1.5 Consolas,monospace;white-space:pre;tab-size:4}.red{color:#ff7373}.green{color:#78d994}.cyan{color:#4fd1c5}.yellow{color:#ffcf75}.purple{color:#d4a1ff}.blue{color:#82aaff}::selection{background:#264f78;color:#fff}</style></head><body><pre>')

    def line(self, text="", tone=""):
        self.parts((text, tone))

    def parts(self, *segments):
        """Keep inline colors consistent in HTML and the live terminal."""
        codes = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "purple": "35", "cyan": "36"}
        terminal = ""

        for text, tone in segments:
            self.txt.write(text)
            self.html.write('<span class="' + tone + '">' + html.escape(text) + '</span>')

            if self.color and tone in codes:
                terminal += "\033[" + codes[tone] + "m" + text + "\033[0m"
            else:
                terminal += text

        self.txt.write("\n")
        self.html.write("\n")
        print(terminal)

    def equation(self, text):
        """Highlight operands, operators and the final numeric result."""
        segments = []
        position = 0
        pattern = r"\b[0-9A-F]{2,8}\b|\b(?:XOR|OR|AND|ROL_\d+|ROR_\d+)\b"
        matches = list(re.finditer(pattern, text))

        for index, match in enumerate(matches):
            segments.append((text[position:match.start()], ""))
            token = match.group()
            tone = "cyan"

            if re.fullmatch(r"[0-9A-F]{2,8}", token):
                tone = "yellow"

                if index == len(matches) - 1:
                    tone = "green"

            segments.append((token, tone))
            position = match.end()

        segments.append((text[position:], ""))
        self.parts(*segments)

    def pair(self, label, correct, faulty, width=8):
        # Match the old terminal logs: spaced bytes in three aligned rows.
        clean = f"{correct:0{width}X}"
        bad = f"{faulty:0{width}X}"
        difference = f"{correct ^ faulty:0{width}X}"
        self.line(label, "cyan")

        for prefix, value in (("Correct: ", clean), ("Faulty:  ", bad), ("XOR:     ", difference)):
            html_bytes = []
            terminal_bytes = []
            plain_bytes = []

            for offset in range(0, width, 2):
                part = value[offset:offset + 2]
                changed = clean[offset:offset + 2] != bad[offset:offset + 2]
                plain_bytes.append(part)

                # Use the SAME change mask in all three rows to make propagation
                # visible. Unaffected bytes, including zero XOR bytes, stay white.
                if changed:
                    html_bytes.append('<span class="red">' + part + '</span>')

                    if self.color:
                        terminal_bytes.append("\033[31m" + part + "\033[0m")
                    else:
                        terminal_bytes.append(part)
                else:
                    html_bytes.append(part)
                    terminal_bytes.append(part)

            self.html.write(prefix + " ".join(html_bytes) + "\n")
            self.txt.write(prefix + " ".join(plain_bytes) + "\n")
            print(prefix + " ".join(terminal_bytes))

        self.line()

    def section(self, title):
        # Plain text separators appear identically in the terminal and both logs.
        self.line()
        self.line("=" * 78, "cyan")
        self.line(title, "cyan")
        self.line("=" * 78, "cyan")

    def end_section(self):
        self.line()

    def close(self):
        self.html.write('</pre></body></html>')
        self.html.close()
        self.txt.close()


def show_peeling(log, ciphertext, number, keys):
    """Explain each inverse round using only already recovered subkeys."""
    words = list(struct.unpack(">4I", ciphertext))[::-1]

    for later in range(31, number, -1):
        q = words[0] ^ words[1] ^ words[2] ^ keys[later]
        b = sm4.sbox(q)
        linear = sm4.linear(b)
        previous = words[3] ^ linear
        log.line(f"Undo round {later} with recovered rk={keys[later]:08X}:")
        log.line(f"  A={words[0]:08X} XOR {words[1]:08X} XOR {words[2]:08X} XOR {keys[later]:08X} = {q:08X}")
        log.line(f"  tau(A)={b:08X}; L(tau(A))={linear:08X}")
        log.line(f"  Previous oldest word = {words[3]:08X} XOR {linear:08X} = {previous:08X}")
        words = [previous, words[0], words[1], words[2]]


def show_candidates(log, event):
    """Replay every one of the 256 public candidate equations for one observation."""
    c = struct.unpack(">4I", bytes.fromhex(event["clean_view"]))
    f = struct.unpack(">4I", bytes.fromhex(event["faulty_view"]))
    shift = 24 - 8 * event["byte"]
    q_word = c[1] ^ c[2] ^ c[3]
    f_word = f[1] ^ f[2] ^ f[3]
    q = (q_word >> shift) & 255
    qf = (f_word >> shift) & 255
    delta = (event["delta_b"] >> shift) & 255
    log.section(f"256 candidates: rk{event['round']} byte {event['byte']}, observation {event['observation']}")
    log.line("ATTACKER CALCULATIONS: ciphertexts and previously recovered keys only.", "cyan")
    keys = {}

    for index, value in event["peeled_with"].items():
        keys[int(index)] = int(value, 16)

    number = event["round"]

    if number < 31:
        # Only earlier-round attacks need inverse rounds with recovered keys.
        log.line("Undo later rounds in the correct ciphertext:")
        show_peeling(log, bytes.fromhex(event["correct"]), number, keys)
        log.line("Undo later rounds in the faulty ciphertext:")
        show_peeling(log, bytes.fromhex(event["faulty"]), number, keys)

        for index in range(4):
            log.pair(f"Derived X[{number + 4 - index}] after undoing later rounds", c[index], f[index])
    else:
        log.line("Use the ciphertext above: C = X[35] || X[34] || X[33] || X[32].")
        log.line("X[35] is the computed round output; X[34], X[33], X[32] are copied input words.")

    log.equation(f"q = X[{number + 1}] XOR X[{number + 2}] XOR X[{number + 3}]")

    log.equation(f"q = {c[3]:08X} XOR {c[2]:08X} XOR {c[1]:08X} = {q_word:08X}")
    log.equation(f"q_faulty = {f[3]:08X} XOR {f[2]:08X} XOR {f[1]:08X} = {f_word:08X}")
    log.equation(f"Observed input error = q XOR q_faulty = {q_word ^ f_word:08X}")
    value = c[0] ^ f[0]
    log.equation(f"DeltaX = X[i+4] XOR X'[i+4] = {c[0]:08X} XOR {f[0]:08X} = {value:08X}")
    log.line("Unchanged X[i] cancels. DeltaB = L^-1(DeltaX), NOT the individual B.")

    for application in range(1, 4):
        # Keep the same input for every rotation within ONE application of L.
        running = value
        log.line(f"Inverse route, L application {application}: input={value:08X}", "purple")

        for rotation in (2, 10, 18, 24):
            rotated = sm4.rotl(value, rotation)
            log.equation(f"  {running:08X} XOR ROL_{rotation}({value:08X})={rotated:08X} = {running ^ rotated:08X}")
            running ^= rotated

        value = running

    log.equation(f"ROR_8({value:08X}) = ({value:08X} >> 8) OR (({value:08X} << 24) AND FFFFFFFF) = {event['delta_b']:08X}")
    log.parts(("Selected byte: ", "cyan"), (f"q={q:02X}", "blue"), (", ", ""), (f"q_faulty={qf:02X}", "purple"), (", ", ""), (f"DeltaB={delta:02X}", "yellow"))

    for candidate in range(256):
        a = q ^ candidate
        af = qf ^ candidate
        b = sm4.SBOX[a]
        bf = sm4.SBOX[af]
        predicted = b ^ bf
        verdict = "REJECT"
        tone = "red"

        if predicted == delta:
            verdict = "PAIR MATCH"
            tone = "green"

        log.parts((f"k={candidate:02X}: ", "yellow"), (f"S({q:02X} XOR {candidate:02X}={a:02X})", "blue"), (" XOR ", "cyan"), (f"S({qf:02X} XOR {candidate:02X}={af:02X})", "purple"), (" = ", ""), (f"{b:02X}", "blue"), (" XOR ", "cyan"), (f"{bf:02X}", "purple"), (" = ", ""), (f"{predicted:02X}", tone), (f"; target={delta:02X}", "yellow"), (" -> ", ""), (verdict, tone))

    survivors = []

    for candidate in event["survivors"]:
        survivors.append(f"{candidate:02X}")

    log.line(f"Intersect previous {event['before']} candidates with pair matches: " + " ".join(survivors), "green")

    if event["remaining"] == 1:
        log.line(f"Recovered rk{event['round']} byte {event['byte']} = {survivors[0]}", "green")

    log.end_section()


def show_schedule(log, keys):
    """Expand every backward key-schedule equation after DFA has solved four keys."""
    words = [None] * 36

    for number in range(28, 32):
        words[number + 4] = keys[number]
        log.line(f"DFA recovered rk{number} = K[{number + 4}] = {keys[number]:08X}", "green")

    for index in range(31, -1, -1):
        q = words[index + 1] ^ words[index + 2] ^ words[index + 3] ^ sm4.CK[index]
        b = sm4.sbox(q)
        transformed = sm4.linear_key(b)
        words[index] = words[index + 4] ^ transformed
        log.line(f"K[{index}] = K[{index + 4}] XOR T'(K[{index + 1}] XOR K[{index + 2}] XOR K[{index + 3}] XOR CK[{index}])", "purple")
        log.equation(f"  q = {words[index + 1]:08X} XOR {words[index + 2]:08X} XOR {words[index + 3]:08X} XOR {sm4.CK[index]:08X} = {q:08X}")
        log.equation(f"  tau(q)={b:08X}; L'(tau(q)) = {b:08X} XOR ROL_13={sm4.rotl(b, 13):08X} XOR ROL_23={sm4.rotl(b, 23):08X} = {transformed:08X}")
        log.equation(f"  K[{index}] = {words[index + 4]:08X} XOR {transformed:08X} = {words[index]:08X}")

    for index in range(4):
        log.equation(f"MK[{index}] = K[{index}] XOR FK[{index}] = {words[index]:08X} XOR {sm4.FK[index]:08X} = {words[index] ^ sm4.FK[index]:08X}")


def main(argv=None):
    """Run the input-word fault lesson and overwrite its HTML/TXT logs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--algorithm", choices=("sm4",), default="sm4")
    parser.add_argument("--key", default=sm4.KEY, help="Target key, used ONLY by target and final verification.")
    parser.add_argument("--plaintext", default=sm4.PLAINTEXT)
    parser.add_argument("--word", type=int, choices=(1, 2, 3), default=1, help="Fault X[i+word] before the round XOR.")
    parser.add_argument("--row", type=int, choices=range(4), default=FAULT_BYTE, help="First byte to recover; overrides FAULT_BYTE.")
    parser.add_argument("--faults", type=int, default=8, help="Maximum observations per byte.")
    parser.add_argument("--step", action="store_true", help="Pause after each faulty encryption.")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    parser.add_argument("--log", default=str(Path(__file__).resolve().parents[1] / "logs" / "log.html"))
    args = parser.parse_args(argv)

    if not isinstance(FAULT_MASK, int) or not 1 <= FAULT_MASK <= 255:
        parser.error("FAULT_MASK must be an integer from 0x01 to 0xFF.")

    if args.row not in range(4):
        parser.error("FAULT_BYTE must be 0..3.")

    if not 1 <= args.faults <= 255:
        parser.error("--faults must be 1..255.")

    try:
        key = bytes.fromhex(args.key)
        plaintext = bytes.fromhex(args.plaintext)
        sm4.validate_block(key, "SM4 key")
        sm4.validate_block(plaintext, "SM4 plaintext")
    except ValueError as error:
        parser.error(str(error))

    log = LessonLog(args.log, args.color)

    try:
        log.line("CONTROLLED ROUND-INPUT BYTE FAULT: SM4 DFA", "cyan")
        log.line(f"Plaintext: {plaintext.hex().upper()}")
        log.line("Byte indices are big-endian; rounds are zero-based.")
        log.line(f"Fault: X[i+{args.word}] byte XOR mask, BEFORE XOR with rk. First mask = {FAULT_MASK:02X}; first byte = {args.row}.")
        log.line("Controlled-byte simulation: hardware glitches do not guarantee this exact model.")
        log.line("One tail subkey is insufficient for the master key: attack rounds 31,30,29,28.")
        correct = sm4.sm4_encrypt_block(plaintext, key)
        log.section("Reference encryption: public output")

        log.line(f"Correct ciphertext: {correct.hex().upper()}", "green")
        log.end_section()
        masks = [FAULT_MASK]

        # Start with the chosen error, then use distinct errors to disambiguate.
        # All four byte positions are eventually needed for a complete subkey.
        for mask in range(1, 256):
            if mask != FAULT_MASK:
                masks.append(mask)

        def oracle(number, byte, mask):
            # The target alone owns the key. Discard its internal teaching trace.
            faulty, _ = sm4_fault_encrypt(plaintext, key, byte, mask, number, args.word)
            log.section(f"Fault injection: round {number}, X[{number + args.word}], byte {byte}, mask {mask:02X}")
            log.line(f"Injected XOR mask: {mask:02X} << {24 - 8 * byte} = {mask << (24 - 8 * byte):08X}", "red")
            log.pair("Final ciphertext: X[35] || X[34] || X[33] || X[32]", int.from_bytes(correct, "big"), int.from_bytes(faulty, "big"), 32)

            if number == 31:
                log.line(f"The input fault in X[{number + args.word}] is copied to ciphertext word {4 - args.word} (zero-based).")
                log.line("It also changes X[35] through the S-box and L. X[31] cancels in the output XOR.")
            log.end_section()

            if args.step:
                input("Press Enter to test the 256 key-byte candidates... ")

            return faulty

        result = recover_sm4_master_key(correct, oracle, masks[:args.faults], args.row, observer=lambda event: show_candidates(log, event))

        if not result["complete"]:
            log.line(f"INCOMPLETE: ambiguous byte at round {result['blocked_round']}. Increase --faults.", "red")
            return 2

        log.section("Recovered tail subkeys and master-key reversal")
        show_schedule(log, result["round_keys"])
        master = result["master_key"]
        log.line(f"Recovered master key: {master.hex().upper()}", "green")
        verified = sm4.sm4_encrypt_block(plaintext, master) == correct
        log.line(f"Re-encryption with recovered master key matches reference: {verified}", "green")
        decrypted = sm4.sm4_decrypt_block(correct, master)
        log.line(f"Decryption: {decrypted.hex().upper()}; matches plaintext: {decrypted == plaintext}", "green")
        log.line(f"Teacher-only final key comparison: {master == key}")
        log.line(f"Faulty encryptions used: {result['used']}")
        log.end_section()

        if not verified or decrypted != plaintext or master != key:
            raise AssertionError("Recovered key failed verification.")

        return 0
    except Exception as error:
        log.line(f"ERROR: {error}", "red")
        raise
    finally:
        log.line(f"HTML log (overwritten each run): {log.path.resolve()}")
        log.line(f"TXT log: {log.path.with_suffix('.txt').resolve()}")
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())

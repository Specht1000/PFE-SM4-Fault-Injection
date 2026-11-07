"""One command: AES + Piret and SM4 + DFA, following AES_SM4_DFA.pdf."""
import argparse
import random
import struct
import aes
import sm4
import piret


def block(value):
    data = bytes.fromhex(value)
    if len(data) != 16:
        raise ValueError("Key and plaintext must contain exactly 16 bytes as hex.")
    return data


class LessonTerminal(piret.Terminal):
    def changed(self, original, faulty):
        return " ".join(self.paint(f"{value:02X}", "31") if value != original[i] else f"{value:02X}" for i, value in enumerate(faulty))

    def pair(self, correct, faulty):
        print("Correct: " + " ".join(f"{b:02X}" for b in correct))
        print("Faulty:  " + self.changed(correct, faulty))
        delta = bytes(a ^ b for a, b in zip(correct, faulty))
        print("XOR:     " + self.changed(bytes(len(delta)), delta))


def aes_demo(terminal, limit, seed):
    key, plaintext = block(aes.KEY), block(aes.PLAINTEXT)
    terminal.section("AES / PDF CHAPTER 2: ENCRYPTION")
    print("Key: " + key.hex().upper() + "\nPlaintext: " + plaintext.hex().upper())
    print("AES layout: index = 4*column + row. This execution has no fault.")
    clean, trace = piret.trace_round8(plaintext, key, fault_round=9)
    if clean != piret.aes_target_encrypt(plaintext, key):
        raise RuntimeError("AES trace differs from aes.py.")
    keys = aes.key_expansion(key)
    for number, round_key in enumerate(keys):
        print(f"K{number:02d} = {aes.state_to_bytes(round_key).hex().upper()}")
    initial = aes.bytes_to_state(plaintext)
    aes.add_round_key(initial, keys[0])
    print("Initial AddRoundKey: " + aes.state_to_bytes(initial).hex().upper())
    for number, operation, state in trace:
        if operation != "Fault point":
            print(f"R{number:02d} {operation:12s}: {state.hex().upper()}")
            terminal.pause()
    print("Correct ciphertext: " + clean.hex().upper())
    terminal.section("AES / PDF CHAPTER 3: PIRET AT ROUND-9 MIXCOLUMNS INPUT")
    print("Recover one K10 quartet per column; repeat across all four columns.")
    print("d = InvSbox[C[p] XOR k] XOR InvSbox[F[p] XOR k].")
    print("Four d values must match one of 4*255 = 1020 MixColumns difference patterns.")
    masks = [1, 2] + random.Random(seed).sample(list(range(3, 256)), limit - 2) if limit >= 2 else [1]
    last_key, total = bytearray(16), 0
    for column in range(4):
        survivors = None
        print(f"\nCOLUMN {column}: output/key positions {piret.output_positions(column)}")
        for observation, mask in enumerate(masks, 1):
            faulty, faulty_trace = piret.trace_round8(plaintext, key, 0, column, mask, fault_round=9)
            total += 1
            print(f"\nObservation {observation}: simulator XOR {mask:02X}, row 0 / column {column}.")
            print("The solver enumerates unknown fault rows/values and does not receive this mask.")
            if observation == 1:
                references = {(r, op): state for r, op, state in trace}
                for number, operation, state in faulty_trace:
                    if number >= 9:
                        print(f"R{number:02d} {operation}")
                        terminal.compare(references[number, operation], state)
                        terminal.pause()
            terminal.pair(clean, faulty)
            fresh = piret.key_candidates(clean, faulty, column)
            before = None if survivors is None else len(survivors)
            survivors = fresh if survivors is None else survivors & fresh
            print(f"Candidates in this pair: {len(fresh)}; intersection: {before} -> {len(survivors)}")
            print("First survivors: " + " | ".join(bytes(candidate).hex().upper() for candidate in sorted(survivors)[:4]))
            terminal.pause()
            if not survivors:
                raise RuntimeError("AES candidate intersection is empty.")
            if len(survivors) == 1:
                for position, value in zip(piret.output_positions(column), next(iter(survivors))):
                    last_key[position] = value
                break
        else:
            print(terminal.paint("AES recovery remains ambiguous. Increase --observations.", "31"))
            return False
    terminal.section("AES / PDF SECTION 3.6: REVERSE KEY EXPANSION")
    print("Recovered K10: " + bytes(last_key).hex().upper())

    def reverse_step(index, current, transformed, recovered):
        print(f"w[{index-4:02d}] = {current.hex().upper()} XOR {transformed.hex().upper()} = {recovered.hex().upper()}")
        if index % 4 == 0:
            terminal.pause()

    recovered = piret.reverse_key_schedule(last_key, reverse_step)
    if recovered != key or piret.aes_target_encrypt(plaintext, recovered) != clean:
        raise RuntimeError("AES key recovery verification failed.")
    print(terminal.paint(f"AES MASTER KEY: {recovered.hex().upper()} / PASS ({total} faulty outputs)", "32"))
    return True


def inverse_rows():
    """Compatibility adapter; the attack calculation lives in piret.py."""
    return piret.inverse_rows()


def inverse_linear(value):
    """Compatibility adapter; the attack calculation lives in piret.py."""
    return piret.inverse_linear(value)


def sm4_encrypt(plaintext, key, byte=None, mask=0, fault_round=31):
    """Terminal compatibility adapter; attack injection belongs to piret.py."""
    return piret.sm4_fault_encrypt(plaintext, key, byte, mask, fault_round)


def sm4_byte_candidates(correct, faulty, byte, mask):
    """Compatibility adapter; the attack calculation lives in piret.py."""
    return piret.sm4_byte_candidates(correct, faulty, byte, mask)


def reverse_sm4(final_keys, observer=None):
    """Compatibility adapter; the attack calculation lives in piret.py."""
    return piret.reverse_sm4(final_keys, observer)


def show_sm4_peeling(terminal, ciphertext, target_round, recovered_keys):
    """Explain restored words using only subkeys already recovered by DFA."""
    view = ciphertext
    for number in range(31, target_round, -1):
        words = struct.unpack(">4I", view)[::-1]
        round_key = recovered_keys[number]
        value = words[0] ^ words[1] ^ words[2] ^ round_key
        substituted = sm4.sbox(value)
        diffused = sm4.linear(substituted)
        # The attack engine performs the actual reversal; this helper explains it.
        view = piret.peel_sm4(ciphertext, number-1, recovered_keys)
        previous = struct.unpack(">4I", view)[-1]
        print(f"  Undo round {number} with recovered rk{number}={round_key:08X}")
        print(f"    A = {words[0]:08X} XOR {words[1]:08X} XOR {words[2]:08X} XOR {round_key:08X} = {value:08X}")
        print(f"    tau(A) = {substituted:08X}; L(tau(A)) = {diffused:08X}")
        print(f"    X{number} = X{number+4} XOR L(tau(A)) = {words[3]:08X} XOR {diffused:08X} = {previous:08X}")
        print(f"    Restored output view: {view.hex().upper()}")


def show_sm4_key_schedule(terminal, recovered_keys):
    """Explain inverse expansion and FK removal from the DFA-recovered tail."""
    terminal.section("SM4: REVERSE THE KEY SCHEDULE / RECOVER ALL EARLIER SUBKEYS")
    print("DFA recovered rk31..rk28. Earlier rk values below are DERIVED by reversing the schedule.")
    print("K[i+4] = rk[i]; K[i] = K[i+4] XOR L'(tau(K[i+1] XOR K[i+2] XOR K[i+3] XOR CK[i]))")
    print("L'(B) = B XOR rol(B,13) XOR rol(B,23). This is NOT the data transform L.")
    final_keys = [recovered_keys[number] for number in range(28, 32)]
    words = [None] * 32 + final_keys
    for number in range(28, 32):
        print(f"Starting word K[{number+4}] = DFA-recovered rk{number} = {recovered_keys[number]:08X}")

    def report(index, recovered_word):
        value = words[index+1] ^ words[index+2] ^ words[index+3] ^ sm4.CK[index]
        substituted = sm4.sbox(value)
        transformed = sm4.linear_key(substituted)
        words[index] = recovered_word
        print(f"\nSchedule step i={index}")
        print(f"  U = K[{index+1}] XOR K[{index+2}] XOR K[{index+3}] XOR CK[{index}]")
        print(f"    = {words[index+1]:08X} XOR {words[index+2]:08X} XOR {words[index+3]:08X} XOR {sm4.CK[index]:08X} = {value:08X}")
        print(f"  tau(U) = {substituted:08X}; L'(tau(U)) = {transformed:08X}")
        print(f"  K[{index}] = K[{index+4}] XOR L'(tau(U)) = {words[index+4]:08X} XOR {transformed:08X} = {recovered_word:08X}")
        if index >= 4:
            print(terminal.paint(f"  DERIVED rk{index-4} = {recovered_word:08X}", "32"))
        else:
            print(f"  K[{index}] is an initial whitened key word, not an encryption subkey.")
        terminal.pause()

    master = piret.reverse_sm4(final_keys, observer=report)
    terminal.section("SM4: REMOVE FK CONSTANTS / ASSEMBLE THE ORIGINAL MASTER KEY")
    for index in range(4):
        value = words[index] ^ sm4.FK[index]
        print(f"MK[{index}] = K[{index}] XOR FK[{index}] = {words[index]:08X} XOR {sm4.FK[index]:08X} = " + terminal.paint(f"{value:08X}", "1;32"))
    print("Master key = MK[0] || MK[1] || MK[2] || MK[3] = " + terminal.paint(master.hex().upper(), "1;32"))
    return master


def show_sm4_observation(terminal, event, recovered_bytes, start_byte=0, known_bit=None):
    """Explain one byte-DFA or Giraud event without strengthening its model."""
    number, byte = event['round'], event['byte']
    if byte == start_byte and event['observation'] == 1:
        terminal.section(f"SM4: DISCOVER rk{number} FROM NEW ROUND-{number} FAULTS")
        if number == 31:
            print("Round 31 is already last; no round needs to be undone.")
        else:
            keys = {int(r): int(value, 16) for r, value in event['peeled_with'].items()}
            print("Restore the target round using ONLY previously recovered later subkeys.")
            print("Correct execution:")
            show_sm4_peeling(terminal, bytes.fromhex(event['correct']), number, keys)
            print("Faulty execution (a NEW fault at the target round):")
            show_sm4_peeling(terminal, bytes.fromhex(event['faulty']), number, keys)
    print(f"\nRound {event['round']}, byte {event['byte']}, observation {event['observation']}, mask {event['mask']:02X}")
    terminal.pair(bytes.fromhex(event['correct']), bytes.fromhex(event['faulty']))
    print("Undo later rounds using ONLY previously recovered subkeys: " + str(event['peeled_with']))
    terminal.pair(bytes.fromhex(event['clean_view']), bytes.fromhex(event['faulty_view']))
    clean_words = struct.unpack(">4I", bytes.fromhex(event['clean_view']))
    faulty_words = struct.unpack(">4I", bytes.fromhex(event['faulty_view']))
    shift = 24 - 8 * byte
    known = ((clean_words[1] ^ clean_words[2] ^ clean_words[3]) >> shift) & 255
    delta = (event['delta_b'] >> shift) & 255
    print(f"DeltaX = {clean_words[0]:08X} XOR {faulty_words[0]:08X} = {clean_words[0] ^ faulty_words[0]:08X}")
    print(f"DeltaB = L-inverse(DeltaX) = {event['delta_b']:08X}; selected byte difference = {delta:02X}")
    print(f"Known byte q = byte {byte} of (X{number+1} XOR X{number+2} XOR X{number+3}) = {known:02X}")
    if known_bit is False:
        allowed = (1, 2, 4, 8, 16, 32, 64, 128)
        print("UNKNOWN-BIT FILTER: the simulator mask above is NOT given to the candidate solver.")
    else:
        allowed = (event['mask'],)
        print("KNOWN-MASK FILTER: the exact error is given to the candidate solver.")
    print("Allowed input errors: " + " ".join(f"{value:02X}" for value in allowed))
    print(f"Test a=00..FF: at least one allowed e must satisfy S(a) XOR S(a XOR e) = {delta:02X}.")
    for candidate in event['inputs']:
        error = next(value for value in allowed if sm4.SBOX[candidate] ^ sm4.SBOX[candidate ^ value] == delta)
        changed = candidate ^ error
        print(f"  a={candidate:02X}, compatible e={error:02X}: S[{candidate:02X}] XOR S[{changed:02X}] = {sm4.SBOX[candidate]:02X} XOR {sm4.SBOX[changed]:02X} = {delta:02X}; rk byte = a XOR q = {candidate:02X} XOR {known:02X} = {candidate ^ known:02X}")
    print(f"L-inverse difference: {event['delta_b']:08X}; candidates {event['before']} -> {event['remaining']}")
    print("Survivors: " + " ".join(f"{value:02X}" for value in event['survivors']))
    if event['remaining'] == 1:
        value = event['survivors'][0]
        recovered_bytes.setdefault(number, {})[byte] = value
        print(terminal.paint(f"RECOVERED rk{number} byte {byte} = {value:02X} / UNIQUE", "32"))
        if len(recovered_bytes[number]) == 4:
            ordered = bytes(recovered_bytes[number][index] for index in range(4))
            print("Assemble bytes in big-endian order: " + " || ".join(f"{v:02X}" for v in ordered))
            print(terminal.paint(f"DFA ASSEMBLED rk{number} = {ordered.hex().upper()}", "1;32"))
    terminal.pause()


def show_aes_key_schedule(terminal, last_key):
    """Explain every reversed AES word and assemble K9 down to K0."""
    terminal.section("AES: REVERSE THE KEY SCHEDULE / K10 -> K0")
    words = [None] * 44
    words[40:] = [bytes(last_key[index:index+4]) for index in range(0, 16, 4)]
    print("Start with the recovered K10: " + bytes(last_key).hex().upper())
    print("w[i-4] = w[i] XOR T(w[i-1]); T is identity except at multiples of four.")

    def report(index, current, transformed, previous):
        if index % 4 == 0:
            original = words[index-1]
            rotated = original[1:] + original[:1]
            substituted = bytes(aes.SBOX[value] for value in rotated)
            print(f"  Schedule core: RotWord({original.hex().upper()}) = {rotated.hex().upper()}; SubWord = {substituted.hex().upper()}")
            print(f"  Rcon[{index//4}] = {aes.RCON[index//4]:02X} in the first byte; T = {transformed.hex().upper()}")
        else:
            print(f"  T is identity: T(w[{index-1}]) = {transformed.hex().upper()}")
        words[index-4] = previous
        print(f"w[{index-4}] = w[{index}] XOR T(w[{index-1}]) = {current.hex().upper()} XOR {transformed.hex().upper()} = {previous.hex().upper()}")
        if (index-4) % 4 == 0:
            round_number = (index-4) // 4
            round_key = b''.join(words[index-4:index])
            print(terminal.paint(f"DERIVED K{round_number} = {round_key.hex().upper()}", "32"))
        terminal.pause()

    master = piret.reverse_key_schedule(last_key, observer=report)
    print("Master key = w[0] || w[1] || w[2] || w[3] = " + terminal.paint(master.hex().upper(), "1;32"))
    return master


def sm4_demo(terminal, limit, start_byte=0):
    """Recover all four final subkeys through faults, then the complete key."""
    key, plaintext = block(sm4.KEY), block(sm4.PLAINTEXT)
    correct, trace = sm4_encrypt(plaintext, key)
    terminal.section("SM4: NORMAL ENCRYPTION")
    for item in trace:
        print(f"Round {item['round']:02d}: A={item['a']:08X} B={item['b']:08X} L(B)={item['linear']:08X} new={item['new']:08X}")
        terminal.pause()
    print("Ciphertext: " + correct.hex().upper())
    terminal.section("SM4: FULL MASTER-KEY DFA / ROUNDS 31 -> 28")
    print("Controlled faults in EACH final round are required. No reference subkeys are supplied.")
    print("For each byte: undo L, test S(a) XOR S(a XOR mask), then convert a to a subkey guess.")
    print("Repeat independent faults and intersect guesses. Only one survivor identifies a byte.")
    recovered_bytes = {}

    def oracle(number, byte, mask):
        return piret.sm4_fault_encrypt(plaintext, key, byte, mask, number)[0]

    def report(event):
        show_sm4_observation(terminal, event, recovered_bytes, start_byte)

    result = piret.recover_sm4_master_key(correct, oracle, range(1, limit+1), start_byte, observer=report)
    if not result['complete']:
        print("SM4 recovery remains ambiguous. Increase --observations.")
        return False
    for number, value in result['round_keys'].items():
        print(terminal.paint(f"DFA RECOVERED rk{number} = {value:08X} / PASS", "32"))
    recovered = show_sm4_key_schedule(terminal, result['round_keys'])
    if recovered != result['master_key']:
        raise RuntimeError("Displayed inverse schedule disagrees with the recovery engine.")
    verified_ciphertext = sm4.sm4_encrypt_block(plaintext, recovered)
    if recovered != key or verified_ciphertext != correct:
        raise RuntimeError("SM4 full master-key verification failed.")
    terminal.section("SM4: VERIFY THE RECOVERED MASTER KEY")
    print("Plaintext:                " + plaintext.hex().upper())
    print("Expected ciphertext:      " + correct.hex().upper())
    print("Recovered-key ciphertext: " + verified_ciphertext.hex().upper())
    print(terminal.paint("SM4 MASTER KEY: " + recovered.hex().upper() + " / PASS", "32"))
    print(f"{result['used']} faulty outputs. All four subkeys came from DFA, not references.")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--algorithm", choices=("all", "aes", "sm4"), default="all")
    parser.add_argument("--step", action="store_true", help="Pause after each state/observation.")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="always")
    parser.add_argument("--observations", type=int, default=8, help="Max observations per AES column / SM4 byte (1..255).")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    if not 1 <= args.observations <= 255:
        parser.error("--observations must be 1..255.")
    try:
        for value in (aes.KEY, aes.PLAINTEXT, sm4.KEY, sm4.PLAINTEXT):
            block(value)
    except ValueError as error:
        parser.error(str(error))
    terminal = LessonTerminal(args.color, args.step)
    print("AES_SM4_DFA.pdf / chapters 2-6 / software demonstration")
    print("RED marks bytes changed by the injected fault, including propagated changes.")
    statuses = []
    if args.algorithm in ("all", "aes"):
        statuses.append(aes_demo(terminal, args.observations, args.seed))
    if args.algorithm in ("all", "sm4"):
        statuses.append(sm4_demo(terminal, args.observations))
    return 0 if all(statuses) else 2


if __name__ == "__main__":
    from terminal_log import run_with_log
    raise SystemExit(run_with_log(main, "run"))

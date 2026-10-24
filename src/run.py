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

    def oracle(number, byte, mask):
        return piret.sm4_fault_encrypt(plaintext, key, byte, mask, number)[0]

    def report(event):
        print(f"\nRound {event['round']}, byte {event['byte']}, observation {event['observation']}, mask {event['mask']:02X}")
        terminal.pair(bytes.fromhex(event['correct']), bytes.fromhex(event['faulty']))
        print("Undo later rounds using ONLY previously recovered subkeys: " + str(event['peeled_with']))
        terminal.pair(bytes.fromhex(event['clean_view']), bytes.fromhex(event['faulty_view']))
        print(f"L-inverse difference: {event['delta_b']:08X}; candidates {event['before']} -> {event['remaining']}")
        print("Survivors: " + " ".join(f"{value:02X}" for value in event['survivors']))
        terminal.pause()

    result = piret.recover_sm4_master_key(correct, oracle, range(1, limit+1), start_byte, observer=report)
    if not result['complete']:
        print("SM4 recovery remains ambiguous. Increase --observations.")
        return False
    for number, value in result['round_keys'].items():
        print(terminal.paint(f"DFA RECOVERED rk{number} = {value:08X} / PASS", "32"))
    recovered = result['master_key']
    if recovered != key or sm4.sm4_encrypt_block(plaintext, recovered) != correct:
        raise RuntimeError("SM4 full master-key verification failed.")
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
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nLesson stopped.")

"""One command: AES + Piret and SM4 + DFA, following AES_SM4_DFA.pdf."""
import argparse
from functools import lru_cache
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


@lru_cache(maxsize=1)
def inverse_rows():
    """Invert SM4 L's 32x32 binary matrix with Gaussian elimination."""
    columns = [sm4.linear(1 << i) for i in range(32)]
    rows = [sum(((columns[col] >> row) & 1) << col for col in range(32)) | (1 << (32 + row)) for row in range(32)]
    for column in range(32):
        pivot = next(row for row in range(column, 32) if (rows[row] >> column) & 1)
        rows[column], rows[pivot] = rows[pivot], rows[column]
        for row in range(32):
            if row != column and (rows[row] >> column) & 1:
                rows[row] ^= rows[column]
    return tuple(row >> 32 for row in rows)


def inverse_linear(value):
    return sum((bin(row & value).count("1") & 1) << index for index, row in enumerate(inverse_rows()))


def sm4_encrypt(plaintext, key, byte=None, mask=0):
    """Controlled fault on A (S-box input), zero-based round 31 only."""
    if len(plaintext) != 16 or len(key) != 16 or byte is not None and not (0 <= byte < 4 and 1 <= mask <= 255):
        raise ValueError("SM4 requires 16-byte inputs and a valid nonzero byte fault.")
    keys, x, trace = sm4.key_expansion(key), list(struct.unpack(">4I", plaintext)), []
    for index, rk in enumerate(keys):
        original = x[index+1] ^ x[index+2] ^ x[index+3] ^ rk
        value = original ^ (mask << (24 - 8 * byte)) if index == 31 and byte is not None else original
        substituted = sm4.sbox(value)
        linear = sm4.linear(substituted)
        x.append(x[index] ^ linear)
        trace.append(dict(round=index, a=value, b=substituted, linear=linear, new=x[-1], rk=rk))
    return struct.pack(">4I", *x[-4:][::-1]), trace


def sm4_byte_candidates(correct, faulty, byte, mask):
    """Attacker API: outputs and the PDF's KNOWN fault byte/value only."""
    if len(correct) != 16 or len(faulty) != 16 or not 0 <= byte < 4 or not 1 <= mask <= 255:
        raise ValueError("Invalid SM4 output or known-fault descriptor.")
    c, f = struct.unpack(">4I", correct), struct.unpack(">4I", faulty)
    if c[1:] != f[1:]:
        raise ValueError("The last-round model requires three output words unchanged.")
    delta_b = inverse_linear(c[0] ^ f[0])
    shift = 24 - 8 * byte
    if not delta_b or delta_b & ~(255 << shift):
        raise ValueError("Difference does not match a single-byte S-box input fault.")
    d = (delta_b >> shift) & 255
    known = ((c[1] ^ c[2] ^ c[3]) >> shift) & 255
    inputs = {a for a in range(256) if sm4.SBOX[a] ^ sm4.SBOX[a ^ mask] == d}
    return {a ^ known for a in inputs}, inputs, delta_b


def reverse_sm4(final_keys, observer=None):
    """Four consecutive keys rk28..rk31 are REQUIRED, not merely rk31."""
    if len(final_keys) != 4:
        raise ValueError("SM4 reversal requires four consecutive final subkeys.")
    words = [None] * 32 + list(final_keys)
    for index in range(31, -1, -1):
        value = words[index+1] ^ words[index+2] ^ words[index+3] ^ sm4.CK[index]
        words[index] = words[index+4] ^ sm4.linear_key(sm4.sbox(value))
        if observer:
            observer(index, words[index])
    return struct.pack(">4I", *(words[i] ^ sm4.FK[i] for i in range(4)))


def sm4_demo(terminal, limit):
    key, plaintext = block(sm4.KEY), block(sm4.PLAINTEXT)
    correct, trace = sm4_encrypt(plaintext, key)
    terminal.section("SM4 / PDF CHAPTER 4: ENCRYPTION")
    print("Key: " + key.hex().upper() + "\nPlaintext: " + plaintext.hex().upper())
    print("A = X[i+1] XOR X[i+2] XOR X[i+3] XOR rk[i]; B = tau(A).")
    print("L uses rotations 2,10,18,24. Key expansion uses L-prime rotations 13,23.")
    for item in trace:
        print(f"Round {item['round']:02d}: rk={item['rk']:08X} A={item['a']:08X} B={item['b']:08X} L(B)={item['linear']:08X} new={item['new']:08X}")
        terminal.pause()
    print("Ciphertext (reversed words): " + correct.hex().upper())
    terminal.section("SM4 / PDF CHAPTER 5: CONTROLLED LAST-ROUND DFA")
    print("This is the PDF's SM4 model, not the AES Piret fault model.")
    print("Assumption: KNOWN XOR on one A byte before the S-box in round 31.")
    print("The attacker observes ciphertexts, knows byte/mask, and computes L-inverse.")
    words = struct.unpack(">4I", correct)
    known_word = words[1] ^ words[2] ^ words[3]
    print(f"Observed X32 XOR X33 XOR X34 = {known_word:08X}; rk31 = A XOR this word.")
    recovered_key = bytearray(4)
    for byte in range(4):
        survivors = None
        for mask in range(1, limit + 1):
            faulty, faulty_trace = sm4_encrypt(plaintext, key, byte, mask)
            print(f"\nByte {byte} (0=MSB), known XOR {mask:02X}")
            print("Teacher view: S-box input A, then output B; hidden from the solver.")
            terminal.pair(trace[-1]["a"].to_bytes(4, "big"), faulty_trace[-1]["a"].to_bytes(4, "big"))
            terminal.pair(trace[-1]["b"].to_bytes(4, "big"), faulty_trace[-1]["b"].to_bytes(4, "big"))
            print("Observed ciphertexts:")
            terminal.pair(correct, faulty)
            fresh, inputs, delta_b = sm4_byte_candidates(correct, faulty, byte, mask)
            before = 256 if survivors is None else len(survivors)
            survivors = fresh if survivors is None else survivors & fresh
            delta_x = int.from_bytes(correct[:4], "big") ^ int.from_bytes(faulty[:4], "big")
            print(f"L-inverse({delta_x:08X}) = {delta_b:08X}")
            print(f"S(a) XOR S(a XOR {mask:02X}) = {(delta_b >> (24-8*byte)) & 255:02X}")
            print("S-box input candidates: " + " ".join(f"{v:02X}" for v in sorted(inputs)))
            print(f"Convert each input guess a into key guess: k = a XOR {(known_word >> (24-8*byte)) & 255:02X}.")
            print(f"Key-byte candidates: {before} -> {len(survivors)}: " + " ".join(f"{v:02X}" for v in sorted(survivors)))
            terminal.pause()
            if not survivors:
                raise RuntimeError("SM4 candidate intersection is empty.")
            if len(survivors) == 1:
                recovered_key[byte] = next(iter(survivors))
                break
        else:
            print(terminal.paint("SM4 rk31 remains ambiguous. Increase --observations.", "31"))
            return False
    rk31 = int.from_bytes(recovered_key, "big")
    if rk31 != trace[-1]["rk"]:
        raise RuntimeError("Recovered SM4 rk31 failed ground-truth verification.")
    print(terminal.paint(f"DFA RECOVERED rk31 = {rk31:08X} / PASS", "32"))
    c = struct.unpack(">4I", correct)
    previous = c[0] ^ sm4.linear(sm4.sbox(c[1] ^ c[2] ^ c[3] ^ rk31))
    print(f"Reconstructed X31 = {previous:08X}")
    terminal.section("SM4 / PDF CHAPTER 6: CONDITIONAL MASTER-KEY REVERSAL")
    print("Only rk31 was recovered by DFA. rk28..rk30 are supplied REFERENCE subkeys.")
    print("This verifies schedule inversion; it is not a full DFA master-key recovery.")
    references = sm4.key_expansion(key)[28:31]
    print("Reference rk28..rk30: " + " ".join(f"{v:08X}" for v in references))

    def reverse_step(index, value):
        print(f"K[{index:02d}] = K[{index+4:02d}] XOR T-prime(K[{index+1:02d}] XOR K[{index+2:02d}] XOR K[{index+3:02d}] XOR CK[{index:02d}]) = {value:08X}")
        terminal.pause()

    recovered = reverse_sm4(references + [rk31], reverse_step)
    if recovered != key or sm4_encrypt(plaintext, recovered)[0] != correct:
        raise RuntimeError("SM4 conditional schedule reversal failed.")
    print("Undo FK: MK[i] = K[i] XOR FK[i].")
    print(terminal.paint("SM4 MASTER KEY (using reference subkeys): " + recovered.hex().upper() + " / PASS", "32"))
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

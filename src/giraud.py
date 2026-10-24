"""Giraud attack calculations, with an optional terminal demonstration.

AES: guess a K10 byte and check whether the inverse-S-box difference is one bit.
SM4 adaptation: undo recovered later rounds, invert L and filter bit differences.

Candidate functions receive correct/faulty ciphertexts, never a secret key.
The separate target adapters run the actual cipher and need its configured key.
known_mask=None means the attacker does not know which bit was flipped.
Visual steps and interface code stay in gui.py. main() runs a small independent
software example without importing Tkinter or opening a window.
"""
import aes
import sm4
from piret import inverse_linear

# Exactly one of the eight bits of a byte may be flipped.
SINGLE_BITS = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)
AES_INVERSE_SBOX = tuple(aes.SBOX.index(value) for value in range(256))


def validate_mask(mask):
    """Reject masks that flip zero bits or more than one bit."""
    if mask not in SINGLE_BITS:
        raise ValueError("Single-bit mask required: 01, 02, 04, 08, 10, 20, 40 or 80.")


def masks_for(first, maximum):
    """Return distinct one-bit faults, starting with the selected bit."""
    validate_mask(first)
    if not 1 <= maximum <= 8:
        raise ValueError("Use 1..8 distinct bit observations per target byte.")
    return ([first] + [mask for mask in SINGLE_BITS if mask != first])[:maximum]


def aes_fault_encrypt(plaintext, key, byte=0, mask=None):
    """Interfere with the real aes.py execution before final SubBytes.

    Only this attack callback changes the state. Without it AES is unchanged.
    Snapshots are copies for teaching; they are never inputs to the solver.
    """
    if not 0 <= byte < 16:
        raise ValueError("AES input byte must be 0..15.")
    if mask is not None:
        validate_mask(mask)
    trace = {}

    def observer(number, operation, state):
        if number == 10 and operation == "Before SubBytes":
            trace["Before fault"] = aes.state_to_bytes(state)
            if mask is not None:
                state[byte % 4][byte // 4] ^= mask
            trace["Injected bit"] = aes.state_to_bytes(state)
        if number == 10 and operation.startswith("After "):
            name = "Ciphertext" if operation == "After AddRoundKey" else operation[6:]
            trace[name] = aes.state_to_bytes(state)

    ciphertext = aes.aes_encrypt(plaintext, key, observer=observer)
    return ciphertext, trace


def sm4_fault_encrypt(plaintext, key, byte=None, mask=0, fault_round=31):
    """Restrict the external SM4 experiment to Giraud's one-bit fault model."""
    import piret
    if byte is not None:
        validate_mask(mask)
    return piret.sm4_fault_encrypt(plaintext, key, byte, mask, fault_round)


def recover_sm4_master_key(correct, fault_oracle, first_mask=1, maximum=8, known_bit=False, start_byte=0, observer=None):
    """Full SM4 recovery using single-bit filtering in rounds 31, 30, 29, 28."""
    import piret

    def candidate_filter(clean, faulty, simulator_mask):
        # Unknown-bit mode deliberately does not pass the oracle's mask onward.
        return sm4_candidates(clean, faulty, simulator_mask if known_bit else None)

    return piret.recover_sm4_master_key(correct, fault_oracle, masks_for(first_mask, maximum), start_byte, candidate_filter, observer)


def aes_candidates(correct, faulty, known_mask=None):
    """Return the affected output position and its compatible K10 byte values.

    For each guess k:
      delta = InvSbox[C[j] XOR k] XOR InvSbox[F[j] XOR k]
    Keep k when delta has exactly one set bit, or equals the known bit mask.
    """
    aes.validate_block(correct, "Correct ciphertext")
    aes.validate_block(faulty, "Faulty ciphertext")
    if known_mask is not None:
        validate_mask(known_mask)

    # Without final-round MixColumns, only one ciphertext byte should change.
    changed = [index for index in range(16) if correct[index] != faulty[index]]
    if len(changed) != 1:
        raise ValueError("AES Giraud requires exactly one changed ciphertext byte.")
    position = changed[0]
    allowed = SINGLE_BITS if known_mask is None else (known_mask,)

    candidates = set()
    for guess in range(256):
        clean_input = AES_INVERSE_SBOX[correct[position] ^ guess]
        faulty_input = AES_INVERSE_SBOX[faulty[position] ^ guess]
        difference = clean_input ^ faulty_input
        if difference in allowed:
            candidates.add(guess)
    return position, candidates


def sm4_candidates(correct, faulty, known_mask=None):
    """Return affected byte, round-key guesses, input guesses and DeltaB.

    Inputs may be actual final ciphertexts or peeled views at an earlier round.

    1. Observe DeltaX35 from the first output word.
    2. Undo linear diffusion: DeltaB = L-inverse(DeltaX35).
    3. Keep a if S(a) XOR S(a XOR e) matches the observed byte difference.
    4. Convert a into a key guess using the three unchanged output words.
    """
    aes.validate_block(correct, "Correct ciphertext")
    aes.validate_block(faulty, "Faulty ciphertext")
    if known_mask is not None:
        validate_mask(known_mask)

    # SM4 outputs X35 || X34 || X33 || X32; only X35 may change in this model.
    if correct[4:] != faulty[4:]:
        raise ValueError("SM4 last-round model requires three output words unchanged.")
    delta_x35 = int.from_bytes(correct[:4], "big") ^ int.from_bytes(faulty[:4], "big")
    delta_b = inverse_linear(delta_x35)
    differences = delta_b.to_bytes(4, "big")
    changed = [index for index in range(4) if differences[index] != 0]
    if len(changed) != 1:
        raise ValueError("SM4 inverse-L difference must affect one S-box byte.")
    position = changed[0]
    allowed = SINGLE_BITS if known_mask is None else (known_mask,)

    # The input value a is unknown. Test every value against each permitted bit.
    inputs = set()
    for guess in range(256):
        for error in allowed:
            difference = sm4.SBOX[guess] ^ sm4.SBOX[guess ^ error]
            if difference == differences[position]:
                inputs.add(guess)
                break

    # A = X32 XOR X33 XOR X34 XOR rk31; all three data words are observable.
    x34 = int.from_bytes(correct[4:8], "big")
    x33 = int.from_bytes(correct[8:12], "big")
    x32 = int.from_bytes(correct[12:16], "big")
    known_byte = ((x32 ^ x33 ^ x34) >> (24 - 8 * position)) & 0xFF
    candidates = {guess ^ known_byte for guess in inputs}
    return position, candidates, inputs, delta_b


def intersect_candidates(previous, current):
    """Keep only key-byte values compatible with every observation so far.

    None marks the first observation. Multiple survivors mean ambiguity;
    exactly one means the byte is recovered. Never choose an arbitrary value.
    """
    survivors = set(current) if previous is None else previous & current
    if not survivors:
        raise ValueError("No compatible Giraud candidates; check the fault model.")
    return survivors


def recover_byte(algorithm, observations):
    """Recover one byte from (correct, faulty[, known_mask]) observations.

    All observations must concern the same output/subkey byte and target key.
    Return (position, survivors). No observations returns (None, None).
    This helper does not read configuration, simulate faults or display results.
    """
    if algorithm not in ("AES-128", "SM4"):
        raise ValueError("Choose AES-128 or SM4.")
    candidate_function = aes_candidates if algorithm == "AES-128" else sm4_candidates
    position, survivors = None, None
    for observation in observations:
        current_position, current = candidate_function(*observation)[:2]
        if position is not None and current_position != position:
            raise ValueError("Observations must affect the same key byte.")
        position = current_position
        survivors = intersect_candidates(survivors, current)
    return position, survivors


def main(argv=None):
    """Demonstrate candidate filtering on the keys configured in aes.py/sm4.py.

    Simulation knows the target key. The candidate functions above receive
    ciphertexts and, only with --known-bit, the exact injected mask.
    """
    import argparse
    import piret
    import run as target

    parser = argparse.ArgumentParser(description="Giraud AES attack and SM4 single-bit adaptation.")
    parser.add_argument("--algorithm", choices=("all", "aes", "sm4"), default="all")
    parser.add_argument("--known-bit", action="store_true", help="Share the exact bit mask with the solver.")
    parser.add_argument("--observations", type=int, default=8, help="Maximum distinct faults per byte, 1..8.")
    parser.add_argument("--step", action="store_true", help="Pause after each observation.")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    args = parser.parse_args(argv)
    try:
        masks = masks_for(1, args.observations)
        for module in (aes, sm4):
            target.block(module.KEY)
            target.block(module.PLAINTEXT)
    except ValueError as error:
        parser.error(str(error))
    terminal = target.LessonTerminal(args.color, args.step)
    success = True

    for algorithm, module in (("aes", aes), ("sm4", sm4)):
        if args.algorithm not in ("all", algorithm):
            continue
        key, plaintext = target.block(module.KEY), target.block(module.PLAINTEXT)
        is_aes = algorithm == "aes"
        size = 16 if is_aes else 4
        recovered, unique, used = bytearray(size), True, 0
        if is_aes:
            correct = aes.aes_encrypt(plaintext, key)
            if correct != piret.aes_target_encrypt(plaintext, key):
                raise RuntimeError("AES simulation does not match aes.py.")
        else:
            correct = sm4.sm4_encrypt_block(plaintext, key)
        terminal.section("GIRAUD / AES-128" if is_aes else "GIRAUD-INSPIRED / SM4")
        print("Correct ciphertext: " + correct.hex().upper())
        print("Bit known to solver: " + str(args.known_bit))
        print("AES: require HW(InvSbox[C XOR k] XOR InvSbox[F XOR k]) = 1." if is_aes else "SM4: invert L, then test S(a) XOR S(a XOR e) for one-bit errors.")

        if not is_aes:
            def oracle(number, byte, mask):
                return sm4_fault_encrypt(plaintext, key, byte, mask, number)[0]

            def show(event):
                print(f"\nRound {event['round']}, key byte {event['byte']}, observation {event['observation']}")
                terminal.pair(bytes.fromhex(event['correct']), bytes.fromhex(event['faulty']))
                print("Undo recovered later rounds: " + str(event['peeled_with']))
                terminal.pair(bytes.fromhex(event['clean_view']), bytes.fromhex(event['faulty_view']))
                print(f"Candidates: {event['before']} -> {event['remaining']}")
                terminal.pause()

            result = recover_sm4_master_key(correct, oracle, maximum=args.observations, known_bit=args.known_bit, observer=show)
            if not result['complete']:
                success = False
                print("Ambiguous SM4 recovery. Increase --observations; no master key is claimed.")
                continue
            for number, value in result['round_keys'].items():
                print(f"Recovered rk{number}: {value:08X}")
            master = result['master_key']
            if master != key or sm4.sm4_encrypt_block(plaintext, master) != correct:
                raise RuntimeError("SM4 full master-key verification failed.")
            print("Recovered master key: " + terminal.paint(master.hex().upper(), "32"))
            print(terminal.paint(f"Verification: PASS / {result['used']} faulty outputs / no reference subkeys", "32"))
            continue

        for byte in range(size):
            survivors = None
            for observation, mask in enumerate(masks, 1):
                faulty = aes_fault_encrypt(plaintext, key, byte, mask)[0]
                position, fresh = aes_candidates(correct, faulty, mask if args.known_bit else None)
                used += 1
                before = 256 if survivors is None else len(survivors)
                survivors = intersect_candidates(survivors, fresh)
                print(f"\nKey byte {position}, observation {observation}, simulator mask {mask:02X}")
                terminal.pair(correct, faulty)
                print(f"Candidate count: {before} -> {len(survivors)}")
                print("Survivors: " + " ".join(f"{value:02X}" for value in sorted(survivors)))
                terminal.pause()
                if len(survivors) == 1:
                    recovered[position] = next(iter(survivors))
                    break
            else:
                unique = False
                print("Ambiguous byte. Increase --observations; no value is selected.")
        if not unique:
            success = False
            print("Recovery incomplete: a unique key is not claimed.")
            continue
        master = piret.reverse_key_schedule(recovered)
        if master != key or piret.aes_target_encrypt(plaintext, master) != correct:
            raise RuntimeError("AES key verification failed.")
        print("\nRecovered K10: " + recovered.hex().upper())
        print("Recovered master key: " + terminal.paint(master.hex().upper(), "32"))
        print(terminal.paint(f"Verification: PASS / {used} faulty outputs", "32"))
    return 0 if success else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EOFError, KeyboardInterrupt):
        print("\nLesson stopped.")

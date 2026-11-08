"""Shared Giraud terminal presentation; algorithm calculations stay in their modules."""
import aes
import sm4
from giraud_common import SINGLE_BITS, masks_for, intersect_candidates
from giraud_aes import AES_INVERSE_SBOX, aes_fault_encrypt, aes_candidates
from giraud_sm4 import sm4_fault_encrypt, recover_sm4_master_key


def main(selected_algorithm, argv=None):
    """Demonstrate candidate filtering on the keys configured in aes.py/sm4.py.

    Simulation knows the target key. The candidate functions above receive
    ciphertexts and, only with --known-bit, the exact injected mask.
    """
    import argparse
    import piret_aes
    import run as target

    parser = argparse.ArgumentParser(description="Giraud AES attack and SM4 single-bit adaptation.")
    parser.add_argument("--algorithm", choices=(selected_algorithm,), default=selected_algorithm)
    parser.add_argument("--known-bit", action="store_true", help="Share the exact bit mask with the solver.")
    parser.add_argument("--observations", type=int, default=8, help="Maximum distinct faults per byte, 1..8.")
    parser.add_argument("--step", action="store_true", help="Pause after each observation.")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    args = parser.parse_args(argv)
    try:
        masks = masks_for(1, args.observations)
        for module in ((aes,) if selected_algorithm == "aes" else (sm4,)):
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
            _, clean_trace = aes_fault_encrypt(plaintext, key)
            if correct != piret_aes.aes_target_encrypt(plaintext, key):
                raise RuntimeError("AES simulation does not match aes.py.")
        else:
            correct = sm4.sm4_encrypt_block(plaintext, key)
        terminal.section("GIRAUD / AES-128" if is_aes else "GIRAUD-INSPIRED / SM4")
        print("Correct ciphertext: " + correct.hex().upper())
        print("Bit known to solver: " + str(args.known_bit))
        print("AES: require HW(InvSbox[C XOR k] XOR InvSbox[F XOR k]) = 1." if is_aes else "SM4: invert L, then test S(a) XOR S(a XOR e) for one-bit errors.")

        if not is_aes:
            recovered_bytes = {}
            _, clean_target_trace = sm4_fault_encrypt(plaintext, key)

            def oracle(number, byte, mask):
                faulty, fault_trace = sm4_fault_encrypt(plaintext, key, byte, mask, number)
                target.attack_steps.emit(terminal, target.attack_steps.sm4_fault_trace(clean_target_trace, fault_trace, number, byte, mask))
                return faulty

            def show(event):
                target.show_sm4_observation(terminal, event, recovered_bytes, known_bit=args.known_bit)

            result = recover_sm4_master_key(correct, oracle, maximum=args.observations, known_bit=args.known_bit, observer=show)
            if not result['complete']:
                success = False
                print("Ambiguous SM4 recovery. Increase --observations; no master key is claimed.")
                continue
            for number, value in result['round_keys'].items():
                print(f"Recovered rk{number}: {value:08X}")
            master = target.show_sm4_key_schedule(terminal, result['round_keys'])
            target.attack_steps.emit(terminal, target.attack_steps.verification("sm4", plaintext, master, correct))
            verified_ciphertext = sm4.sm4_encrypt_block(plaintext, master)
            if master != result['master_key'] or master != key or verified_ciphertext != correct:
                raise RuntimeError("SM4 full master-key verification failed.")
            terminal.section("GIRAUD-INSPIRED SM4: VERIFY THE RECOVERED MASTER KEY")
            print("Plaintext:                " + plaintext.hex().upper())
            print("Expected ciphertext:      " + correct.hex().upper())
            print("Recovered-key ciphertext: " + verified_ciphertext.hex().upper())
            print("Recovered master key: " + terminal.paint(master.hex().upper(), "32"))
            print(terminal.paint(f"Verification: PASS / {result['used']} faulty outputs / no reference subkeys", "32"))
            continue

        for byte in range(size):
            survivors = None
            for observation, mask in enumerate(masks, 1):
                faulty, fault_trace = aes_fault_encrypt(plaintext, key, byte, mask)
                position, fresh = aes_candidates(correct, faulty, mask if args.known_bit else None)
                used += 1
                before = 256 if survivors is None else len(survivors)
                target.attack_steps.emit(terminal, target.attack_steps.aes_giraud(correct, faulty, position, survivors, mask if args.known_bit else None))
                survivors = intersect_candidates(survivors, fresh)
                print(f"\nKey byte {position}, observation {observation}, simulator mask {mask:02X}")
                print(f"Fault before final SubBytes: input byte {byte}, row {byte%4}, column {byte//4} -> ciphertext/K10 byte {position} after ShiftRows.")
                for operation, state in fault_trace.items():
                    print("Final-round stage: " + operation)
                    terminal.pair(clean_trace[operation], state)
                allowed = (mask,) if args.known_bit else SINGLE_BITS
                print("Allowed input errors: " + " ".join(f"{value:02X}" for value in allowed))
                print("The simulator mask is NOT given to the candidate solver." if not args.known_bit else "The candidate solver receives the exact mask.")
                terminal.pair(correct, faulty)
                print("For every guess k=00..FF, undo final key XOR and SubBytes on BOTH outputs.")
                print(f"Rejected guesses: {256-len(fresh)}; compatible guesses from this pair: {len(fresh)}")
                for guess in sorted(fresh):
                    clean_input = AES_INVERSE_SBOX[correct[position] ^ guess]
                    faulty_input = AES_INVERSE_SBOX[faulty[position] ^ guess]
                    delta = clean_input ^ faulty_input
                    print(f"  k={guess:02X}: InvSbox[{correct[position]:02X} XOR {guess:02X}] XOR InvSbox[{faulty[position]:02X} XOR {guess:02X}] = {clean_input:02X} XOR {faulty_input:02X} = {delta:02X}; HW={bin(delta).count('1')} / ACCEPT")
                print(f"Candidate count: {before} -> {len(survivors)}")
                print("Survivors: " + " ".join(f"{value:02X}" for value in sorted(survivors)))
                terminal.pause()
                if len(survivors) == 1:
                    recovered[position] = next(iter(survivors))
                    print(terminal.paint(f"RECOVERED K10 byte {position} = {recovered[position]:02X} / UNIQUE", "32"))
                    break
            else:
                unique = False
                print("Ambiguous byte. Increase --observations; no value is selected.")
        if not unique:
            success = False
            print("Recovery incomplete: a unique key is not claimed.")
            continue
        print("\nAssemble K10 in ciphertext byte order: " + " || ".join(f"{value:02X}" for value in recovered))
        master = target.show_aes_key_schedule(terminal, recovered)
        target.attack_steps.emit(terminal, target.attack_steps.verification("aes", plaintext, master, correct))
        verified_ciphertext = piret_aes.aes_target_encrypt(plaintext, master)
        if master != key or verified_ciphertext != correct:
            raise RuntimeError("AES key verification failed.")
        terminal.section("GIRAUD AES: VERIFY THE RECOVERED MASTER KEY")
        print("Plaintext:                " + plaintext.hex().upper())
        print("Expected ciphertext:      " + correct.hex().upper())
        print("Recovered-key ciphertext: " + verified_ciphertext.hex().upper())
        print("\nRecovered K10: " + recovered.hex().upper())
        print("Recovered master key: " + terminal.paint(master.hex().upper(), "32"))
        print(terminal.paint(f"Verification: PASS / {used} faulty outputs", "32"))
    return 0 if success else 2


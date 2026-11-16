"""Verify last-round SM4 fault equations and show a nonlinear counterexample."""
import argparse
import struct

import piret_sm4
import sm4
from terminal_log import run_with_log


def inverse_sbox_word(value):
    """Undo tau on each byte separately, preserving big-endian byte order."""
    inverse = [0] * 256

    for input_byte, output_byte in enumerate(sm4.SBOX):
        inverse[output_byte] = input_byte

    output = 0

    for shift in (24, 16, 8, 0):
        byte = (value >> shift) & 255
        output |= inverse[byte] << shift

    return output


def capture(plaintext, key, error):
    """Use the real cipher; emulate a transient rk-wire XOR at the final XOR."""
    trace = {}

    def observer(number, operation, value):
        if number == 31:
            if operation == "Sbox input":
                # (W1 XOR W2 XOR W3 XOR rk) XOR E equals using rk XOR E.
                # The stored key schedule is not permanently changed.
                value ^= error

            trace[operation] = value

        return value

    ciphertext = sm4.sm4_encrypt_block(plaintext, key, observer=observer)
    return ciphertext, trace


def calculate(plaintext, key, byte=0, mask=3):
    """Check identities with teacher states and separate observable quantities."""
    if len(plaintext) != 16 or len(key) != 16:
        raise ValueError("Use one 16-byte plaintext and one 16-byte key.")

    if not 0 <= byte < 4 or not 1 <= mask <= 255:
        raise ValueError("Byte must be 0..3 and mask must be 01..FF.")

    error = mask << (24 - 8 * byte)
    correct, clean_trace = capture(plaintext, key, 0)
    faulty, fault_trace = capture(plaintext, key, error)
    c = struct.unpack(">4I", correct)
    f = struct.unpack(">4I", faulty)
    w0, w1, w2, w3 = clean_trace["State input"]
    rk = sm4.key_expansion(key)[31]
    a_correct = clean_trace["Sbox input"]
    a_faulty = fault_trace["Sbox input"]
    b_correct = clean_trace["Sbox output"]
    b_faulty = fault_trace["Sbox output"]
    q = c[1] ^ c[2] ^ c[3]
    delta_x = c[0] ^ f[0]
    delta_b = piret_sm4.inverse_linear(delta_x)
    inverse_difference = inverse_sbox_word(delta_b)

    # These checks establish the same last-round input state and untouched words.
    assert fault_trace["State input"] == clean_trace["State input"]
    assert c[1:] == f[1:]
    assert (c[3], c[2], c[1]) == (w1, w2, w3)
    assert q == w1 ^ w2 ^ w3
    assert a_correct == q ^ rk
    assert a_faulty == q ^ rk ^ error
    assert c[0] == w0 ^ sm4.linear(b_correct)
    assert f[0] == w0 ^ sm4.linear(b_faulty)

    # L is linear: the unchanged W0 cancels, so inverse L recovers a DIFFERENCE.
    assert delta_b == b_faulty ^ b_correct
    assert sm4.linear(delta_b) == delta_x

    # Correct recovery equations use each individual B, not inverse_tau(DeltaB).
    # These values are available here only because this is an instrumented target.
    faulty_input = inverse_sbox_word(b_faulty)
    clean_input = inverse_sbox_word(b_correct)
    faulty_round_key = faulty_input ^ q
    recovered_round_key = faulty_round_key ^ error
    clean_round_key = clean_input ^ q

    # Individual B values can be inverted; inverse tau is not XOR-linear.
    assert inverse_sbox_word(b_correct) == a_correct
    assert inverse_sbox_word(b_faulty) == a_faulty
    assert inverse_sbox_word(b_faulty) ^ inverse_sbox_word(b_correct) == error
    assert inverse_sbox_word(b_faulty) ^ q == rk ^ error
    assert inverse_sbox_word(b_faulty) ^ q ^ error == rk
    assert inverse_sbox_word(b_correct) ^ q == rk
    assert faulty_round_key == rk ^ error
    assert recovered_round_key == clean_round_key == rk

    # Individual B values require hidden W0, unlike the observable difference.
    assert piret_sm4.inverse_linear(c[0] ^ w0) == b_correct
    assert piret_sm4.inverse_linear(f[0] ^ w0) == b_faulty

    # Output-only DFA still has to enumerate and intersect compatible guesses.
    candidates, inputs, unused_delta = piret_sm4.sm4_byte_candidates(correct, faulty, byte, mask)
    expected_byte = (rk >> (24 - 8 * byte)) & 255
    assert expected_byte in candidates
    return dict(correct=correct, faulty=faulty, w0=w0, w1=w1, w2=w2, w3=w3, rk=rk, error=error, a_correct=a_correct, a_faulty=a_faulty, b_correct=b_correct, b_faulty=b_faulty, q=q, delta_x=delta_x, delta_b=delta_b, inverse_difference=inverse_difference, candidates=candidates, inputs=inputs, teacher_faulty_round_key=faulty_round_key, teacher_recovered_round_key=recovered_round_key, teacher_clean_round_key=clean_round_key)


def print_colored(text=""):
    """Emit ANSI colors that the shared logger also renders in its HTML file."""
    stripped = text.strip()
    color = "37"

    if "/ PASS" in text or text.startswith("All asserted equations passed"):
        color = "32"
    elif "-> False" in text or text.startswith("This proposed equality") or text.startswith("The XOR of B values cannot"):
        color = "31"
    elif stripped.startswith(("SM4 ROUND", "DIAGRAM MAPPING", "1.", "2.", "3.", "4.", "5.", "6.")):
        color = "1;36"
    elif "hidden" in text or text.startswith("Teacher states") or text.startswith("This is DeltaB"):
        color = "33"
    elif text.startswith(("Faulty ciphertext:", "A_faulty", "B_faulty  ")):
        color = "31"
    elif text.startswith("Key-byte candidates"):
        color = "35"

    print(f"\033[{color}m{text}\033[0m")


def show_linear_calculation(label, value):
    """Expand every rotation and XOR in the public SM4 data map L."""
    print_colored(f"\n{label}: input = {value:08X}")
    result = value

    for rotation in (2, 10, 18, 24):
        high = (value << rotation) & 0xFFFFFFFF
        wrap = value >> (32 - rotation)
        rotated = high | wrap
        print_colored(f"ROL_{rotation}({value:08X}) = (({value:08X} << {rotation}) AND FFFFFFFF) OR ({value:08X} >> {32 - rotation})")
        print_colored(f"                  = {high:08X} OR {wrap:08X} = {rotated:08X}")
        before = result
        result ^= rotated
        print_colored(f"Running XOR       = {before:08X} XOR {rotated:08X} = {result:08X}")

    assert result == sm4.linear(value)
    print_colored(f"{label} = {result:08X} / PASS")
    return result


def show_inverse_calculation(value):
    """Expand an equivalent inverse formula and check the matrix implementation."""
    print_colored("\nNUMERICAL INVERSE: L^-1(y) = ROR_8(L(L(L(y))))")
    print_colored("This is an equivalent evaluation route: L^4(x)=ROL_8(x). The matrix routine returns the same inverse.")
    result = value

    for application in range(1, 4):
        result = show_linear_calculation(f"Inverse calculation, L application {application}", result)

    before = result
    right = before >> 8
    wrap = (before << 24) & 0xFFFFFFFF
    result = right | wrap
    print_colored(f"ROR_8({before:08X}) = ({before:08X} >> 8) OR (({before:08X} << 24) AND FFFFFFFF)")
    print_colored(f"                  = {right:08X} OR {wrap:08X} = {result:08X}")
    assert result == piret_sm4.inverse_linear(value)
    print_colored(f"L^-1({value:08X}) = {result:08X} / PASS (agrees with the matrix inverse)")
    return result


def show(data, show_counterexample=False):
    """Present correct identities first; invalid expressions are optional examples."""
    # All lesson lines use the same coloring in the terminal and saved HTML.
    print = print_colored
    d = data
    print("SM4 ROUND 31: CONTROLLED EFFECTIVE ROUND-KEY FAULT")
    print("E is a 32-bit XOR mask, positioned in the selected byte.")
    print("Teacher states are shown for verification; they are not public solver inputs.\n")
    print(f"Correct ciphertext: {d['correct'].hex().upper()}")
    print(f"Faulty ciphertext:  {d['faulty'].hex().upper()}")
    print(f"rk31 = {d['rk']:08X}; E = {d['error']:08X}; effective faulty rk = {d['rk'] ^ d['error']:08X}")
    print("\nDIAGRAM MAPPING (each R is a 32-bit word)")
    print(f"W0 = X31 = {d['w0']:08X}  (hidden older word)")
    print(f"R0 = W3 = X34 = {d['w3']:08X}")
    print(f"R1 = W2 = X33 = {d['w2']:08X}")
    print(f"R2 = W1 = X32 = {d['w1']:08X}")
    print(f"Q = R2 XOR R1 XOR R0 = {d['q']:08X}")
    print("\n1. THE REAL S-BOX INPUT AND OUTPUT")
    print(f"A_correct = Q XOR rk = {d['q']:08X} XOR {d['rk']:08X} = {d['a_correct']:08X}")
    print(f"A_faulty  = A_correct XOR E = {d['a_correct']:08X} XOR {d['error']:08X} = {d['a_faulty']:08X}")
    print(f"B_correct = tau(A_correct) = {d['b_correct']:08X}")
    print(f"B_faulty  = tau(A_faulty)  = {d['b_faulty']:08X}")
    print("\n2. WHAT INVERSE L ACTUALLY RECOVERS")
    linear_correct = show_linear_calculation("L(B_correct)", d["b_correct"])
    linear_faulty = show_linear_calculation("L(B_faulty)", d["b_faulty"])
    print(f"\nR3_correct = W0 XOR L(B_correct) = {d['w0']:08X} XOR {linear_correct:08X} = {int.from_bytes(d['correct'][:4], 'big'):08X}")
    print(f"R3_faulty  = W0 XOR L(B_faulty)  = {d['w0']:08X} XOR {linear_faulty:08X} = {int.from_bytes(d['faulty'][:4], 'big'):08X}")
    print("R3_faulty XOR R3_correct = (W0 XOR L(B_faulty)) XOR (W0 XOR L(B_correct))")
    print(f"Regroup: ({d['w0']:08X} XOR {d['w0']:08X}) XOR {linear_faulty:08X} XOR {linear_correct:08X}")
    print(f"       = 00000000 XOR {linear_faulty:08X} XOR {linear_correct:08X}")
    print("= L(B_faulty) XOR L(B_correct) = L(B_faulty XOR B_correct)")
    c = int.from_bytes(d["correct"][:4], "big")
    f = int.from_bytes(d["faulty"][:4], "big")
    print(f"DeltaX = R3_faulty XOR R3_correct = {f:08X} XOR {c:08X} = {d['delta_x']:08X}")
    show_inverse_calculation(d["delta_x"])
    print(f"L^-1(DeltaX) = {d['delta_b']:08X}")
    print(f"B_faulty XOR B_correct = {d['b_faulty']:08X} XOR {d['b_correct']:08X} = {d['delta_b']:08X} / PASS")
    print("Byte-by-byte verification of DeltaB:")

    for shift in (24, 16, 8, 0):
        faulty_byte = (d["b_faulty"] >> shift) & 255
        correct_byte = (d["b_correct"] >> shift) & 255
        print(f"  {faulty_byte:02X} XOR {correct_byte:02X} = {faulty_byte ^ correct_byte:02X}")

    forward_check = show_linear_calculation("Forward check L(DeltaB)", d["delta_b"])
    assert forward_check == d["delta_x"]
    print("This is DeltaB, not B_correct. W0 cancels because it is unchanged.")
    print("Use only the changing 32-bit R3 word; L^-1 acts on 32 bits, not the whole 128-bit ciphertext.")
    print("\n3. INVERT EACH INDIVIDUAL S-BOX OUTPUT, THEN XOR")
    print(f"tau^-1(B_faulty)  = tau^-1({d['b_faulty']:08X}) = {d['a_faulty']:08X}")
    print(f"tau^-1(B_correct) = tau^-1({d['b_correct']:08X}) = {d['a_correct']:08X}")
    print(f"tau^-1(B_faulty) XOR tau^-1(B_correct) = {d['a_faulty']:08X} XOR {d['a_correct']:08X} = {d['error']:08X} / PASS")
    print("The inverse is applied BEFORE the XOR. This check requires the two individual B values.")
    print("\n4. THE CORRECT KEY EQUATIONS, IF INDIVIDUAL B VALUES ARE AVAILABLE")
    faulty_input = inverse_sbox_word(d["b_faulty"])
    print(f"tau^-1(B_faulty) XOR R2 XOR R1 XOR R0")
    print(f"= {faulty_input:08X} XOR {d['w1']:08X} XOR {d['w2']:08X} XOR {d['w3']:08X}")
    print(f"= {d['teacher_faulty_round_key']:08X} = rk XOR E / PASS")
    print(f"Alternatively tau^-1(B_correct) XOR Q = {d['a_correct']:08X} XOR {d['q']:08X} = {d['teacher_clean_round_key']:08X} / PASS")
    print("\n5. CORRECT FINAL EXPRESSION: REMOVE THE FAULT MASK")
    print("rk = tau^-1(B_faulty) XOR R2 XOR R1 XOR R0 XOR E")
    print(f"   = {faulty_input:08X} XOR {d['w1']:08X} XOR {d['w2']:08X} XOR {d['w3']:08X} XOR {d['error']:08X}")
    print(f"   = {d['teacher_faulty_round_key']:08X} XOR {d['error']:08X}")
    print(f"   = {d['teacher_recovered_round_key']:08X} / PASS")
    print(f"Reference rk used only for validation: {d['rk']:08X}")
    print("This direct equation uses teacher-only B_faulty; it is not ciphertext-only key recovery.")
    print("\n6. WHY THE CIPHERTEXT-ONLY ATTACK STILL NEEDS DFA")
    print(f"B_correct = L^-1(R3_correct XOR hidden W0) = {d['b_correct']:08X}")
    print("W0 is hidden, so ciphertexts alone provide DeltaB, not the individual B values used in step 4.")
    print("For each byte, solve S(a) XOR S(a XOR e) = delta_b and intersect observations.")
    labels = []

    for value in sorted(d["candidates"]):
        labels.append(f"{value:02X}")

    print("Key-byte candidates from this one public pair: " + " ".join(labels))
    print("All asserted equations passed. The correct direct key equation uses individual B; public DFA uses candidate intersections.")

    if show_counterexample:
        # Retain the old expression only behind an explicit educational option.
        wrong = d["inverse_difference"] ^ d["q"]
        print("\nOPTIONAL COUNTEREXAMPLE: NOT A VALID KEY-RECOVERY FORMULA")
        print(f"tau^-1(DeltaB) = {d['inverse_difference']:08X}")
        print(f"tau^-1(DeltaB) XOR Q = {wrong:08X}")
        print(f"Claim tau^-1(DeltaB) == rk XOR E -> {d['inverse_difference'] == d['teacher_faulty_round_key']}")
        print("This proposed equality is not an identity; inverse tau is nonlinear.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mask", default="01", help="Nonzero hexadecimal byte error, default %(default)s.")
    parser.add_argument("--byte", type=int, choices=range(4), default=0)
    parser.add_argument("--show-counterexample", action="store_true", help="Also display the old, invalid inverse-of-XOR expression as a counterexample.")
    args = parser.parse_args(argv)

    try:
        mask = int(args.mask, 16)
        key = bytes.fromhex(sm4.KEY)
        plaintext = bytes.fromhex(sm4.PLAINTEXT)
        data = calculate(plaintext, key, args.byte, mask)
    except ValueError as error:
        parser.error(str(error))

    show(data, args.show_counterexample)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_with_log(main, "prove_sm4_round31"))

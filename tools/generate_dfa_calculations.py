"""Generate complete numerical SM4 inverse-diffusion and schedule calculations."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import sm4
import piret_sm4


def table(lines, headings, rows, columns):
    """Keep long numerical tables readable over page breaks."""
    lines.extend([r"\begingroup\small", r"\begin{longtable}{" + columns + "}", r"\toprule", " & ".join(headings) + r"\\\midrule", r"\endhead"])

    for row in rows:
        values = []

        for value in row:
            values.append(str(value))

        lines.append(" & ".join(values) + r"\\")

    lines.extend([r"\bottomrule\end{longtable}", r"\endgroup"])


def generate():
    lines = [r"\chapter{SM4 DFA: Complete Numerical Calculations}", r"\label{chap:complete_calculations}", r"This chapter expands the calculations behind the preceding example. All 32 basis vectors, every Gaussian-elimination row operation, all 32 inverse-output bits, all 256 byte-input tests, and all 32 reverse key-schedule steps are printed. Values are generated from the public SM4 functions and checked before publication. Bit index 0 means the least significant bit; byte index 0 means the most significant byte. These conventions differ intentionally.", r"\section{Why inverse diffusion is necessary}", r"For an isolated fault at a last-round S-box input, the older word cancels in the ciphertext difference:", r"\[\Delta X_{35}=L(B)\xor L(B')=L(B\xor B')=L(\Delta B).\]", r"The equality uses linearity over GF(2), where addition is XOR. Consequently the attacker computes $\Delta B=L^{-1}(\Delta X_{35})$; this does not require the secret key.", r"\section{Forward diffusion: every rotation and XOR}"]
    b = 0x4F000000
    running = b
    lines.append(r"\begin{align*}B&=\hex{4F000000}\\")

    for rotation in (2, 10, 18, 24):
        rotated = sm4.rotl(b, rotation)
        previous = running
        running ^= rotated
        lines.append(r"\operatorname{ROL}_{" + str(rotation) + r"}(B)&=\hex{" + f"{rotated:08X}" + r"},\\")
        lines.append(r"\text{running XOR}&=\hex{" + f"{previous:08X}" + r"}\xor\hex{" + f"{rotated:08X}" + r"}=\hex{" + f"{running:08X}" + r"}\\")

    lines.extend([r"\end{align*}", r"Thus the observed word difference is $\hex{734E3D3D}$, even though the S-box difference affects only one byte.", r"\section{Construct the binary matrix of L}", r"Let $v_i=2^i$ be a 32-bit word with only bit $i$ set. Column $i$ of $M$ is the bit vector of $L(v_i)$, because $L$ is linear. Thus $M_{r,i}=(L(2^i)\gg r)\mathbin{\&}1$. Every column is shown below."])
    columns = []
    rows_for_table = []

    for bit in range(32):
        transformed = sm4.linear(1 << bit)
        columns.append(transformed)
        rows_for_table.append([bit, f"{1 << bit:08X}", f"{transformed:08X}"])

    table(lines, ["Bit $i$", "$v_i$ (hex)", "$L(v_i)$ (hex)"], rows_for_table, "rll")
    matrix = []
    initial = []

    for row in range(32):
        word = 0

        for column in range(32):
            word |= ((columns[column] >> row) & 1) << column

        matrix.append(word | (1 << (32 + row)))
        initial.append([row, f"{word:08X}", f"{1 << row:08X}"])

    lines.extend([r"\section{Invert the matrix: every elementary operation}", r"The following table gives every row of the augmented matrix $[M\mid I]$. Hexadecimal compresses 32 binary entries without omitting them: the least significant bit represents column 0. In the implementation the low 32 bits store the left half and the high 32 bits store the right half."])
    table(lines, ["Row", "Left $M$ (hex)", "Right $I$ (hex)"], initial, "rll")
    operations = []

    for column in range(32):
        pivot = None

        for candidate in range(column, 32):
            if (matrix[candidate] >> column) & 1:
                pivot = candidate
                break

        if pivot is None:
            raise ValueError("Public SM4 L is unexpectedly singular.")

        matrix[column], matrix[pivot] = matrix[pivot], matrix[column]
        operations.append([column, f"swap {column},{pivot}", "--", "--", "--"])

        for row in range(32):
            if row != column and ((matrix[row] >> column) & 1):
                before = matrix[row]
                operand = matrix[column]
                matrix[row] ^= operand
                operations.append([column, f"R{row} XOR R{column}", f"{before:016X}", f"{operand:016X}", f"{matrix[row]:016X}"])

    lines.append(r"Each XOR row below prints the complete 64-bit packed augmented row before the operation, its pivot operand and its result. A swap with equal indices is a no-op. No pivot or elimination operation is skipped; XOR replaces subtraction and no division is needed in GF(2).")
    table(lines, ["Pivot", "Operation", "Before", "Operand", "After"], operations, "rllll")
    inverses = []
    final_rows = []

    for index in range(32):
        if matrix[index] & 0xFFFFFFFF != 1 << index:
            raise ValueError("Gaussian elimination did not produce the identity.")

        inverse = matrix[index] >> 32
        inverses.append(inverse)
        final_rows.append([index, f"{matrix[index] & 0xFFFFFFFF:08X}", f"{inverse:08X}"])

    if tuple(inverses) != piret_sm4.inverse_rows():
        raise ValueError("Printed inverse differs from the attack implementation.")

    lines.append(r"The final matrix is $[I\mid M^{-1}]$. These are its complete rows:")
    table(lines, ["Row", "Left $I$", "Right $M^{-1}$"], final_rows, "rll")
    lines.extend([r"\section{Apply the inverse: all 32 output-bit calculations}", r"For $d=\hex{734E3D3D}$ and inverse row $r_j$, compute $t_j=r_j\mathbin{\&}d$, count its set bits, and retain the parity. This is the binary dot product: $b_j=\bigoplus_i(M^{-1})_{j,i}d_i$. Then assemble $B=\bigvee_j(b_j\ll j)$. The AND selects participating bits, parity performs their XOR, and OR assembles distinct output positions."])
    application = []
    result = 0

    for index, row in enumerate(inverses):
        selected = row & 0x734E3D3D
        count = selected.bit_count()
        parity = count & 1
        result |= parity << index
        application.append([index, f"{row:08X}", f"{selected:08X}", count, parity, f"{result:08X}"])

    assert result == 0x4F000000
    assert sm4.linear(result) == 0x734E3D3D
    table(lines, ["Bit", "Inverse row", "Selected bits", "Count", "Parity", "Running result"], application, "rllrrl")
    lines.extend([r"Hence $L^{-1}(\hex{734E3D3D})=\hex{4F000000}$. Applying the forward rotation/XOR calculation above returns the observed difference, which independently checks the inversion.", r"\section{Every candidate test for the first key byte}", r"The unchanged words give $q=\operatorname{byte}_0(\hex{D206965E}\xor\hex{86B3E94F}\xor\hex{536E4246})=\hex{07}$. For each input $a$, the corresponding key guess is $k=a\xor q$. The first observation requires $D_1=S(a)\xor S(a\xor\hex{01})=\hex{4F}$; the second requires $D_2=S(a)\xor S(a\xor\hex{02})=\hex{81}$. Both columns are computed for every input below; acceptance requires both equalities."])
    candidates = []
    accepted = []

    for a in range(256):
        first = sm4.SBOX[a] ^ sm4.SBOX[a ^ 1]
        second = sm4.SBOX[a] ^ sm4.SBOX[a ^ 2]
        status = "reject"

        if first == 0x4F and second == 0x81:
            status = "KEEP"
            accepted.append(a ^ 7)

        candidates.append([f"{a:02X}", f"{sm4.SBOX[a]:02X}", f"{sm4.SBOX[a ^ 1]:02X}", f"{first:02X}", f"{sm4.SBOX[a ^ 2]:02X}", f"{second:02X}", f"{a ^ 7:02X}", status])

    assert accepted == [0x91]
    table(lines, ["$a$", "$S(a)$", r"$S(a\xor01)$", "$D_1$", r"$S(a\xor02)$", "$D_2$", "$k$", "Both tests"], candidates, "llllllll")
    lines.extend([r"\section{Recover all four tail subkeys from actual observations}", r"The following computation runs the real ciphertext-only recovery engine on the public vector. Each byte uses masks 01 then 02. Tables print every queried pair, inverse difference, S-box input set, and surviving key-byte intersection. Values of the secret key are supplied only to the simulated target; no reference subkey is supplied to the solver."])
    public = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    correct = sm4.sm4_encrypt_block(public, public)

    def oracle(number, byte, mask):
        faulty, trace = piret_sm4.sm4_fault_encrypt(public, public, byte, mask, number)
        return faulty

    recovery = piret_sm4.recover_sm4_master_key(correct, oracle, masks=(1, 2))
    assert recovery["complete"] and recovery["used"] == 32

    for number in range(31, 27, -1):
        lines.append(r"\subsection*{Recover $rk_{" + str(number) + r"}$}")

        for event in recovery["history"]:
            if event["round"] != number:
                continue

            view = bytes.fromhex(event["clean_view"])
            faulty_view = bytes.fromhex(event["faulty_view"])
            c_words = []

            for offset in range(0, 16, 4):
                c_words.append(int.from_bytes(view[offset:offset + 4], "big"))

            q_word = c_words[1] ^ c_words[2] ^ c_words[3]
            q_byte = (q_word >> (24 - 8 * event["byte"])) & 255
            input_labels = []
            key_labels = []

            for value in event["inputs"]:
                input_labels.append(f"{value:02X}")

            for value in event["survivors"]:
                key_labels.append(f"{value:02X}")

            delta_x = int.from_bytes(view[:4], "big") ^ int.from_bytes(faulty_view[:4], "big")
            lines.extend([r"\paragraph{Byte " + str(event["byte"]) + ", observation " + str(event["observation"]) + r".}", r"The clean and faulty views, after undoing only previously recovered rounds, are:", r"\[\begin{aligned}C_{\rm view}&=\hex{" + view.hex().upper() + r"},\\F_{\rm view}&=\hex{" + faulty_view.hex().upper() + r"}.\end{aligned}\]", r"\[\Delta X=\hex{" + f"{delta_x:08X}" + r"},\quad L^{-1}(\Delta X)=\hex{" + f"{event['delta_b']:08X}" + r"}.\]", r"\[e=\hex{" + f"{event['mask']:02X}" + r"},\quad q_{\rm word}=\hex{" + f"{q_word:08X}" + r"},\quad q_{\rm byte}=\hex{" + f"{q_byte:02X}" + r"}.\]", r"Compatible S-box inputs: \hex{" + ", ".join(input_labels) + r"}. Surviving key bytes after intersection: \hex{" + ", ".join(key_labels) + r"}. Each candidate key byte is the corresponding input XOR $q_{\rm byte}$."])

        lines.append(r"After all four byte intersections: $rk_{" + str(number) + r"}=\hex{" + f"{recovery['round_keys'][number]:08X}" + r"}$.")

        if number > 28:
            state_words = list(reversed(c_words))
            q = state_words[0] ^ state_words[1] ^ state_words[2] ^ recovery["round_keys"][number]
            z = sm4.sbox(q)
            diffusion = sm4.linear(z)
            previous = state_words[3] ^ diffusion
            lines.extend([r"To expose the previous round, undo the newest word:", r"\[Q=\hex{" + f"{state_words[0]:08X}" + r"}\xor\hex{" + f"{state_words[1]:08X}" + r"}\xor\hex{" + f"{state_words[2]:08X}" + r"}\xor\hex{" + f"{recovery['round_keys'][number]:08X}" + r"}=\hex{" + f"{q:08X}" + r"}.\]", r"\[\tau(Q)=\hex{" + f"{z:08X}" + r"},\quad L(\tau(Q))=\hex{" + f"{diffusion:08X}" + r"}.\]", r"\[X_{\rm previous}=\hex{" + f"{state_words[3]:08X}" + r"}\xor\hex{" + f"{diffusion:08X}" + r"}=\hex{" + f"{previous:08X}" + r"}.\]"])

    lines.extend([r"The first pair alone keeps input guesses $\{\hex{96},\hex{97}\}$ and key guesses $\{\hex{91},\hex{90}\}$. The second pair keeps input guesses $\{\hex{75},\hex{77},\hex{94},\hex{96}\}$. Their intersection is $\{\hex{96}\}$, so the key byte is $\hex{96}\xor\hex{07}=\hex{91}$.", r"\section{Reverse expansion: all 32 numerical recurrences}", r"The following calculations start from four already recovered tail subkeys. They do not claim that two last-round faults reveal the earlier subkeys. For each step $Q_i=K_{i+1}\xor K_{i+2}\xor K_{i+3}\xor CK_i$, $Z_i=\tau(Q_i)$, and $K_i=K_{i+4}\xor Z_i\xor\operatorname{ROL}_{13}(Z_i)\xor\operatorname{ROL}_{23}(Z_i)$. Thus the key-schedule map $L'$ uses different rotations from data diffusion $L$."])
    words = [0] * 36
    words[32:] = [0x428D3654, 0x62293496, 0x01CF72E5, 0x9124A012]

    for index in range(31, -1, -1):
        q = words[index + 1] ^ words[index + 2] ^ words[index + 3] ^ sm4.CK[index]
        z = sm4.sbox(q)
        r13 = sm4.rotl(z, 13)
        r23 = sm4.rotl(z, 23)
        transformed = z ^ r13 ^ r23
        words[index] = words[index + 4] ^ transformed
        lines.extend([r"\subsection*{Backward step $i=" + str(index) + "$}", r"\begin{align*}", r"Q_i&=\hex{" + f"{words[index+1]:08X}" + r"}\xor\hex{" + f"{words[index+2]:08X}" + r"}\xor\hex{" + f"{words[index+3]:08X}" + r"}\xor\hex{" + f"{sm4.CK[index]:08X}" + r"}\\&=\hex{" + f"{q:08X}" + r"},\\", r"Z_i&=\tau(Q_i)=\hex{" + f"{z:08X}" + r"},\\", r"\operatorname{ROL}_{13}(Z_i)&=\hex{" + f"{r13:08X}" + r"},\quad\operatorname{ROL}_{23}(Z_i)=\hex{" + f"{r23:08X}" + r"},\\", r"T'(Q_i)&=\hex{" + f"{z:08X}" + r"}\xor\hex{" + f"{r13:08X}" + r"}\xor\hex{" + f"{r23:08X}" + r"}=\hex{" + f"{transformed:08X}" + r"},\\", r"K_i&=\hex{" + f"{words[index+4]:08X}" + r"}\xor\hex{" + f"{transformed:08X}" + r"}=\hex{" + f"{words[index]:08X}" + r"}.\end{align*}"])
        byte_rows = []

        for byte in range(4):
            shift = 24 - 8 * byte
            value = (q >> shift) & 255
            byte_rows.append([byte, f"{value:02X}", f"{sm4.SBOX[value]:02X}"])

        table(lines, ["Byte", "Input to S-box", "Output from S-box"], byte_rows, "rll")

    lines.append(r"\section{Remove FK: all four master-key words}")
    master = bytearray()

    for index in range(4):
        value = words[index] ^ sm4.FK[index]
        master.extend(value.to_bytes(4, "big"))
        lines.append(r"\[MK_{" + str(index) + r"}=\hex{" + f"{words[index]:08X}" + r"}\xor\hex{" + f"{sm4.FK[index]:08X}" + r"}=\hex{" + f"{value:08X}" + r"}.\]")

    assert master.hex().upper() == "0123456789ABCDEFFEDCBA9876543210"
    assert sm4.key_expansion(bytes(master)) == words[4:]
    lines.append(r"Concatenating these words gives $MK=\hex{0123456789ABCDEFFEDCBA9876543210}$. Regenerating the forward schedule matches all 32 words $K_4$ through $K_{35}$, and encryption of the public plaintext reproduces the reference ciphertext.")
    out = ROOT / "docs" / "latex" / "generated" / "complete_calculations.tex"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Generated complete calculations: {len(operations)} elimination steps, 32 inverse bits, 256 candidate tests, 32 schedule steps.")


if __name__ == "__main__":
    from terminal_log import run_with_log
    raise SystemExit(run_with_log(generate, "generate_dfa_calculations"))

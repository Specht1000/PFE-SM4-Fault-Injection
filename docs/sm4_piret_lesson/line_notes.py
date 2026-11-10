"""Authored explanations for each executable line in the two walkthrough modules."""
import ast
from pathlib import Path

# Each diagram describes the real experiment's corresponding activity. The
# Python implementation itself still executes entirely on the host computer.
FUNCTIONS = {
    ('piret_sm4.py', 'sm4_fault_encrypt'): ("Simulate a controlled fault during the real SM4 implementation, while collecting teacher-only intermediates.", "Plaintext and target key", "Run SM4; replace selected S-box input", "Faulty ciphertext and teaching trace", "Target-side behavior is modeled here. In firmware, intermediate words could occupy CPU registers or RAM depending on compilation; this Python callback does not access STM32 registers."),
    ('piret_sm4.py', 'inverse_rows'): ("Construct and cache the inverse of the public 32-bit diffusion map.", "Public SM4 linear map L", "Binary Gaussian elimination on [M | I]", "Rows of inverse L", "This is attacker-side algebra on the PC. No pulse, board read or secret key is required."),
    ('piret_sm4.py', 'inverse_linear'): ("Apply the inverse binary matrix to one observed output difference.", "32-bit output XOR", "Compute inverse-matrix row parities", "32-bit S-box output XOR", "The PC transforms received ciphertext bytes into a mathematical difference. The target does not run backward."),
    ('piret_sm4.py', 'sm4_byte_candidates'): ("Find key-byte guesses consistent with one restored ciphertext pair and a known byte fault.", "C, F, byte index and known mask", "Undo L; test every S-box input", "Compatible key-byte set", "This filtering happens on the PC after a response has been received. The known-mask assumption must be established separately for a physical experiment."),
    ('piret_sm4.py', 'peel_sm4'): ("Reconstruct an earlier output window using only already recovered later keys.", "Ciphertext plus recovered later keys", "Undo later SM4 round recurrences", "Restored target-round output view", "This is offline PC computation. It neither rewinds the STM32 nor reads an old state from target RAM."),
    ('piret_sm4.py', 'recover_sm4_master_key'): ("Coordinate independent fault observations, intersections, four tail-key recoveries and inverse key expansion.", "Correct output and fault oracle", "Recover rk31, rk30, rk29, rk28", "Master key or explicit ambiguity", "On hardware, each oracle request would involve another target encryption and response. The implementation here makes software calls, not USB or serial requests."),
    ('piret_sm4.py', 'reverse_sm4'): ("Derive the initial key words from four consecutive recovered tail words, then remove FK.", "Recovered rk28 through rk31", "Reverse schedule; remove public FK", "Original 128-bit master key", "All schedule inversion runs on the PC. Public CK/FK constants are not extracted from the board."),
    ('piret_sm4.py', 'main'): ("Parse the attack-specific command and enter the same SM4 terminal lesson used by run.py.", "Terminal command and options", "Validate options; call sm4_demo", "Success or ambiguity exit status", "This is a PC entry point. Selecting --row chooses a simulated byte, not a physical chip coordinate. The compatibility options --column and --seed are parsed but not used in this SM4 path."),
    ('run.py', 'block'): ("Convert a hexadecimal input string to exactly sixteen bytes.", "32 hexadecimal characters", "Decode hex and check length", "16 raw bytes", "A future host transport would send these bytes to firmware. This function only prepares host memory."),
    ('run.py', 'LessonTerminal'): ("Format the same data as clean/faulty/XOR rows with red differences.", "Two arrays of bytes", "Compare positions; apply ANSI colors", "Readable terminal and log rows", "Only the PC display changes. Red text is a visualization of differing data, not a measured electrical pulse."),
    ('run.py', 'aes_demo'): ("Run the AES round-9 lesson when AES is selected; this function is not executed by --algorithm sm4.", "AES selection only", "AES encryption and quartet recovery", "AES verification result", "Included for complete run.py coverage. It does not contribute to SM4 recovery; all operations here remain host-side software simulation."),
    ('run.py', 'inverse_rows'): ("Delegate inverse-matrix construction to the SM4 attack module.", "Public linear map", "Call piret_sm4.inverse_rows", "Cached inverse-matrix rows", "This wrapper exists on the host for compatible call sites; it does not issue a hardware operation."),
    ('run.py', 'inverse_linear'): ("Delegate inverse diffusion to the SM4 attack module.", "Observed difference", "Call piret_sm4.inverse_linear", "Restored S-box difference", "Offline PC algebra; no new target encryption occurs."),
    ('run.py', 'sm4_encrypt'): ("Delegate a clean or faulty encryption request to the software target adapter.", "Plaintext, key and optional fault", "Call SM4 target adapter", "Ciphertext and trace", "This wrapper currently calls Python. A serial transport is not implemented by this function."),
    ('run.py', 'sm4_byte_candidates'): ("Delegate the known-mask byte equation to the attack module.", "Restored output pair", "Call SM4 candidate solver", "Input/key guesses and difference", "This is PC analysis of outputs, not access to hidden chip state."),
    ('run.py', 'reverse_sm4'): ("Delegate schedule inversion without duplicating its equations.", "Four recovered tail keys", "Call inverse key expansion", "Original key bytes", "The host derives key material mathematically after the fault observations."),
    ('run.py', 'show_sm4_peeling'): ("Explain every reverse round numerically for a correct or faulty output.", "Ciphertext and recovered later keys", "Print each reconstructed older word", "Detailed peeling explanation", "This reconstructs a software view on the PC. It is not a live trace of past target registers."),
    ('run.py', 'show_sm4_key_schedule'): ("Produce and print detailed SM4 inverse-schedule teaching events.", "DFA-recovered tail keys", "Explain all reverse words and FK removal", "Master key and printed derivation", "This display may repeat an already completed inverse schedule. That repetition does not collect additional faults."),
    ('run.py', 'show_sm4_observation'): ("Explain one observation, its inverse-L calculation, its candidates and its uniqueness status.", "Solver event and previous sets", "Render equations and intersections", "Recovered-byte/round-key summaries", "The event contains measurements and reconstructed values. Teacher traces and hidden states must not be confused with the solver inputs."),
    ('run.py', 'show_aes_key_schedule'): ("Print the AES inverse schedule; this path is inactive in the SM4 demonstration.", "Recovered AES K10", "Derive AES schedule events", "AES K0", "Included only because it is a function in run.py. The SM4 path instead uses show_sm4_key_schedule."),
    ('run.py', 'sm4_demo'): ("Build the clean reference, define target/report callbacks, recover the key and validate the result.", "Configured SM4 inputs", "Clean run; faults; recovery; checks", "Printed SM4 result and boolean success", "This is the host experiment controller. In a board experiment the oracle would need a real transport and glitch campaign instead of the present Python target adapter."),
    ('run.py', 'main'): ("Choose AES, SM4 or both and aggregate their exit status.", "Command-line arguments", "Validate configuration; select lessons", "Process success/ambiguity code", "All selection, printing and log handling runs on the PC. --algorithm sm4 skips the AES lesson, although configuration validation checks both modules."),
}

# Rules are matched against actual source lines, not obsolete hard-coded line
# numbers. Specific equations come before general formatting/control rules.
RULES = [
('return value', 'Return the unchanged or injected scalar to the normal SM4 engine; this returned replacement is what the next cipher operation consumes.'),
('keys = sm4.key_expansion(key)', 'Compute the target schedule for trace labeling. The result is a list indexed 0..31, not a dictionary; it is not passed to the output-only solver.'),
('trace = [dict(', 'Allocate one record per round and attach its target round-key value for the teacher trace. These records are not attacker observations.'),
('fields = {', 'Translate cipher callback event names into short trace dictionary fields a, b, linear and new.'),
('if byte is not None and not', 'If a fault was requested, require a byte position 0..3 and a nonzero one-byte mask. None permits a clean reference run.'),
('if not 0 <= fault_round', 'Reject a selected round outside the zero-based 0..31 interval.'),
('if number == fault_round', 'Inject only when both round and operation match, and a target byte was selected; other events pass through unchanged.'),
('value ^= mask <<', 'Move the mask into the selected big-endian byte and XOR it into the word. For byte 0 and mask 01, the shifted mask is 01000000.'),
('if operation in fields:', 'Record only named scalar intermediate events; ignore other observation events for this teacher trace.'),
('trace[number][fields[operation]]', 'Save the observed scalar at its round and semantic field, so the terminal can compare clean and faulty calculations.'),
('ciphertext = sm4.sm4_encrypt_block', 'Execute normal SM4 with the external observer attached. A returned observer replacement is consumed by the real round function.'),
('return ciphertext, trace', 'Return the target output together with teacher-only intermediate records. The oracle later forwards only the ciphertext to the solver.'),
('columns = [sm4.linear(1 << i)', 'Apply L to each one-hot input word. These thirty-two results are the columns of its public binary matrix.'),
('rows = [sum(', 'Build each row of the augmented binary matrix. Lower 32 bits encode L; bit 32+row places the matching identity bit in the upper half.'),
('for column in range(32):', 'Process one pivot column of the 32-by-32 binary matrix at a time.'),
('pivot = next(', 'Find a remaining row whose current pivot bit equals one. Invertibility ensures a pivot exists.'),
('rows[column], rows[pivot]', 'Swap the chosen pivot row into the current diagonal position.'),
('for row in range(32):', 'Visit every augmented row so the current column can be cleared outside its pivot.'),
('if row != column and', 'Leave the pivot unchanged; eliminate only another row whose pivot-column bit is one.'),
('rows[row] ^= rows[column]', 'XOR the entire augmented pivot row into that row, performing GF(2) row elimination on both halves.'),
('return tuple(row >> 32', 'Discard the now-identity lower half and return the inverse-matrix rows from the upper half.'),
('return sum((bin(row & value)', 'For each inverse row, AND selects contributing input bits; population-count parity is their GF(2) dot product. Shift the parity to its output bit and assemble the 32-bit result.'),
('if len(correct) != 16', 'Require two complete block outputs and valid controlled-fault descriptors before interpreting differences.'),
('c, f = struct.unpack', 'Decode each sixteen-byte output into four big-endian unsigned 32-bit words.'),
('if c[1:] != f[1:]', 'Require the last three restored output words to be unchanged. Otherwise this observation violates the selected last-round model.'),
('delta_b = inverse_linear', 'XOR the newest words, then undo public linear diffusion to recover the S-box output difference.'),
('shift = 24 - 8 * byte', 'Map byte 0,1,2,3 to bit shifts 24,16,8,0 in a big-endian 32-bit word.'),
('if not delta_b or delta_b &', 'Reject a zero difference or any nonzero difference bit outside the selected byte.'),
('d = (delta_b >> shift)', 'Select the affected S-box output difference byte, keeping only its lowest eight bits.'),
('known = ((c[1]', 'Compute q: select a byte of the XOR of the three observable unchanged words. It is not a hidden state read.'),
('inputs = {a for a in range(256)', 'Enumerate every unknown S-box input a and keep those satisfying S(a) XOR S(a XOR mask) = observed byte difference.'),
('return {a ^ known', 'Convert each compatible input to a key-byte guess a XOR q; also return input guesses and the full inverse-L difference for explanation.'),
('if len(final_keys) != 4', 'Require four consecutive tail subkeys; a single recovered rk31 is insufficient to seed the inverse schedule.'),
('words = [None] * 32', 'Reserve K0..K31 as unknown and seed K32..K35 with recovered rk28..rk31 in that order.'),
('for index in range(31, -1, -1)', 'Recover schedule words in descending order so every right-hand dependency is already known.'),
('value = words[index+1]', 'Form the public schedule-core input from three known neighboring words and CK[index].'),
('words[index] = words[index+4]', 'Apply the forward S-box and key-specific L-prime, then XOR with K[index+4] to solve for the older schedule word.'),
('if observer:', 'Call optional explanatory instrumentation only if supplied; the numerical result has already been computed.'),
('observer(index, words[index])', 'Report this derived schedule word without giving the observer control over key recovery.'),
('return struct.pack(">4I", *(words[i]', 'Remove FK whitening from K0..K3, then concatenate the four master words as sixteen big-endian bytes.'),
('aes.validate_block(', 'Reuse a sixteen-byte length check. This does not execute AES and does not import an AES key into SM4 recovery.'),
('if not 28 <= target_round', 'Restrict this full-recovery peeling helper to the four modeled target rounds.'),
('words = list(struct.unpack', 'Read the four final output words, then reverse their order to restore the chronological rolling state.'),
('for number in range(31, target_round', 'Undo only rounds later than the requested target round, newest first.'),
('if number not in recovered_keys', 'Require a genuinely recovered later key before reversing its round; never substitute a reference key.'),
('previous = words[3] ^', 'Recompute the later-round nonlinear/linear transform and XOR with its newest word to reconstruct the missing oldest word.'),
('words = [previous,', 'Shift the reconstructed window backward by one round: old, u0, u1, u2.'),
('return struct.pack(">4I", *words[::-1])', 'Return a synthetic ciphertext-style view with word reversal, allowing reuse of the same last-round candidate equation.'),
('masks = tuple(masks)', 'Freeze a possibly one-shot iterable so every target byte can reuse the same ordered observation masks.'),
('if not masks or len(set(masks))', 'Validate a nonempty set of distinct nonzero byte masks and a valid first-byte selector; repeated masks would not add independent information.'),
('keys, history, counts, used', 'Initialize recovered keys, event history, per-byte counts and actual faulty-output query count separately.'),
('for number in range(31, 27, -1)', 'Target rounds 31,30,29,28 in that order; later recovered keys enable peeling for the next target.'),
('clean_view = peel_sm4', 'Restore the clean reference to this target round using only the currently recovered later keys.'),
('subkey = bytearray(4)', 'Allocate four output bytes for the current round key; unfilled bytes must not be treated as recovered.'),
('for byte in [(start_byte', 'Start at the user-selected byte and wrap modulo four so all four positions are processed exactly once.'),
('survivors = None', 'Mark the byte or group as unconstrained before its first observation; an empty set would instead mean inconsistency.'),
('for observation, mask in enumerate', 'Request distinct faults sequentially, numbering observations from one within this target byte/group.'),
('faulty = bytes(fault_oracle', 'Query the simulated target for one new faulty ciphertext. No key or teacher trace is returned to this solver.'),
('faulty_view = peel_sm4', 'Undo the same recovered later rounds in the faulty ciphertext so both outputs refer to the same target round.'),
('if candidate_filter is None', 'Choose the default known-byte filter unless another compatible filter, such as the Giraud-inspired one, was explicitly supplied.'),
('fresh, inputs, delta = sm4_byte_candidates', 'Apply the selected-round byte equation to this clean/faulty pair and known mask.'),
('position, fresh, inputs, delta = candidate_filter', 'Run the alternate filter and receive its inferred byte position alongside candidate sets and difference.'),
('if position != byte', 'Reject an alternate-filter result whose changed byte is inconsistent with the requested target byte.'),
('before = 256 if survivors is None', 'Record 256 possible byte values before the first observation, or the prior surviving count thereafter.'),
('survivors = set(fresh)', 'The first pair initializes the byte set; subsequent pairs intersect it. No new guess can be introduced by intersection.'),
('if not survivors', 'An empty intersection means the observations and model cannot be reconciled; do not claim a key.'),
('used += 1', 'Count one faulty ciphertext actually consumed by the solver, not a printed stage or a schedule replay.'),
('counts[f"{number}:{byte}"]', 'Store the surviving count for this particular round and byte.'),
('event = dict(', 'Package the measurement pair, restored views, known mask, input guesses, surviving key guesses and recovered peeling keys for presentation.'),
('history.append(event)', 'Preserve this observation in order for later inspection and reproducibility.'),
('if observer is not None', 'Only invoke the optional reporting callback if the caller requested it.'),
('observer(dict(event))', 'Pass copied event metadata to reporting. Candidate-set intersection has already been decided in the solver.'),
('if len(survivors) == 1', 'Uniqueness is the acceptance rule: one value remains compatible with all observations for this byte/group.'),
('subkey[byte] = next(iter(survivors))', 'Extract the sole surviving byte and store it at the correct big-endian position.'),
('break', 'Stop this observation loop immediately after uniqueness; do not query unused masks.'),
('return dict(master_key=None', 'Return an explicit incomplete result when the observation loop exhausts its budget without a break. No master key is selected.'),
('keys[number] = int.from_bytes', 'Concatenate the four uniquely recovered bytes into one 32-bit round key and make it available for future peeling.'),
('master = reverse_sm4(', 'Arrange recovered rk28..rk31 in schedule order and reverse expansion to derive the original key.'),
('return dict(master_key=master', 'Return the complete key together with actual recovered tail keys, history, counts and fault-query cost.'),
('data = bytes.fromhex(value)', 'Decode hexadecimal text into raw bytes; malformed hex raises ValueError instead of silently changing the input.'),
('if len(data) != 16', 'Accept only one complete 128-bit block or key for this demonstration.'),
('return data', 'Return the validated raw bytes used by the cipher and target simulator.'),
('delta = bytes(a ^ b', 'Compute the per-byte XOR of the aligned clean and faulty arrays; equal positions become zero.'),
('return " ".join(self.paint', 'Format every byte as two hex digits and use ANSI red only where the faulty byte differs from the reference.'),
('return piret_sm4.inverse_rows', 'Delegate to the single cached implementation of inverse-matrix construction.'),
('return piret_sm4.inverse_linear', 'Delegate inverse diffusion; the wrapper introduces no new equation or target operation.'),
('return piret_sm4.sm4_fault_encrypt', 'Forward the target inputs and optional fault descriptor to the SM4 simulator, returning both output and trace.'),
('return piret_sm4.sm4_byte_candidates', 'Delegate ciphertext-based candidate filtering rather than duplicate it in presentation code.'),
('return piret_sm4.reverse_sm4', 'Delegate schedule reversal, forwarding the optional explanatory callback.'),
('view = ciphertext', 'Start the explanatory peeling pass from the measured final ciphertext.'),
('words = struct.unpack(">4I", view)[::-1]', 'Restore chronological word order for the current reverse-round explanation.'),
('round_key = recovered_keys[number]', 'Use the already recovered subkey corresponding to the later round being undone.'),
('value = words[0] ^ words[1]', 'Form that round\'s S-box input from the three newest surviving words and its recovered key.'),
('substituted = sm4.sbox(value)', 'Substitute the four reconstructed input bytes using the public SM4 S-box.'),
('diffused = sm4.linear(substituted)', 'Apply encryption diffusion L to the substituted value for the reverse-round equation.'),
('view = piret_sm4.peel_sm4', 'Ask the actual attack helper for the restored view, so the explanatory pass cannot silently use different reversal logic.'),
('previous = struct.unpack', 'Read the newly reconstructed oldest word from the last word of the ciphertext-style restored view.'),
('master, events = attack_steps.sm4_schedule', 'Build all numerical inverse-schedule events and the resulting SM4 master key from recovered tail keys.'),
('master, events = attack_steps.aes_schedule', 'Build AES-specific inverse-schedule teaching events; this function is inactive for SM4-only execution.'),
('return master', 'Return the master-key bytes produced by the explained inverse schedule.'),
("number, byte = event['round']", 'Read the selected target round and byte from the completed solver observation.'),
("identity = ('candidates'", 'Use a compound dictionary key so candidate history for one byte cannot contaminate another round or position.'),
('recovered_bytes[identity] = set', 'Remember the current candidate set for the next detailed intersection display; this does not change the solver.'),
("if byte == start_byte and event['observation'] == 1", 'Print the round-level introduction only for the first observation of the first displayed byte.'),
('if number == 31:', 'The actual last round requires no peeling; earlier target rounds must remove later rounds first.'),
('keys = {int(r): int(value, 16)', 'Decode the event\'s already recovered later keys from their hexadecimal display representation.'),
('show_sm4_peeling(', 'Explain correct or faulty round peeling separately; these reconstructed views remain offline host values.'),
('clean_words = struct.unpack', 'Decode the clean restored output view into four big-endian words for the explanatory equations.'),
('faulty_words = struct.unpack', 'Decode the corresponding faulty restored output with exactly the same layout.'),
('known = ((clean_words[1]', 'Recompute q from public restored words for the displayed key-byte conversion.'),
("delta = (event['delta_b']", 'Select the target byte of the already computed S-box output difference.'),
('if known_bit is False:', 'Unknown-bit Giraud must test every one-bit mask. The default controlled-byte demonstration instead knows its mask.'),
('allowed = (1, 2, 4, 8', 'List the eight possible single-bit errors without revealing which simulator bit was actually selected.'),
("allowed = (event['mask'],)", 'Use the exact known error for the controlled-byte or explicitly known-bit model.'),
("for candidate in event['inputs']", 'Explain every compatible S-box input that survived the current pair equation.'),
('error = next(value for value in allowed', 'Find a permitted error witnessing that this input guess satisfies the observed S-box difference.'),
('changed = candidate ^ error', 'Reconstruct the corresponding faulty S-box input for this compatible hypothesis.'),
("if event['remaining'] == 1", 'Only print a recovered-byte declaration when the accumulated intersection has exactly one value.'),
("value = event['survivors'][0]", 'Read that unique key-byte value from the sorted event list.'),
('recovered_bytes.setdefault(number', 'Maintain a per-round collection of uniquely recovered bytes for final round-key assembly.'),
('if len(recovered_bytes[number]) == 4', 'Wait until all four byte positions are known before claiming a complete 32-bit subkey.'),
('ordered = bytes(recovered_bytes[number]', 'Assemble byte positions 0,1,2,3 in big-endian order, independent of discovery order.'),
('key, plaintext = block(sm4.KEY)', 'Read and validate the configured target key and plaintext for simulation. The solver does not receive the key.'),
('correct, trace = sm4_encrypt', 'Run a clean reference encryption with no fault selected and retain teacher-only round records.'),
('for item in trace:', 'Print each of the thirty-two clean encryption-round records in order.'),
('recovered_bytes = {}', 'Start presentation-only histories for candidate sets and uniquely recovered round-key bytes.'),
('faulty, fault_trace = piret_sm4.sm4_fault_encrypt', 'Perform one new target encryption with the selected fault. The detailed trace is for teaching, not solving.'),
('return faulty', 'Give the attacker only the target ciphertext; do not return its trace or target key.'),
('show_sm4_observation(', 'Render a solver event without taking control of its candidate computation.'),
('result = piret_sm4.recover_sm4_master_key', 'Run full output-based SM4 recovery with mask budget 1..limit, selected starting byte and a reporting callback.'),
("if not result['complete']", 'Detect an observation budget exhausted before full uniqueness; do not continue to a claimed master key.'),
('return False', 'Tell the caller that this requested lesson did not establish verified complete recovery.'),
("for number, value in result['round_keys'].items()", 'Summarize only the four subkeys actually recovered through fault observations.'),
('recovered = show_sm4_key_schedule', 'Repeat inverse expansion through the detailed teaching view and retain its reconstructed master key.'),
("if recovered != result['master_key']", 'Cross-check the detailed display\'s inverse schedule against the recovery engine\'s result.'),
('verified_ciphertext = sm4.sm4_encrypt_block', 'Re-encrypt the known plaintext with the recovered key using the ordinary SM4 cipher.'),
('if recovered != key or verified_ciphertext', 'Validate both simulation ground-truth equality and the original correct ciphertext, only after recovery.'),
('return True', 'Return verified success to the command-line controller.'),
('terminal = LessonTerminal(', 'Configure presentation colors and optional pauses; these choices do not affect the cryptographic equations.'),
('statuses = []', 'Collect independent success flags for the requested algorithm demonstrations.'),
('if args.algorithm in ("all", "aes")', 'Execute the AES branch only when requested. It is skipped by --algorithm sm4.'),
('if args.algorithm in ("all", "sm4")', 'Execute the SM4 demonstration for either an explicit SM4 selection or the combined default.'),
('statuses.append(aes_demo', 'Run the AES lesson and store its success flag; not executed in the SM4-only command.'),
('statuses.append(sm4_demo', 'Run the SM4 lesson with its observation budget and store whether full recovery verified.'),
('return 0 if all(statuses)', 'Report process success only if every requested lesson succeeded; return 2 for ambiguous recovery.'),
('return 0 if run.sm4_demo', 'Enter the shared terminal controller with this entry point\'s mask budget and first-byte selection; map success to exit status 0 and ambiguity to 2.'),
('for value in (aes.KEY', 'Validate both cipher configurations even if just one lesson was requested; this is configuration checking, not AES execution.'),
('block(value)', 'Require this configured key or plaintext to decode as a complete block.'),
# AES-only lines in run.py are covered explicitly so the file has no skipped function.
('key, plaintext = block(aes.KEY)', 'Load AES simulation inputs. This line belongs to the AES branch and does not supply SM4 key material.'),
('clean, trace = piret_aes.trace_round8', 'Use the AES trace adapter with fault_round=9; mask zero creates the clean reference.'),
('if clean != piret_aes.aes_target_encrypt', 'Check that the trace adapter matches ordinary AES encryption before teaching its fault behavior.'),
('keys = aes.key_expansion', 'Compute AES round keys for the teacher-only normal-encryption display.'),
('for number, round_key in enumerate', 'Show each AES expanded round key in sequence.'),
('initial = aes.bytes_to_state', 'Convert the plaintext into the AES column-major matrix for initial key addition.'),
('aes.add_round_key(initial', 'Apply the initial AES K0 XOR in the teacher view.'),
('for number, operation, state in trace', 'Walk the clean AES transformation snapshots in execution order.'),
('if operation != "Fault point"', 'Exclude the adapter marker from the ordinary AES transformation display.'),
('masks = [1, 2]', 'Try AES masks 1 and 2 first, then reproducibly sample other distinct nonzero masks up to the limit.'),
('last_key, total = bytearray', 'Prepare sixteen AES final-key bytes and a total faulty-output counter.'),
('for column in range(4):', 'Recover each of the four AES pre-ShiftRows key quartets in turn.'),
('faulty, faulty_trace = piret_aes.trace_round8', 'Run an AES round-9 byte-fault encryption for the selected column and mask.'),
('total += 1', 'Count this faulty AES encryption once, independently of display stages.'),
('references = {', 'Index clean AES snapshots by round and operation for paired fault-propagation comparisons.'),
('for number, operation, state in faulty_trace', 'Visit each faulty AES transformation snapshot for the current observation.'),
('if number >= 9:', 'Display only the AES fault round and later propagation in this part of the lesson.'),
('fresh = piret_aes.key_candidates', 'Derive compatible AES K10 quartets from correct/faulty ciphertexts, not from the printed key.'),
('before = None if survivors is None', 'Record whether this AES quartet has a previous observation and its surviving count.'),
('survivors = fresh if survivors is None', 'Initialize or intersect the AES quartet candidate set for this column.'),
('for position, value in zip', 'Place the unique AES tuple bytes into final ciphertext/key order using inverse ShiftRows mapping.'),
('last_key[position] = value', 'Store one uniquely recovered AES final-key byte at its true serialized position.'),
('recovered = show_aes_key_schedule', 'Derive AES K0 from the recovered K10 through the detailed display helper.'),
('if recovered != key or piret_aes.aes_target_encrypt', 'Check the AES recovered key only after recovery: ground truth and re-encryption must both agree.'),
]


EXPANDED_RULES = [
    ('trace = []', 'Create an empty teaching trace; the following explicit loop adds one record for each round.'),
    ('for index in range(32)', 'Visit all thirty-two round indices to construct the trace records.'),
    ('trace.append(', 'Add the record for this round and its target-side round key to the teacher trace.'),
    ('columns = []', 'Prepare the list of images of the thirty-two input basis words under the public map L.'),
    ('for bit_index in range(32)', 'Choose each input basis bit explicitly, from bit zero through bit thirty-one.'),
    ('basis_word = 1 << bit_index', 'Construct a 32-bit word with exactly the selected input bit set.'),
    ('transformed_word = sm4.linear(basis_word)', 'Apply public encryption diffusion L to that basis word, obtaining one matrix column.'),
    ('columns.append(transformed_word)', 'Store this basis image as the next column of the binary matrix.'),
    ('rows = []', 'Prepare the augmented-matrix row list before encoding individual row bits.'),
    ('for row_index in range(32)', 'Construct each output row of the binary matrix explicitly.'),
    ('matrix_row = 0', 'Start this encoded matrix row with every bit cleared.'),
    ('for column_index in range(32)', 'Read the selected output bit from each stored matrix column.'),
    ('output_bit = (columns[column_index]', 'Extract the bit indicating whether this input column contributes to the selected output row.'),
    ('matrix_row |= output_bit << column_index', 'Place that contribution bit in the encoded matrix row; OR combines disjoint bit positions.'),
    ('identity_bit = 1 << (32 + row_index)', 'Place the matching identity-matrix bit in the upper half of the augmented row.'),
    ('augmented_row = matrix_row | identity_bit', 'Combine the L-matrix row with its identity bit to form the packed row of [M | I].'),
    ('rows.append(augmented_row)', 'Store the completed augmented row before Gaussian elimination.'),
    ('pivot = None', 'Mark the pivot as not yet found; the following ordinary loop searches eligible rows.'),
    ('for candidate_row in range(column, 32)', 'Search the current and remaining rows for a one in the pivot column.'),
    ('pivot_bit = (rows[candidate_row]', 'Read the current candidate row bit at the pivot column.'),
    ('if pivot_bit == 1', 'Accept this row as a valid pivot only if its selected column bit is one.'),
    ('pivot = candidate_row', 'Remember the actual row index, then stop searching because a valid pivot was found.'),
    ('if pivot is None', 'Detect a missing pivot instead of blindly swapping an invalid row index.'),
    ('inverse_matrix_rows = []', 'Prepare the final public inverse-matrix rows after elimination.'),
    ('for augmented_row in rows', 'Visit each reduced augmented row to extract its inverse half.'),
    ('inverse_row = augmented_row >> 32', 'Discard the lower identity half and retain the upper inverse-matrix row.'),
    ('inverse_matrix_rows.append(inverse_row)', 'Add the extracted inverse row in the original output-bit order.'),
    ('return tuple(inverse_matrix_rows)', 'Return an immutable sequence of inverse rows, cached for reuse by later observations.'),
    ('result = 0', 'Clear the output word before placing one parity bit at a time.'),
    ('for index, row in enumerate(inverse_rows())', 'Associate each inverse-matrix row with the output bit it computes.'),
    ('selected_bits = row & value', 'Select exactly the input bits used by this inverse row.'),
    ('set_bit_count = bin(selected_bits).count', 'Count selected one bits; only whether this count is odd or even matters over GF(2).'),
    ('parity = set_bit_count & 1', 'Keep the lowest count bit: odd becomes one and even becomes zero.'),
    ('result |= parity << index', 'Place this row parity into its output position without changing other output bits.'),
    ('return result', 'Return the word assembled from all thirty-two inverse-row parity calculations.'),
    ('inputs = set()', 'Start an empty set of compatible unknown S-box input bytes.'),
    ('for candidate_input in range(256)', 'Test each possible unknown input byte explicitly.'),
    ('faulty_input = candidate_input ^ mask', 'Apply the known error hypothesis to the candidate S-box input.'),
    ('output_difference = sm4.SBOX[candidate_input]', 'Calculate the clean/faulty S-box XOR for this candidate input and known error.'),
    ('if output_difference == d', 'Keep the hypothesis only if its predicted S-box difference equals the observed one.'),
    ('inputs.add(candidate_input)', 'Record this compatible input value; the set removes duplicates.'),
    ('key_candidates = set()', 'Prepare key-byte candidates separately from S-box input hypotheses.'),
    ('for candidate_input in inputs', 'Convert each compatible S-box input into a key-byte guess.'),
    ('key_byte = candidate_input ^ known', 'Solve a = q XOR key_byte using the observable q byte.'),
    ('key_candidates.add(key_byte)', 'Store the resulting key-byte hypothesis for intersection with other observations.'),
    ('return key_candidates, inputs, delta_b', 'Return the key hypotheses, compatible S-box inputs and full inverse-L difference separately.'),
    ('master_words = []', 'Prepare four unwhitened master-key words.'),
    ('for word_index in range(4)', 'Remove FK separately for master-word positions zero through three.'),
    ('master_word = words[word_index] ^ sm4.FK[word_index]', 'Undo initial key whitening with the corresponding public FK constant.'),
    ('master_words.append(master_word)', 'Preserve the master-word order for final serialization.'),
    ('return struct.pack(">4I", *master_words)', 'Serialize the four recovered master words into sixteen big-endian bytes.'),
    ('if not masks:', 'Reject an empty fault-mask sequence before any target query.'),
    ('if len(set(masks)) != len(masks)', 'Reject repeated masks; deterministic repeated observations do not add constraints.'),
    ('for candidate_mask in masks', 'Validate each supplied fault descriptor explicitly.'),
    ('if not 1 <= candidate_mask <= 255', 'Reject zero and masks that do not fit in one nonzero byte.'),
    ('if not 0 <= start_byte < 4', 'Require the first selected byte position to be zero through three.'),
    ('byte_order = []', 'Prepare an explicit ordering of all four byte positions for this round.'),
    ('for offset in range(4)', 'Visit four offsets starting from the user-selected first byte.'),
    ('byte_order.append((start_byte + offset) % 4)', 'Wrap the byte position modulo four so every position appears once.'),
    ('for byte in byte_order', 'Recover one complete key byte at a time in the chosen order.'),
    ('if survivors is None:', 'Distinguish the first observation from subsequent intersections; no previous candidate set exists yet.'),
    ('before = 256', 'Before a first byte observation all 256 byte values are still possible.'),
    ('before = len(survivors)', 'Record the number of hypotheses remaining before applying the new observation.'),
    ('before = None', 'Mark the initial AES quartet history as unconstrained rather than claiming a previous finite set.'),
    ('survivors = survivors & fresh', 'Intersect the prior hypotheses with those from the new pair; never introduce a new candidate.'),
    ('survivors = fresh', 'Initialize this AES quartet set directly from the first observed pair.'),
    ('recovered_key_labels = {}', 'Prepare a display-only dictionary of already recovered later subkeys.'),
    ('for index, value in keys.items()', 'Visit only subkeys already established by the solver.'),
    ('recovered_key_labels[str(index)]', 'Format each recovered subkey as eight hexadecimal digits for event metadata.'),
    ('final_keys = []', 'Prepare the four recovered tail keys in forward key-schedule order.'),
    ('for candidate_number in range(28, 32)', 'Read rk28, rk29, rk30 and rk31 in the order expected by schedule inversion.'),
    ('final_keys.append(keys[candidate_number])', 'Add the actual recovered subkey to the inverse-schedule seed.'),
    ('if run.sm4_demo(', 'Run the shared SM4 lesson and test whether full recovery verified.'),
    ('return 0', 'Return successful process status after verified complete recovery.'),
    ('return 2', 'Return the explicit ambiguity/failure status when full recovery was not verified.'),
    ('result_value = 0', 'Select process success because all requested demonstrations verified.'),
    ('result_value = 2', 'Select process ambiguity status because a requested demonstration did not fully recover its key.'),
    ('return result_value', 'Return the selected process status without changing the recovered data.'),
    ('if all(statuses)', 'Check the already collected success flags for all requested algorithm demonstrations.'),
    ('formatted_values', 'Accumulate or append the explicitly formatted hexadecimal display fragments; this does not modify cipher data.'),
    ('return \' \'.join(formatted_values)', 'Join the prepared hex fragments with spaces for terminal display.'),
    ('for index, value in enumerate(faulty)', 'Compare each faulty output byte with its reference position before choosing its color.'),
    ('if value != original[index]', 'Use red formatting only when this faulty byte differs from the clean reference byte.'),
    ('element_value = self.paint', 'Prepare this changed byte with ANSI red and an immediate reset.'),
    ('element_value = f', 'Prepare an unchanged byte as ordinary two-digit hexadecimal text.'),
    ('for byte_2 in correct', 'Format each clean reference byte without fault coloring.'),
    ('byte_values = []', 'Prepare an explicit byte buffer for the following comparison or recovered-key serialization.'),
    ('for input_value, byte in zip(correct, faulty)', 'Visit the aligned correct and faulty bytes in the same serialized order.'),
    ('byte_values.append(input_value ^ byte)', 'Append their byte XOR, which is zero exactly when the two positions agree.'),
    ('delta = bytes(byte_values)', 'Serialize the explicitly constructed difference buffer.'),
    ('if limit >= 2', 'Use the two preferred initial AES masks when the observation budget allows both.'),
    ('masks = [1]', 'For a budget of one, run only the first AES mask rather than requesting extra observations.'),
    ('for row, op, candidate_state in trace', 'Build the clean AES snapshot lookup explicitly from each recorded round and operation.'),
    ('references[row, op] = candidate_state', 'Index the clean state by its round/operation pair for later fault-propagation comparisons.'),
    ('for candidate in sorted(survivors)[:4]', 'Format up to four candidates for the short summary; the earlier detailed tables remain exhaustive.'),
    ('for candidate_value', 'Visit each value of the displayed allowed-error, survivor or recovered-byte sequence explicitly.'),
    ('keys = {}', 'Prepare the decoded recovered-key dictionary for the explanatory peeling pass.'),
    ("for row, candidate_value_5 in event['peeled_with'].items()", 'Decode each already recovered later key carried by the event.'),
    ('keys[int(row)] = int(candidate_value_5, 16)', 'Convert string indices and hexadecimal key labels back to integers for the display calculation.'),
    ('error = None', 'Start without a compatible error witness; the explicit search must find one.'),
    ('for allowed_error in allowed', 'Test each error permitted by the selected known-mask or unknown-bit model.'),
    ('faulty_input = candidate ^ allowed_error', 'Construct the corresponding faulty S-box input for this candidate and error.'),
    ('predicted_difference = sm4.SBOX[candidate]', 'Calculate the predicted S-box difference for this error witness.'),
    ('if predicted_difference == delta', 'Accept the error witness only if it matches the observed byte difference.'),
    ('error = allowed_error', 'Remember this compatible error before stopping the witness search.'),
    ('if error is None', 'Report the impossible-witness condition rather than inventing an error value.'),
    ('for index in range(4)', 'Visit the four recovered byte positions in big-endian order.'),
    ('byte_values.append(recovered_bytes[number][index])', 'Add the uniquely recovered byte at this position to the round-key buffer.'),
    ('ordered = bytes(byte_values)', 'Serialize all four recovered bytes into the assembled round-key view.'),
]


def explain(node, line, purpose):
    """Require a semantic explanation; unknown arithmetic must fail the build."""

    text = line.strip()

    for prefix, description in EXPANDED_RULES:
        if text.startswith(prefix):
            return description

    if text == 'break' and purpose.startswith('Construct and cache'):
        return 'Stop searching pivot rows as soon as a valid row has been found.'

    if text == 'break' and purpose.startswith('Explain one observation'):
        return 'Stop the permitted-error search once one compatible witness is found.'

    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        if text.startswith('def observer'):
            return 'Define the target callback; its body executes later when the normal cipher calls the observation hook, not when this definition is reached.'

        if text.startswith('def oracle'):
            return 'Define a target-query callback closing over the plaintext and simulated secret key. Its public result is only a ciphertext.'

        if text.startswith('def report'):
            return 'Define the presentation callback invoked after each solver observation; it does not generate faults or choose candidates.'

        if text.startswith('def changed'):
            return 'Define the byte-formatting method used to color differences without changing any byte values.'

        if text.startswith('def pair'):
            return 'Define the clean/faulty/XOR printing method used throughout both lessons.'

        return 'Declare this callable and its parameters; the body runs only when called. ' + purpose

    if text.startswith('print('):
        # Formatting specifications such as 08X are not text printed literally.
        format_nodes = set()

        for number_3 in ast.walk(node):
            if isinstance(number_3, ast.FormattedValue) and number_3.format_spec is not None:
                for child in ast.walk(number_3.format_spec):
                    format_nodes.add(id(child))

        if node.value.args:
            fragments_2 = []

            for number_2 in ast.walk(node.value.args[0]):
                if isinstance(number_2, ast.Constant) and isinstance(number_2.value, str) and (id(number_2) not in format_nodes):
                    fragments_2.append(number_2.value)
        else:
            fragments_2 = []

        fragments = fragments_2

        label = ' '.join(fragments).replace('\n', ' ').strip()

        fields = []

        for number in ast.walk(node.value):
            if isinstance(number, ast.FormattedValue):
                fields.append(ast.unparse(number.value))

        if label:
            description = 'Print the text/label "' + label + '".'
        else:
            description = 'Print the supplied display value.'

        if fields:
            description += ' Substitute these runtime fields: ' + ', '.join(fields) + '.'

        return description + ' This is presentation output, also mirrored to the active log; it performs no target query and changes no candidates.'

    if text.startswith('parser = argparse.ArgumentParser'):
        return 'Create the command-line option parser using the module description for help text.'

    if text.startswith('parser.add_argument'):
        arg = node.value.args[0].value

        extra = {'--algorithm': 'Select the allowed cipher branch for this entry point.', '--step': 'Enable pauses at teaching boundaries.', '--color': 'Select automatic, forced or disabled ANSI colors.', '--faults': 'Set the maximum distinct mask observations per SM4 target byte.', '--observations': 'Set the per-byte or per-column observation budget.', '--row': 'Choose the first simulated SM4 byte position.', '--column': 'Compatibility setting parsed but not used by this SM4 entry point.', '--seed': 'Used for AES mask sampling in run.py; not used for SM4 mask order.'}

        return 'Register ' + arg + '. ' + extra[arg]

    if text.startswith('args = parser.parse_args'):
        return 'Decode the supplied argument list (or process command line) and enforce the declared argument types and choices.'

    if text.startswith('parser.error'):
        return 'Report invalid configuration and terminate argument processing rather than starting an invalid experiment.'

    if text.startswith('raise '):
        return 'Stop this path with the stated exception. The message identifies the violated input, model or verification condition; no recovered key is accepted by this line.'

    if text.startswith('if not 1 <= args.'):
        return 'Reject an observation budget outside 1..255 before requesting any faulty outputs.'

    if text.startswith('import run'):
        return 'Load the shared terminal controller at call time. This avoids a top-level circular import between attack and presentation modules.'

    if text.startswith('try:'):
        return 'Begin a protected configuration-validation block; the associated except path turns invalid input into a parser error.'

    if text.startswith('terminal.section'):
        return 'Print the named teaching-section boundary. This affects terminal/log organization only and does not advance the target or the solver.'

    if text.startswith('terminal.pause'):
        return 'Wait for Enter only if --step is enabled. Pausing does not change a state word, create a fault or alter a candidate set.'

    if text.startswith('terminal.pair') or text.startswith('terminal.compare'):
        return 'Compare the two supplied byte arrays visually, compute their XOR and color changed positions red. The data is not modified.'

    if text.startswith('attack_steps.emit'):
        if '.sm4_observation(' in text:
            return 'Print every detailed stage for this observation: restored views, inverse-L contributions, candidate tests and intersection. The previous display set is passed only for explanation.'

        if '.sm4_fault_trace(' in text:
            return 'Print teacher-only fault propagation from the target trace. This exposes intermediate values for learning, but none are returned as solver inputs.'

        if '.verification(' in text:
            return 'Run and print recovered-key encryption/decryption consistency checks on the ordinary cipher.'

        if '.aes_piret(' in text:
            return 'Print exhaustive AES byte guesses and shared-error quartet patterns; this branch is not used in SM4-only execution.'

        return 'Print the numerical teaching events already generated by the schedule helper. This is explanatory replay, not additional fault collection.'

    for prefix, description in RULES:
        if text.startswith(prefix):
            return description

    raise RuntimeError('Missing authored line explanation: ' + text)


def tex_escape(text):
    replacements = {'\\': r'\textbackslash{}', '{': r'\{', '}': r'\}', '_': r'\_', '%': r'\%', '#': r'\#', '&': r'\&', '$': r'\$', '^': r'\textasciicircum{}', '~': r'\textasciitilde{}'}

    formatted_values = []

    for column in text:
        formatted_values.append(replacements.get(column, column))

    return ''.join(formatted_values)


def generate_line_guide(root, folder):
    """Pair full numbered source with one entry per executable physical line."""

    sections, coverage = [], []

    for filename in ('piret_sm4.py', 'run.py'):
        path = root / 'src' / filename

        source = path.read_text(encoding='utf-8')

        source_lines = source.splitlines()

        nodes = []

        for candidate_node in ast.parse(source).body:
            if isinstance(candidate_node, (ast.FunctionDef, ast.ClassDef)):
                nodes.append(candidate_node)

        sections.append(r'\chapter{Line-by-line: \texttt{' + tex_escape(filename) + '}}')

        for fn in nodes:
            purpose, inputs, action, outputs, reality = FUNCTIONS[(filename, fn.name)]
            element_values_2 = []

            for d in fn.decorator_list:
                element_values_2.append(d.lineno)

            first_line = min([fn.lineno] + element_values_2)
            basename = 'annotated_' + filename[:-3] + '_' + fn.name + '.txt'
            (folder / basename).write_text('\n'.join(source_lines[first_line-1:fn.end_lineno]) + '\n', encoding='utf-8')
            sections += [r'\section{\texttt{' + tex_escape(fn.name) + '}}', tex_escape(purpose), r'\begin{center}\begin{tikzpicture}[node distance=4mm]', r'\node[box,text width=100mm] (input) {' + tex_escape(inputs) + '};', r'\node[box,below=of input,text width=100mm] (action) {' + tex_escape(action) + '};', r'\node[box,below=of action,text width=100mm] (output) {' + tex_escape(outputs) + '};', r'\draw[flow](input)--(action);\draw[flow](action)--(output);', r'\end{tikzpicture}\end{center}', r'\remember{\textbf{Physical interpretation:} ' + tex_escape(reality) + '}', r'\subsection*{Exact source}', r'\VerbatimInput[firstnumber=' + str(first_line) + ']{generated/' + basename + '}', r'\subsection*{Read each executable line}', r'\begingroup\small\begin{longtable}{r >{\raggedright\arraybackslash}p{138mm}}\toprule Line&Meaning and effect\\\midrule\endfirsthead\toprule Line&Meaning and effect\\\midrule\endhead']
            explanations = {}
            doc_lines = set()
            branches = {}

            for node in ast.walk(fn):
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    doc_lines.update(range(node.lineno, node.end_lineno+1))
                elif isinstance(node, ast.stmt):
                    explanations[node.lineno] = explain(node, source_lines[node.lineno-1], purpose)

                if isinstance(node, (ast.If, ast.For)) and node.orelse:
                    first_alternative = node.orelse[0].lineno

                    for branch_line in range(node.body[-1].end_lineno+1, first_alternative):
                        if source_lines[branch_line-1].strip() == 'else:':
                            if isinstance(node, ast.For):
                                computed_value = 'The for-loop beginning at line ' + str(node.lineno) + ' exhausted its observation budget without break; execute the following ambiguity result.'
                            else:
                                computed_value = 'The if-condition at line ' + str(node.lineno) + ' was false; follow this alternative path rather than the preceding branch.'

                            branches[branch_line] = computed_value

            for decorator in fn.decorator_list:
                explanations[decorator.lineno] = 'Cache the public inverse-matrix result after the first calculation. The matrix is key-independent and is not recomputed for every observation.'

            for number in range(first_line, fn.end_lineno+1):
                text = source_lines[number-1].strip()

                if not text or text.startswith('#') or number in doc_lines:
                    continue

                if number in explanations:
                    meaning = explanations[number]
                elif text.startswith('else:'):
                    meaning = branches[number]
                elif text.startswith('except '):
                    meaning = 'Catch the named validation exception and report its message through the command-line parser.'
                else:
                    element_values = []

                    for candidate_number in explanations:
                        if candidate_number < number:
                            element_values.append(candidate_number)

                    prior = max(element_values, default=fn.lineno)
                    meaning = 'Continue the same multi-line statement begun at source line ' + str(prior) + '; no separate operation occurs on this continuation line.'

                sections.append(str(number) + '&' + tex_escape(meaning) + r'\\')
                coverage.append((filename, fn.name, number))

            sections += [r'\bottomrule\end{longtable}\endgroup']

    (folder / 'line_by_line.tex').write_text('\n'.join(sections), encoding='utf-8')

    return coverage

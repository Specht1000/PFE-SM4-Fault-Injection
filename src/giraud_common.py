"""Shared single-bit fault validation and candidate intersections."""
SINGLE_BITS = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)


def validate_mask(mask):
    """Reject masks that flip zero bits or more than one bit."""

    # Membership rejects zero and every multi-bit mask, not just out-of-range bytes.
    if mask not in SINGLE_BITS:
        raise ValueError("Single-bit mask required: 01, 02, 04, 08, 10, 20, 40 or 80.")


def masks_for(first, maximum):
    """Return distinct one-bit faults, starting with the selected bit."""

    validate_mask(first)

    # Put the requested mask first, then use other distinct one-bit masks.
    if not 1 <= maximum <= 8:
        raise ValueError("Use 1..8 distinct bit observations per target byte.")

    # Do not repeat masks: repeating the same deterministic observation adds no constraint.
    result_values = []

    for mask in SINGLE_BITS:
        if mask != first:
            result_values.append(mask)

    return ([first] + result_values)[:maximum]


def intersect_candidates(previous, current):
    """Keep only key-byte values compatible with every observation so far.

    None marks the first observation. Multiple survivors mean ambiguity;
    exactly one means the byte is recovered. Never choose an arbitrary value.
    """

    if previous is None:
        survivors = set(current)
    else:
        survivors = previous & current

    # The first observation starts the set; later observations only narrow it.
    if not survivors:
        raise ValueError("No compatible Giraud candidates; check the fault model.")

    return survivors


def recover_byte(candidate_function, observations):
    """Recover one byte from (correct, faulty[, known_mask]) observations.

    All observations must concern the same output/subkey byte and target key.
    Return (position, survivors). No observations returns (None, None).
    This helper does not read configuration, simulate faults or display results.
    """

    position, survivors = None, None

    for observation in observations:
        # Candidate functions inspect outputs only; no target key enters this helper.
        current_position, current = candidate_function(*observation)[:2]

        if position is not None and current_position != position:
            # Intersecting guesses for different key bytes would be meaningless.
            raise ValueError("Observations must affect the same key byte.")

        position = current_position

        # Accumulate constraints across observations for the same key byte.
        survivors = intersect_candidates(survivors, current)

    return position, survivors


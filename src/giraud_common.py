"""Shared single-bit fault validation and candidate intersections."""
SINGLE_BITS = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)


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


def intersect_candidates(previous, current):
    """Keep only key-byte values compatible with every observation so far.

    None marks the first observation. Multiple survivors mean ambiguity;
    exactly one means the byte is recovered. Never choose an arbitrary value.
    """
    survivors = set(current) if previous is None else previous & current
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
        current_position, current = candidate_function(*observation)[:2]
        if position is not None and current_position != position:
            raise ValueError("Observations must affect the same key byte.")
        position = current_position
        survivors = intersect_candidates(survivors, current)
    return position, survivors


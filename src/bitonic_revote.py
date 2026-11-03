"""Bitonic sorting + last-legitimate-revote resolution (PLAINTEXT demo).

IMPORTANT: This is not an oblivious MPC computation. Both the nullifiers and
is_legit flags are processed openly by Python. A real coercion-resistant design
would require authenticated/private flags and MPC compare/swap operations.
"""
from dataclasses import dataclass
from typing import Dict, List, Sequence


@dataclass(frozen=True)
class Ballot:
    nullifier: int
    sequence_number: int
    is_legit: bool
    one_hot: tuple
    is_padding: bool = False


@dataclass
class SortResult:
    incoming: List[Ballot]
    ordered: List[Ballot]                 # Includes padding up to power of 2
    selected: List[Ballot]                # Last legitimate ballot per nullifier
    status_by_sequence: Dict[int, str]   # COUNTED, SUPERSEDED, DECOY
    tally: List[int]


def _key(ballot: Ballot):
    """Sort padding last, group nullifiers, decoys before legitimate ballots,
    then order legitimate submissions by their trusted arrival sequence.
    """
    return (int(ballot.is_padding), ballot.nullifier,
            int(ballot.is_legit), ballot.sequence_number)


def _validate(ballots: Sequence[Ballot], k_candidates: int) -> None:
    if k_candidates < 1:
        raise ValueError("k_candidates must be >= 1")
    seen_sequences = set()
    for ballot in ballots:
        if ballot.is_padding:
            raise ValueError("Padding records are internal only")
        if not isinstance(ballot.nullifier, int) or ballot.nullifier < 0:
            raise ValueError("Nullifier must be a non-negative integer")
        if type(ballot.is_legit) is not bool:
            raise ValueError("is_legit must be bool")
        if not isinstance(ballot.sequence_number, int) or ballot.sequence_number < 0:
            raise ValueError("sequence_number must be a non-negative integer")
        if ballot.sequence_number in seen_sequences:
            raise ValueError("Gateway sequence_number must be globally unique")
        seen_sequences.add(ballot.sequence_number)
        if (len(ballot.one_hot) != k_candidates
                or any(type(x) is not int or x not in (0, 1) for x in ballot.one_hot)
                or sum(ballot.one_hot) != 1):
            raise ValueError("Invalid one-hot vote")


def bitonic_sort(ballots: Sequence[Ballot], k_candidates: int) -> List[Ballot]:
    """Classic bitonic comparator network: fixed compare/swap positions.

    Returns padding too, so the padded network can be audited. Comparisons
    and conditional swaps are ordinary Python (not oblivious).
    """
    rows = list(ballots)
    _validate(rows, k_candidates)
    if not rows:
        return []   # Nothing to sort
    size = 1 << (len(rows) - 1).bit_length()    # Next power of 2
    dummy = Ballot(0, 0, False, (0,) * k_candidates, True)  # Padding row
    rows += [dummy] * (size - len(rows))    # Pad to power of 2 for bitonic network
    k = 2   # Bitonic network size (2, 4, 8, 16, ...)
    while k <= size:
        j = k // 2  # Distance between positions (half the size of the current bitonic sequence)
        while j:
            for i in range(size):
                partner = i ^ j # Bitwise XOR to find the partner index
                if partner > i:
                    ascending = (i & k) == 0
                    should_swap = ((_key(rows[i]) > _key(rows[partner])) if ascending
                                   else (_key(rows[i]) < _key(rows[partner])))
                    if should_swap:
                        rows[i], rows[partner] = rows[partner], rows[i]
            j //= 2
        k *= 2
    return rows


def resolve_revoting(ballots: Sequence[Ballot], k_candidates: int) -> SortResult:
    incoming = list(ballots)
    ordered = bitonic_sort(incoming, k_candidates)
    selected = []
    statuses = {}
    for i, ballot in enumerate(ordered):
        if ballot.is_padding:
            continue
        if not ballot.is_legit:
            statuses[ballot.sequence_number] = "DECOY"
            continue
        # Legitimate votes follow all decoys within the same nullifier group,
        # with increasing arrival sequence. The final one is the one to count.
        next_ballot = ordered[i + 1] if i + 1 < len(ordered) else None
        last_for_voter = (next_ballot is None or next_ballot.is_padding
                          or next_ballot.nullifier != ballot.nullifier)
        if last_for_voter:
            statuses[ballot.sequence_number] = "COUNTED"
            selected.append(ballot)
        else:
            statuses[ballot.sequence_number] = "SUPERSEDED"
    tally = [0] * k_candidates
    for ballot in selected:
        for candidate, value in enumerate(ballot.one_hot):
            tally[candidate] += value
    assert sum(tally) == len(selected)
    return SortResult(incoming, ordered, selected, statuses, tally)


def print_sort_audit(result: SortResult, *, show_all: bool = False,
                     demo_labels=None) -> None:
    """Show before/after with optional full listing (including dummy rows)."""
    demo_labels = demo_labels or {}
    counts = {}
    for ballot in result.incoming:
        counts[ballot.nullifier] = counts.get(ballot.nullifier, 0) + 1
    repeated = {key for key, count in counts.items() if count > 1}
    visible = lambda b: show_all or b.nullifier in repeated

    def describe(b):
        tag = demo_labels.get(b.nullifier, f"{b.nullifier:08x}"[-8:])
        return (f"seq={b.sequence_number:>3}  voter={tag:<12}  "
                f"candidate={b.one_hot.index(1)}  "
                f"is_legit={str(b.is_legit):<5}  "
                f"-> {result.status_by_sequence[b.sequence_number]}")

    print("\n--- BEFORE BITONIC SORT (submission/arrival order) ---")
    for b in result.incoming:
        if visible(b):
            print(describe(b))
    if not show_all:
        print("(Only repeated nullifiers shown; set show_all=True to display all ballots)")

    print("\n--- AFTER BITONIC SORT (nullifier, is_legit, sequence) ---")
    for b in result.ordered:
        if b.is_padding:
            if show_all:
                print("[PADDING]")
        elif visible(b):
            print(describe(b))

    print("\n--- REVOTING SUMMARY ---")
    print(f"Gateway-admitted submissions: {len(result.incoming)}")
    print(f"Padded network positions:     {len(result.ordered)}")
    print(f"Repeated-nullifier groups:   {len(repeated)}")
    print(f"Superseded legitimate votes: {list(result.status_by_sequence.values()).count('SUPERSEDED')}")
    print(f"Decoy ballots ignored:       {list(result.status_by_sequence.values()).count('DECOY')}")
    print(f"Unique votes counted:        {len(result.selected)}")
    print(f"Tally after revoting:        {result.tally}")


def demo() -> None:
    """Small deterministic example for auditing by eye."""
    ballots = [
        Ballot(101, 1, True,  (1, 0, 0, 0)), # alice's first vote
        Ballot(202, 2, True,  (0, 1, 0, 0)), # bob's first vote
        Ballot(303, 3, True,  (0, 0, 1, 0)), # carol's vote
        Ballot(202, 4, True,  (1, 0, 0, 0)), # bob revotes
        Ballot(101, 5, True,  (0, 1, 0, 0)), # alice revotes
        Ballot(101, 6, False, (0, 0, 1, 0)), # later decoy: ignored
    ]
    result = resolve_revoting(ballots, 4)
    print_sort_audit(result, show_all=True, demo_labels={101:"Alice", 202:"Bob", 303:"Carol"})
    assert result.tally == [1, 1, 1, 0]
    assert {b.sequence_number for b in result.selected} == {3, 4, 5}
    print("\nDEMO PASSED: 6 submissions -> 3 counted, final tally [1, 1, 1, 0]")


if __name__ == "__main__":
    demo()

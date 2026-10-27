"""Standalone exhaustive matching oracle for issue #15 (Python 3 stdlib).

Run: python scripts/reproduce_corroboration_matching.py
No network, credentials, project installation or third-party dependencies.
This is an algorithm reproduction, NOT a test of trusted provenance or write gates.
"""
from itertools import combinations, product


def maximum_matching(pairs):
    edges = {}
    for domain, origin in pairs:
        edges.setdefault(domain, set()).add(origin)
    occupied = {}

    def augment(domain, seen):
        for origin in sorted(edges[domain]):
            if origin in seen:
                continue
            seen.add(origin)
            if origin not in occupied or augment(occupied[origin], seen):
                occupied[origin] = domain
                return True
        return False

    for domain in sorted(edges):
        augment(domain, set())
    return len(occupied)


def exhaustive_optimum(pairs):
    return max(
        (
            size
            for size in range(4)
            for subset in combinations(pairs, size)
            if len({domain for domain, _ in subset}) == size
            and len({origin for _, origin in subset}) == size
        ),
        default=0,
    )


def main():
    universe = list(product("ABC", "XYZ"))
    for mask in range(1 << len(universe)):
        selected = [
            pair for index, pair in enumerate(universe) if mask & (1 << index)
        ]
        observed = maximum_matching(selected)
        expected = exhaustive_optimum(selected)
        assert observed == expected, (mask, observed, expected)
    print("PASS: 512/512 graphs agree with exhaustive optimum")


if __name__ == "__main__":
    main()

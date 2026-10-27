"""Layer 3 — Policy compiler: business rules + graph -> data/policy.json."""

# TODO (Layer 3, Day 5): implement per sentinel-build-spec.md Prompt 4.
# Read data/business_rules.txt + data/graph.json, call muse-spark-1.3
# with structured output, write data/policy.json as rules
# {subject, action, resource, conditions, effect}. Flag uncompilable
# rules; never silently drop them.


def main() -> None:
    raise NotImplementedError("TODO (Layer 3): implement policy.py")


if __name__ == "__main__":
    main()

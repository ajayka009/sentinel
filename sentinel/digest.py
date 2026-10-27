"""Layer 1 — Digest / Scout: registry + configs -> data/graph.json."""

# TODO (Layer 1, Day 3): implement per sentinel-build-spec.md Prompt 2.
# Read data/registry.yaml + PLC register map, call muse-spark-1.3 with
# structured output, attach SAM 3.1 segmentation of sim/camera_frames/*,
# write data/graph.json. The registry is the source of truth: reject any
# model-introduced component not in it.


def main() -> None:
    raise NotImplementedError("TODO (Layer 1): implement digest.py")


if __name__ == "__main__":
    main()

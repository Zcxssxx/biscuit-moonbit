"""Bidirectional mixed-algorithm tokens, third-party signatures and proof checks."""
import os
from pathlib import Path
import json
from interop import run, rust, fields


def moon(values):
    env = os.environ.copy()
    env.update(values)
    return run(["moon", "run", "--target", "native", "examples/algorithms"], env)


def main():
    reference = rust("algorithm-matrix")
    rows = []
    for line in reference.splitlines():
        if line.startswith("REFERENCE_MATRIX "):
            rows.append({"id": line.split()[1].rstrip(":")})
        elif line.startswith("REFERENCE_"):
            key, value = line.split("=", 1)
            rows[-1][key] = value
    assert len(rows) == 8
    report = []
    for row in rows:
        root, next_key, external = row["id"]
        values = {"ROOT_ALGORITHM": root, "NEXT_ALGORITHM": next_key,
                  "EXTERNAL_ALGORITHM": external, "MATRIX_MODE": "mint"}
        minted = fields(moon(values))
        values.update(ROOT_KEY=minted["ROOT_KEY"])
        for name in ["TOKEN", "SEALED"]:
            values["TOKEN"] = minted[name]
            assert rust("algorithm-verify", values) == "VALID"
        values["TOKEN"] = minted["TOKEN"]
        rust_extended = fields(rust("algorithm-append", values))["TOKEN"]
        values.update(TOKEN=rust_extended, MATRIX_MODE="append")
        moon_extended = fields(moon(values))["TOKEN"]
        values["TOKEN"] = moon_extended
        assert rust("algorithm-verify", values) == "VALID"
        values.update(ROOT_KEY=row["REFERENCE_ROOT"], TOKEN=row["REFERENCE_TOKEN"])
        appended = fields(moon(values))["TOKEN"]
        values["TOKEN"] = appended
        assert rust("algorithm-verify", values) == "VALID"
        values.update(TOKEN=row["REFERENCE_SEALED"], MATRIX_MODE="sealed")
        assert moon(values) == "SEALED_VALID"
        report.append({"algorithms": row["id"], "status": "PASS"})
        print(f"MoonBit / Rust algorithm matrix {row['id']}: PASS", flush=True)
    Path("_build/algorithm-interop.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Bidirectional algorithm matrix: 8/8 passed")


if __name__ == "__main__":
    main()

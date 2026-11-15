"""Run bidirectional MoonBit / pinned biscuit-rust interoperability checks."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUST_MANIFEST = ROOT / "tools" / "biscuit-rust-interop" / "Cargo.toml"
ROOT_PUBLIC_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def run(command: list[str], env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def rust(mode: str, values: dict[str, str] | None = None) -> str:
    env = os.environ.copy()
    if values:
        env.update(values)
    return run(
        [
            "cargo",
            "run",
            "--quiet",
            "--manifest-path",
            str(RUST_MANIFEST),
            "--",
            mode,
        ],
        env,
    )


def fields(output: str) -> dict[str, str]:
    parsed = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            parsed[key] = value
    return parsed


def moonbit_authorize(token: str, root_key: str, query: str) -> str:
    env = os.environ.copy()
    env.update(
        {
            "BISCUIT_TOKEN": token,
            "BISCUIT_ROOT_PUBLIC_KEY": root_key,
            "BISCUIT_POLICY": query,
        }
    )
    return run(["moon", "run", "--target", "native", "examples/interop"], env)


def rust_authorize(token: str, root_key: str, query: str) -> str:
    return rust(
        "authorize",
        {
            "BISCUIT_TOKEN": token,
            "BISCUIT_ROOT_PUBLIC_KEY": root_key,
            "BISCUIT_POLICY": query,
        },
    )


def assert_parity(
    label: str, token: str, root_key: str, query: str, expected: str
) -> None:
    moonbit_result = moonbit_authorize(token, root_key, query)
    rust_result = rust_authorize(token, root_key, query)
    assert moonbit_result == rust_result, (
        f"{label}: MoonBit={moonbit_result}, biscuit-rust={rust_result}"
    )
    assert moonbit_result == expected, (
        f"{label}: expected {expected}, got {moonbit_result}"
    )
    print(
        f"{label}: {moonbit_result} "
        f"(MoonBit and biscuit-rust agree; policy: {query})"
    )


def main() -> None:
    if shutil.which("cargo") is None:
        print(
            "Rust interoperability checks require cargo; install the Rust toolchain first.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    moonbit_token = run(["moon", "run", "--target", "native", "examples/issue"])
    assert_parity(
        "MoonBit-issued and attenuated token",
        moonbit_token,
        ROOT_PUBLIC_KEY,
        'eligible($n), $n >= 10',
        "ALLOW",
    )
    assert_parity(
        "MoonBit token policy denial",
        moonbit_token,
        ROOT_PUBLIC_KEY,
        'eligible($n), $n > 100',
        "DENY",
    )

    rust_tokens = fields(rust("mint"))
    rust_root = rust_tokens["ROOT_PUBLIC_KEY"]
    assert_parity(
        "biscuit-rust authority token",
        rust_tokens["RUST_TOKEN"],
        rust_root,
        "interop_allow(true)",
        "ALLOW",
    )
    assert_parity(
        "biscuit-rust attenuation",
        rust_tokens["RUST_ATTENUATED"],
        rust_root,
        "attenuated(true)",
        "ALLOW",
    )

    env = os.environ.copy()
    env.update(
        {
            "BISCUIT_TOKEN": rust_tokens["RUST_TOKEN"],
            "BISCUIT_ROOT_PUBLIC_KEY": rust_root,
        }
    )
    moonbit_attenuated = fields(
        run(["moon", "run", "--target", "native", "examples/attenuate_rust"], env)
    )["MOONBIT_ATTENUATED"]
    assert_parity(
        "MoonBit attenuation of a biscuit-rust token",
        moonbit_attenuated,
        rust_root,
        "moonbit_attenuated(true)",
        "ALLOW",
    )

    moonbit_third_party = fields(
        run(["moon", "run", "--target", "native", "examples/third_party"])
    )
    assert_parity(
        "MoonBit third-party base token",
        moonbit_third_party["MOONBIT_TOKEN"],
        moonbit_third_party["ROOT_PUBLIC_KEY"],
        "true",
        "DENY",
    )
    assert_parity(
        "MoonBit-signed and appended third-party block",
        moonbit_third_party["MOONBIT_APPENDED_TOKEN"],
        moonbit_third_party["ROOT_PUBLIC_KEY"],
        "true",
        "ALLOW",
    )
    rust_appended_moonbit_block = fields(
        rust(
            "append-moonbit-third-party",
            {
                "BISCUIT_TOKEN": moonbit_third_party["MOONBIT_TOKEN"],
                "BISCUIT_ROOT_PUBLIC_KEY": moonbit_third_party[
                    "ROOT_PUBLIC_KEY"
                ],
                "BISCUIT_THIRD_PARTY_CONTENTS": moonbit_third_party[
                    "THIRD_PARTY_CONTENTS"
                ],
                "BISCUIT_EXTERNAL_PUBLIC_KEY": moonbit_third_party[
                    "EXTERNAL_PUBLIC_KEY"
                ],
            },
        )
    )
    assert rust_appended_moonbit_block["BASE"] == "DENY"
    assert rust_appended_moonbit_block["APPENDED"] == "ALLOW"
    assert_parity(
        "MoonBit-signed third-party block appended by biscuit-rust",
        rust_appended_moonbit_block["APPENDED_TOKEN"],
        moonbit_third_party["ROOT_PUBLIC_KEY"],
        "true",
        "ALLOW",
    )

    rust_third_party = fields(rust("mint-third-party"))
    assert_parity(
        "biscuit-rust third-party base token",
        rust_third_party["RUST_THIRD_PARTY_BASE"],
        rust_third_party["ROOT_PUBLIC_KEY"],
        "true",
        "DENY",
    )
    assert_parity(
        "biscuit-rust-signed third-party block",
        rust_third_party["RUST_THIRD_PARTY_APPENDED"],
        rust_third_party["ROOT_PUBLIC_KEY"],
        "true",
        "ALLOW",
    )

    print("All bidirectional Biscuit interoperability checks passed.")


if __name__ == "__main__":
    main()

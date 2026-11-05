"""Optional interoperability check; install biscuit-python==0.4.0 first.

This uses only published test keys. Run from the repository root.
"""
import base64
import subprocess

from biscuit_auth import Biscuit, PublicKey

encoded = subprocess.check_output(["moon", "run", "examples/issue"], text=True).strip()
root = PublicKey("ed25519/d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
token = Biscuit.from_bytes(base64.b64decode(encoded), root)
assert token.block_count() == 2
print("biscuit-python accepted the two-block MoonBit token")

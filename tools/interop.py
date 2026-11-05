"""Optional interoperability check; install biscuit-python==0.4.0 first.

This uses only published test keys. Run from the repository root.
"""
import base64
import subprocess

from biscuit_auth import Biscuit, PublicKey

encoded = subprocess.check_output(["moon", "run", "examples/issue"], text=True).strip()
root = PublicKey("ed25519/d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
padding = "=" * (-len(encoded) % 4)
token = Biscuit.from_bytes(base64.urlsafe_b64decode(encoded + padding), root)
assert token.block_count() == 2
authority = token.block_source(0)
attenuation = token.block_source(1)
print("Authority block decoded by biscuit-python:")
print(authority)
print("Attenuation block decoded by biscuit-python:")
print(attenuation)
assert "eligible" in authority and "item" in authority
assert "eligible" in attenuation and "check" in attenuation
print("biscuit-python parsed the structured rule, comparison and check")

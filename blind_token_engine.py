"""
blind_token_engine.py
Chaumian RSA Blind Signature Issuer and Nullifier Verification Pool.
Provides voter credential unlinkability and double-spending detection.
"""

import hashlib
import secrets
from typing import Tuple, Set, Dict, Optional
from cryptography.hazmat.primitives.asymmetric import rsa


class RegistrarAuthority:
    """Registrar issuing blind signatures over voter identity-blinded tokens."""
    def __init__(self, key_size: int = 2048):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        pub_numbers = self.key.public_key().public_numbers()
        self.n = pub_numbers.n
        self.e = pub_numbers.e
        self.d = self.key.private_numbers().d
        self.authorized_voters: Dict[str, bool] = {}

    def register_voter(self, voter_id: str):
        """Authorizes a voter to request one blind signature."""
        self.authorized_voters[voter_id] = False  # False = token not yet claimed

    def issue_blind_signature(self, voter_id: str, blinded_token: int) -> Optional[int]:
        """
        Signs the blinded payload: s' = (m')^d mod n.
        Fails if voter is unauthorized or has already drawn a signature.
        """
        if voter_id not in self.authorized_voters:
            return None
        if self.authorized_voters[voter_id]:
            return None  # Replay prevention at the registration desk

        self.authorized_voters[voter_id] = True
        return pow(blinded_token, self.d, self.n)

    def get_public_key(self) -> Tuple[int, int]:
        return self.n, self.e


class VoterTokenHandler:
    """Client-side token blinding, signature unblinding, and nullifier generation."""
    def __init__(self, registrar_n: int, registrar_e: int):
        self.n = registrar_n
        self.e = registrar_e
        self.token = secrets.token_bytes(32)

        # Hash raw token to integer in Z_n
        digest = hashlib.sha256(self.token).digest()
        self.m = int.from_bytes(digest, "big") % self.n

        # Select random blinding factor r coprime to n
        while True:
            self.r = secrets.randbelow(self.n - 2) + 2
            try:
                self.r_inv = pow(self.r, -1, self.n)
                break
            except ValueError:
                continue

    def generate_blinded_token(self) -> int:
        """m' = (m * r^e) mod n."""
        return (self.m * pow(self.r, self.e, self.n)) % self.n

    def unblind_signature(self, blind_signature: int) -> int:
        """s = s' * r^(-1) mod n."""
        self.unblinded_sig = (blind_signature * self.r_inv) % self.n
        return self.unblinded_sig

    def get_token_hash_int(self) -> int:
        return self.m

    def get_nullifier(self) -> str:
        """Derives a single-use public nullifier: H(token || 'nullifier')."""
        return hashlib.sha256(self.token + b":nullifier").hexdigest()


class NullifierVerificationPool:
    """Public Bulletin Board state component tracking spent credentials."""
    def __init__(self, registrar_n: int, registrar_e: int):
        self.n = registrar_n
        self.e = registrar_e
        self.spent_nullifiers: Set[str] = set()

    def verify_and_spend(self, token_hash_int: int, unblinded_signature: int, nullifier: str) -> Tuple[bool, str]:
        """
        1. Verifies that s^e == m (mod n) under Registrar's public key.
        2. Ensures nullifier has not been recorded before.
        """
        # RSA Signature verification: s^e mod n == m
        if pow(unblinded_signature, self.e, self.n) != (token_hash_int % self.n):
            return False, "FORGERY: Unblinded signature is invalid for the presented token."

        # Nullifier collision / replay detection
        if nullifier in self.spent_nullifiers:
            return False, f"REPLAY: Nullifier {nullifier[:12]}... already spent. Double vote rejected."

        self.spent_nullifiers.add(nullifier)
        return True, "VALID: Signature verified and nullifier recorded."
"""
paillier_engine.py
Paillier Cryptosystem Configuration and Benchmarking Suite.
Based on the additive aggregation model in Rahman et al. (2021).
"""

import time
from typing import List, Tuple, Dict, Any
from phe import paillier


class PaillierEngine:
    def __init__(self, key_size: int = 1024):
        """
        Initializes Paillier keypair based on configured bit length.
        Rahman et al. evaluate key sizes across 1024 and 2048 bits for e-voting latency.
        """
        self.key_size = key_size
        self.pubkey, self.privkey = paillier.generate_paillier_keypair(n_length=key_size)
        self.n = self.pubkey.n
        self.nsquare = self.pubkey.nsquare

    def encrypt_scalar(self, plaintext: int) -> Tuple[paillier.EncryptedNumber, int]:
        """
        Encrypts an integer message m: c = g^m * r^n mod n^2.
        Returns both the EncryptedNumber and the blinding factor r used.
        """
        # phe handles r internally; we expose the EncryptedNumber
        ciphertext = self.pubkey.encrypt(plaintext)
        return ciphertext, ciphertext.obfuscator

    def encrypt_vector(self, vector: List[int]) -> List[paillier.EncryptedNumber]:
        """Maps an indicator vector (v_1, ..., v_M) into Paillier ciphertexts."""
        return [self.pubkey.encrypt(val) for val in vector]

    def add_ciphertexts(
        self, c1: paillier.EncryptedNumber, c2: paillier.EncryptedNumber
    ) -> paillier.EncryptedNumber:
        """Homomorphic addition: E(m1) * E(m2) mod n^2 = E(m1 + m2)."""
        return c1 + c2

    def homomorphic_sum_vector(
        self, ciphertext_matrix: List[List[paillier.EncryptedNumber]]
    ) -> List[paillier.EncryptedNumber]:
        """
        Aggregates N ballots across M candidates column-wise:
        C_j = prod_{i=1}^N c_{i,j} mod n^2
        """
        num_voters = len(ciphertext_matrix)
        num_candidates = len(ciphertext_matrix[0])
        accumulated = list(ciphertext_matrix[0])

        for i in range(1, num_voters):
            for j in range(num_candidates):
                accumulated[j] = accumulated[j] + ciphertext_matrix[i][j]
        return accumulated

    def decrypt(self, ciphertext: paillier.EncryptedNumber) -> int:
        """Central authority decrypts accumulated sums."""
        return self.privkey.decrypt(ciphertext)


def benchmark_paillier(key_sizes: List[int] = [1024, 2048], num_voters: int = 5, num_candidates: int = 3) -> List[Dict[str, Any]]:
    """Benchmarks key generation, encryption, accumulation, and decryption in ms."""
    results = []

    for k in key_sizes:
        # Keygen
        t0 = time.perf_counter()
        engine = PaillierEngine(key_size=k)
        keygen_ms = (time.perf_counter() - t0) * 1000

        # Vector Encryption (Single Voter: 3 candidates)
        sample_vote = [1, 0, 0]
        t0 = time.perf_counter()
        ciphers = engine.encrypt_vector(sample_vote)
        enc_ms = (time.perf_counter() - t0) * 1000

        # Homomorphic Accumulation (N = 5 voters, M = 3 candidates)
        matrix = [engine.encrypt_vector(sample_vote) for _ in range(num_voters)]
        t0 = time.perf_counter()
        tally = engine.homomorphic_sum_vector(matrix)
        accum_ms = (time.perf_counter() - t0) * 1000

        # Decryption (M = 3 candidates)
        t0 = time.perf_counter()
        plain_tally = [engine.decrypt(tally[j]) for j in range(num_candidates)]
        dec_ms = (time.perf_counter() - t0) * 1000

        results.append({
            "key_size_bits": k,
            "keygen_ms": round(keygen_ms, 2),
            "encryption_3vec_ms": round(enc_ms, 2),
            "accumulation_5voters_ms": round(accum_ms, 4),
            "decryption_3candidates_ms": round(dec_ms, 2),
            "verified_sums": plain_tally
        })
    return results
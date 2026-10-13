"""
run_verification.py
Runs the complete Member 1 Cryptographic Test & Benchmark Suite.
"""

from paillier_engine import PaillierEngine, benchmark_paillier
from zkp_engine import DisjunctiveProofEngine
from blind_token_engine import RegistrarAuthority, VoterTokenHandler, NullifierVerificationPool


def main():
    print("=" * 70)
    print("MEMBER 1: CRYPTOGRAPHY & STATE VERIFICATION ENGINE")
    print("=" * 70)

    # 1. Benchmark Paillier
    print("\n[+] Running Paillier Benchmarking Suite (Rahman et al. Methodology)...")
    benchmarks = benchmark_paillier(key_sizes=[1024, 2048], num_voters=5, num_candidates=3)
    for b in benchmarks:
        print(f"  - Key Size: {b['key_size_bits']} bits")
        print(f"    • Keygen Latency:         {b['keygen_ms']} ms")
        print(f"    • 3-Vector Encryption:    {b['encryption_3vec_ms']} ms")
        print(f"    • 5-Voter Accumulation:   {b['accumulation_5voters_ms']} ms")
        print(f"    • 3-Candidate Decryption: {b['decryption_3candidates_ms']} ms")
        print(f"    • Accumulated Sums:       {b['verified_sums']}")

    # 2. Test ZKP Multi-Candidate Disjunctive Proof
    print("\n[+] Testing ZKP Multi-Candidate Disjunctive Engine...")
    pe = PaillierEngine(key_size=1024)
    valid_vote = [0, 1, 0]  # Vote for Candidate B
    ciphers = pe.encrypt_vector(valid_vote)

    proof = DisjunctiveProofEngine.prove_ballot_validity(pe.pubkey, valid_vote, ciphers)
    is_valid = DisjunctiveProofEngine.verify_ballot_validity(pe.pubkey, ciphers, proof)
    print(f"  • Honest Ballot Proof [0, 1, 0]: Verified = {is_valid}")
    assert is_valid, "Valid proof failed verification!"

    # Adversarial Injection: Illegal weight vector [2, 0, 0]
    illegal_vote = [2, 0, 0]
    illegal_ciphers = pe.encrypt_vector(illegal_vote)
    malicious_proof = DisjunctiveProofEngine.prove_ballot_validity(pe.pubkey, illegal_vote, illegal_ciphers)
    malicious_verified = DisjunctiveProofEngine.verify_ballot_validity(pe.pubkey, illegal_ciphers, malicious_proof)
    print(f"  • Adversarial Ballot Proof [2, 0, 0]: Verified = {malicious_verified}")
    assert not malicious_verified, "Malicious proof was incorrectly accepted!"

    # 3. Test Chaumian Blind Signatures and Nullifier Pool
    print("\n[+] Testing Chaumian Blind Signatures & Nullifier Pool...")
    reg = RegistrarAuthority(key_size=2048)
    reg.register_voter("voter_alice")
    n, e = reg.get_public_key()
    pool = NullifierVerificationPool(n, e)

    # Alice obtains blind signature
    alice = VoterTokenHandler(n, e)
    m_prime = alice.generate_blinded_token()
    s_prime = reg.issue_blind_signature("voter_alice", m_prime)
    s = alice.unblind_signature(s_prime)
    nullifier = alice.get_nullifier()

    # Bulletin Board receives Alice's ballot credential
    ok, msg = pool.verify_and_spend(alice.get_token_hash_int(), s, nullifier)
    print(f"  • Legitimate Spend: {ok} -> {msg}")
    assert ok, "Legitimate token spend failed!"

    # Adversarial Replay Attack: Alice attempts to vote again with same nullifier
    ok_replay, msg_replay = pool.verify_and_spend(alice.get_token_hash_int(), s, nullifier)
    print(f"  • Replay Attack:   {ok_replay} -> {msg_replay}")
    assert not ok_replay, "Replay attack was incorrectly accepted!"

    # Adversarial Forgery Attack: Unregistered attacker fabricates signature
    fake_token = alice.get_token_hash_int()
    forged_s = 123456789
    fake_nullifier = "deadbeef" * 8
    ok_forge, msg_forge = pool.verify_and_spend(fake_token, forged_s, fake_nullifier)
    print(f"  • Forgery Attack:  {ok_forge} -> {msg_forge}")
    assert not ok_forge, "Forged signature was incorrectly accepted!"

    print("\n" + "=" * 70)
    print("ALL MEMBER 1 CRYPTOGRAPHIC PRIMITIVES PASSED AUDIT SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    main()
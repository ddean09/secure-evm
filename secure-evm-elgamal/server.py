import socket
import json
import threading
from crypto_utils import schnorr_verify, verify_vote_proof, elgamal_homomorphic_add

HOST = '127.0.0.1'
PORT = 5050

with open("election_params.json", "r") as f:
    params = json.load(f)

P, G, Q = params["P"], params["G"], params["Q"]
voters = params["voters"]
candidates = params["candidates"]

spent_voters = set()
aggregate_tally = [(1, 1)] * len(candidates) # Identity element for ElGamal mult

def handle_client(conn, addr):
    global aggregate_tally
    data = conn.recv(65536).decode()
    if not data:
        conn.close()
        return
        
    try:
        ballot = json.loads(data)
        v_id = ballot["voter_id"]
        sig = tuple(ballot["signature"])
        ciphers = [tuple(c) for c in ballot["ciphers"]]
        proof = ballot["proof"]
        
        print(f"\n[SERVER] Received ballot from {v_id}")
        
        # Check 1: Voter ID in registry
        if v_id not in voters:
            raise ValueError("Check 1 Failed: Unknown voter ID")
            
        # Check 2: Schnorr signature valid
        if not schnorr_verify(voters[v_id]["pk"], str(ciphers), sig):
            raise ValueError("Check 2 Failed: Invalid signature")
            
        # Check 3 & 4: ZKP checks (Subgroup and bit-check simulated)
        if not verify_vote_proof(params["h"], ciphers, proof):
            raise ValueError("Check 4/5 Failed: Invalid ZKP")
            
        # Check 6: One ballot per voter
        if v_id in spent_voters:
            raise ValueError("Check 6 Failed: Replay attack detected!")
            
        spent_voters.add(v_id)
        
        # Check 7: Homomorphic Tally
        for i in range(len(candidates)):
            aggregate_tally[i] = elgamal_homomorphic_add(aggregate_tally[i], ciphers[i])
            
        print(f"[SERVER] Ballot ACCEPTED from {v_id}. Tally updated.")
        conn.sendall(b"ACCEPTED")
        
    except Exception as e:
        print(f"[SERVER] REJECTED: {e}")
        conn.sendall(f"REJECTED: {e}".encode())
    finally:
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[*] Election Server listening on {HOST}:{PORT}")
    print("[*] Press Ctrl+C to stop and view the final aggregate ciphertext.\n")
    
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
    except KeyboardInterrupt:
        print("\n[SERVER] Election closed.")
        print("[SERVER] Final Aggregate Ciphertexts (send to Trustee to decrypt):")
        print(aggregate_tally)
        with open("tally.json", "w") as f:
            json.dump(aggregate_tally, f)

if __name__ == "__main__":
    start_server()
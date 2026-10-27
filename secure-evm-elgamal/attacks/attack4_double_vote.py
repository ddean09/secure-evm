# In the architecture diagram, this is Check 6 (One ballot per voter). 
# The Election Server maintains a list of spent_voters. 
# Even though the second ballot has a completely valid cryptographic signature and a valid ZKP,
# the server recognizes that voter_2 has already cast a ballot. 
# This prevents double-voting or replay attacks over the network.
import socket
import json
import sys
import os

# Tell Python to look in the parent directory for crypto_utils
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_utils import schnorr_sign, generate_vote_proof

# Load params
with open("election_params.json", "r") as f:
    params = json.load(f)

v_id = "voter_2" # We will use voter_2 for this demo
pk = params["h"]
sk = params["voters"][v_id]["sk"]
num_candidates = len(params["candidates"])

def send_ballot(choice_idx):
    ciphers, proof = generate_vote_proof(pk, num_candidates, choice_idx)
    sig = schnorr_sign(sk, str(ciphers))
    
    ballot = {
        "voter_id": v_id,
        "ciphers": ciphers,
        "proof": proof,
        "signature": sig
    }
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 5050))
    client.sendall(json.dumps(ballot).encode())
    response = client.recv(65536).decode()
    client.close()
    return response

print(f"[ATTACK 4] Sending FIRST ballot for {v_id} (for Bob)...")
res1 = send_ballot(1)
print(f"  -> Server Response: {res1}")

print(f"\n[ATTACK 4] Sending SECOND ballot for {v_id} (trying to vote for Carol)...")
res2 = send_ballot(2)
print(f"  -> Server Response: {res2}")
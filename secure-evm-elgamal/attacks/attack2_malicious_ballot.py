import socket
import json
import sys
import os

# Tell Python to also look in the parent directory for crypto_utils
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_utils import elgamal_encrypt, schnorr_sign, hash_to_int

# Load params from the main folder
with open("election_params.json", "r") as f:
    params = json.load(f)
    
pk = params["h"]
v_id = "voter_3" # Impersonating voter_3
sk = params["voters"][v_id]["sk"]

# Malicious weight inflation: 10 votes for Alice
malicious_vector = [10, 0, 0] 
ciphers = []
for val in malicious_vector:
    ct, _ = elgamal_encrypt(pk, val)
    ciphers.append(ct)

# Fake proof
proof = hash_to_int(*[c[0] for c in ciphers], *[c[1] for c in ciphers])
sig = schnorr_sign(sk, str(ciphers))

ballot = {"voter_id": v_id, "ciphers": ciphers, "proof": proof, "signature": sig}

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 5050))
client.sendall(json.dumps(ballot).encode())
print(f"[ATTACK 2] Malicious ballot sent -> {client.recv(65536).decode()}")
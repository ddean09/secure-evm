import socket
import json
import sys
import argparse
from crypto_utils import elgamal_encrypt, schnorr_sign, generate_vote_proof

def cast_vote(v_id, candidate_idx, port):
    with open("election_params.json", "r") as f:
        params = json.load(f)
        
    pk = params["h"]
    sk = params["voters"][v_id]["sk"]
    num_candidates = len(params["candidates"])
    
    # 1. Encrypt vote
    ciphers, proof = generate_vote_proof(pk, num_candidates, candidate_idx)
    
    # 2. Sign ballot
    sig = schnorr_sign(sk, str(ciphers))
    
    # 3. Prepare payload
    ballot = {
        "voter_id": v_id,
        "ciphers": ciphers,
        "proof": proof,
        "signature": sig
    }
    
    # 4. Send to server
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('127.0.0.1', port))
        client.sendall(json.dumps(ballot).encode())
        
        response = client.recv(65536).decode()
        print(f"[{v_id}] Vote for {params['candidates'][candidate_idx]} -> {response}")
        client.close()
    except ConnectionRefusedError:
        print(f"[{v_id}] ERROR: Server is not running on port {port}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, help="Voter ID (e.g., voter_1)")
    parser.add_argument("--choice", type=int, required=True, help="0=Alice, 1=Bob, 2=Carol")
    parser.add_argument("--port", type=int, default=5050, help="Port to connect to")
    args = parser.parse_args()
    
    cast_vote(args.id, args.choice, args.port)
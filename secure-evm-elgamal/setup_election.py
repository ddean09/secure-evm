import json
from crypto_utils import schnorr_keygen, P, G, Q
import secrets

def setup():
    # Trustee secret key x
    x = secrets.randbelow(Q - 1) + 1
    h = pow(G, x, P)
    
    voters = {}
    for i in range(1, 6):
        v_id = f"voter_{i}"
        sk, pk = schnorr_keygen()
        voters[v_id] = {"sk": sk, "pk": pk}
        
    params = {
        "P": P, "G": G, "Q": Q, "h": h,
        "voters": voters,
        "candidates": ["Alice", "Bob", "Carol"]
    }
    
    with open("election_params.json", "w") as f:
        json.dump(params, f, indent=4)
        
    print("[+] Election parameters generated.")
    print(f"[+] Trustee secret key x: {x} (Keep this safe!)")
    print("[+] Saved to election_params.json")

if __name__ == "__main__":
    setup()
    
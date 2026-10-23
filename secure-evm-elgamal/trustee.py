import json
from crypto_utils import P, G

def decrypt_tally():
    # Note: In a real run, the trustee knows the secret 'x' from setup_election.py
    # For this demo, we'll assume the trustee runs the setup or reads the key.
    print("Enter the Trustee secret key x (from setup_election.py):")
    x = int(input("x = "))
    
    with open("tally.json", "r") as f:
        aggregate_tally = json.load(f)
        
    print("\n--- Final Decrypted Election Results ---")
    candidates = ["Alice", "Bob", "Carol"]
    
    for i, ct in enumerate(aggregate_tally):
        c1, c2 = ct
        # g^m = c2 * (c1^x)^-1 mod P
        gm = (c2 * pow(pow(c1, x, P), -1, P)) % P
        
        # Brute-force discrete log for small m (since total votes <= 5)
        m = 0
        current = 1
        while current != gm:
            current = (current * G) % P
            m += 1
            if m > 10: break # safety
            
        print(f"{candidates[i]}: {m} votes")

if __name__ == "__main__":
    decrypt_tally()
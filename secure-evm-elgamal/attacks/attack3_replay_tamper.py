import socket
import json

with open("../election_params.json", "r") as f:
    params = json.load(f)

# Simulate a captured ballot
ct = params["h"]
ballot = {
    "voter_id": "voter_4", # Replaying as voter_4
    "ciphers": [(123, 456), (123, 456), (123, 456)], # Fake values
    "proof": 999,
    "signature": (111, 222)
}

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 5000))
client.sendall(json.dumps(ballot).encode())
print(f"[ATTACK 3] Replay/Tamper sent -> {client.recv(1024).decode()}")
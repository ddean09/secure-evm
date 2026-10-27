import socket
import threading

def forward(source, destination):
    while True:
        data = source.recv(65536)
        if not data:
            break
        print(f"[EAVESDROPPER] Intercepted: {data.decode()[:100]}... (Garbage/math)")
        destination.sendall(data)
    destination.shutdown(socket.SHUT_WR)
    source.close()

def start_proxy():
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.bind(('127.0.0.1', 6000))
    proxy.listen()
    print("[*] Eavesdropper proxy listening on 6000. Forwarding to 5050...")
    
    while True:
        client, addr = proxy.accept()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect(('127.0.0.1', 5050))
        
        threading.Thread(target=forward, args=(client, server)).start()
        threading.Thread(target=forward, args=(server, client)).start()

if __name__ == "__main__":
    start_proxy()
import socket
import threading
from openssl import *

class Peer:
    def __init__(self, is_server, host='127.0.0.1', port=5001):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_server = is_server
        self.host = host
        self.port = port
        self.conn = None

    # ---------------- HANDSHAKE ---------------- #

    def _recv_full_pem(self):
        buffer = b""
        while b"<<ENDKEY>>" not in buffer:
            chunk = self.conn.recv(512)
            if not chunk:
                break
            buffer += chunk
        return buffer.replace(b"<<ENDKEY>>", b"")

    def _handshake(self):
        print("[*] Starting handshake...")

        if self.is_server:
            peer_pub = self._recv_full_pem()
            pub = generate_ephemeral_keypair(self.is_server)
            self.conn.sendall(pub + b"<<ENDKEY>>")
        else:
            pub = generate_ephemeral_keypair(self.is_server)
            self.conn.sendall(pub + b"<<ENDKEY>>")
            peer_pub = self._recv_full_pem()

        self.session_key = perform_key_exchange(peer_pub, self.is_server)

        # 🔥 KEY DERIVATION
        self.aes_key, self.mac_key = derive_keys(self.session_key)

        print("[+] Secure session established.")

    # ---------------- CONNECTION ---------------- #

    def start(self):
        if self.is_server:
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
            print("[*] Waiting for connection...")
            self.conn, _ = self.sock.accept()
        else:
            self.sock.connect((self.host, self.port))
            self.conn = self.sock

        self._handshake()
        self._start_threads()

    def _start_threads(self):
        threading.Thread(target=self._receive_loop, daemon=True).start()
        print("I'm ready")
        self._send_loop()

    # ---------------- RECEIVE ---------------- #

    def _receive_loop(self):
        while True:
            try:
                data = self.conn.recv(4096)
                if not data:
                    break

                try:
                    message = decrypt_and_verify(data, self.aes_key, self.mac_key)
                except:
                    print("[ERROR] MAC verification failed")
                    continue

                print(f"\n[Peer]: {message}")

            except Exception as e:
                print(f"[Receive error]: {e}")
                break

    # ---------------- SEND ---------------- #

    def _send_loop(self):
        while True:
            try:
                msg = input("You: ").strip()
                if msg.lower() == "exit":
                    break

                cipher = encrypt_and_mac(msg, self.aes_key, self.mac_key)
                self.conn.sendall(cipher)

            except Exception as e:
                print(f"[Send error]: {e}")
                break

        self.conn.close()
        self.sock.close()
        print("[*] Connection closed.")
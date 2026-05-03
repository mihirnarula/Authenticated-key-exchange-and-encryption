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

    # -------- RECEIVE HANDSHAKE -------- #

    def _recv_full(self):
        buffer = b""
        while b"<<END>>" not in buffer:
            chunk = self.conn.recv(512)
            if not chunk:
                break
            buffer += chunk

        data = buffer.replace(b"<<END>>", b"")

        # If server sent signature → verify
        if b"<<SIG>>" in data:
            pub, sig = data.split(b"<<SIG>>", 1)

            if not verify_signature(pub, sig):
                raise Exception("RSA verification failed")

            return pub

        # Client case (no signature)
        return data

    # -------- HANDSHAKE -------- #

    def _handshake(self):
        print("[*] Starting handshake...")

        if self.is_server:
            # Server receives client pubkey first
            peer_pub = self._recv_full()

            # Server generates and signs
            pub = generate_ephemeral_keypair(self.is_server)
            sig = sign_data(pub)
            payload = pub + b"<<SIG>>" + sig + b"<<END>>"

            self.conn.sendall(payload)

        else:
            # Client sends pubkey only
            pub = generate_ephemeral_keypair(self.is_server)
            payload = pub + b"<<END>>"
            self.conn.sendall(payload)

            # Client receives signed server key
            peer_pub = self._recv_full()

        # Derive session key
        self.session_key = perform_key_exchange(peer_pub, self.is_server)
        self.aes_key, self.mac_key = derive_keys(self.session_key)

        print("[+] Secure session established.")

    # -------- CONNECTION -------- #

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

    # -------- RECEIVE -------- #

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

    # -------- SEND -------- #

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
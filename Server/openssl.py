import subprocess
import os
import hashlib

# -------- ECDH -------- #

def generate_ephemeral_keypair(mode):
    key_dir = "Server_keys" if mode else "Client_keys"
    os.makedirs(key_dir, exist_ok=True)

    private_path = os.path.join(key_dir, "private.pem")
    public_path = os.path.join(key_dir, "public.pem")

    subprocess.run([
        "openssl", "ecparam",
        "-name", "prime256v1",
        "-genkey", "-noout",
        "-out", private_path
    ], check=True)

    subprocess.run([
        "openssl", "ec",
        "-in", private_path,
        "-pubout",
        "-out", public_path
    ], check=True)

    with open(public_path, "rb") as f:
        return f.read()


def perform_key_exchange(peer_pub_bytes, mode):
    key_dir = "Server_keys" if mode else "Client_keys"
    private_path = os.path.join(key_dir, "private.pem")
    peer_public_path = os.path.join(key_dir, "peer_public.pem")
    session_key_path = os.path.join(key_dir, "shared_secret.bin")

    with open(peer_public_path, "wb") as f:
        f.write(peer_pub_bytes)

    subprocess.run([
        "openssl", "pkeyutl",
        "-derive",
        "-inkey", private_path,
        "-peerkey", peer_public_path,
        "-out", session_key_path
    ], check=True)

    with open(session_key_path, "rb") as f:
        return f.read()


# -------- KEY DERIVATION -------- #

def derive_keys(shared_secret):
    h = hashlib.sha256(shared_secret).digest()
    return h[:16], h[16:]


# -------- AES + HMAC -------- #

def encrypt_and_mac(message, aes_key, mac_key):
    message_bytes = message.encode()

    mac = subprocess.check_output([
        "openssl", "dgst", "-sha256",
        "-mac", "HMAC",
        "-macopt", f"hexkey:{mac_key.hex()}"
    ], input=message_bytes).split()[-1]

    mac_bytes = bytes.fromhex(mac.decode())
    payload = message_bytes + mac_bytes

    iv = os.urandom(16)

    ciphertext = subprocess.check_output([
        "openssl", "enc", "-aes-128-cbc",
        "-K", aes_key.hex(),
        "-iv", iv.hex()
    ], input=payload)

    return iv + ciphertext


def decrypt_and_verify(data, aes_key, mac_key):
    iv = data[:16]
    ciphertext = data[16:]

    decrypted = subprocess.check_output([
        "openssl", "enc", "-d", "-aes-128-cbc",
        "-K", aes_key.hex(),
        "-iv", iv.hex()
    ], input=ciphertext)

    message = decrypted[:-32]
    recv_mac = decrypted[-32:]

    mac = subprocess.check_output([
        "openssl", "dgst", "-sha256",
        "-mac", "HMAC",
        "-macopt", f"hexkey:{mac_key.hex()}"
    ], input=message).split()[-1]

    calc_mac = bytes.fromhex(mac.decode())

    if calc_mac != recv_mac:
        raise Exception("MAC verification failed")

    return message.decode()


# -------- RSA -------- #

def sign_data(data):
    return subprocess.check_output([
        "openssl", "dgst", "-sha256",
        "-sign", "rsa_private.pem"
    ], input=data)


def verify_signature(data, signature):
    with open("temp_sig.bin", "wb") as f:
        f.write(signature)

    try:
        subprocess.run([
            "openssl", "dgst", "-sha256",
            "-verify", "rsa_public.pem",
            "-signature", "temp_sig.bin"
        ], input=data, check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
        return True
    except:
        return False
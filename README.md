# Secure Messenger

secure messenger using:

1. ECDH (key exchange)

2. RSA (authentication)

3. AES-128-CBC (encryption)

4. HMAC-SHA256 (integrity)

---

## Setup

### 5. Generate RSA keys - only on server

```bash
cd server
openssl genpkey -algorithm RSA -out rsa_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in rsa_private.pem -out rsa_public.pem
```

---

### 6. iii. Copy public key to client

```bash
cp rsa_public.pem ../client/
```

---

## RUN

### 7. RUN on server

```bash
cd server
python3 alt_run_server.py server
```

---

on client

```bash
cd client
python3 alt_run_client.py client {ip u get at server}
```

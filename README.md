secure messenger using:

   ECDH (key exchange)
   RSA (authentication)
   AES-128-CBC (encryption)
   HMAC-SHA256 (integrity)

1. Generate RSA keys - only on server
cd server
openssl genpkey -algorithm RSA -out rsa_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in rsa_private.pem -out rsa_public.pem

2. 3. Copy public key to client
cp rsa_public.pem ../client/

3. RUN
on server 
cd server python3 alt_run_server.py server

on client 
cd client python3 alt_run_client.py client {ip u get at server}

import time
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

print("\n===== ECC vs RSA Security Comparison =====\n")

# -----------------------------
# ECC KEY GENERATION
# -----------------------------
start = time.time()

ecc_private = ec.generate_private_key(ec.SECP256R1())
ecc_public = ecc_private.public_key()

ecc_key_time = time.time() - start

ecc_private_pem = ecc_private.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

ecc_public_pem = ecc_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("ECC Key Size:", ecc_private.key_size, "bits")
print("ECC Private Key File Size:", len(ecc_private_pem), "bytes")
print("ECC Public Key File Size:", len(ecc_public_pem), "bytes")
print("ECC Key Generation Time:", ecc_key_time, "seconds\n")


# -----------------------------
# RSA KEY GENERATION
# -----------------------------
start = time.time()

rsa_private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072
)

rsa_public = rsa_private.public_key()

rsa_key_time = time.time() - start

rsa_private_pem = rsa_private.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

rsa_public_pem = rsa_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("RSA Key Size:", rsa_private.key_size, "bits")
print("RSA Private Key File Size:", len(rsa_private_pem), "bytes")
print("RSA Public Key File Size:", len(rsa_public_pem), "bytes")
print("RSA Key Generation Time:", rsa_key_time, "seconds\n")


# -----------------------------
# SIGNING PERFORMANCE TEST
# -----------------------------
message = b"authentication_test_message"

# ECC Signing
start = time.time()

ecc_signature = ecc_private.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)

ecc_sign_time = time.time() - start

# RSA Signing
start = time.time()

rsa_signature = rsa_private.sign(
    message,
    rsa.padding.PKCS1v15(),
    hashes.SHA256()
)

rsa_sign_time = time.time() - start

print("ECC Signature Time:", ecc_sign_time, "seconds")
print("RSA Signature Time:", rsa_sign_time, "seconds")

print("\n===== Test Complete =====")
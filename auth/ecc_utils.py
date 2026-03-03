import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization


# =====================================
# KEY GENERATION
# =====================================

def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return private_pem, public_pem


# =====================================
# NONCE GENERATION
# =====================================

def generate_nonce(size=16):
    return os.urandom(size)


# =====================================
# SIGNATURE CREATION
# =====================================

def sign_nonce(private_key_pem, nonce):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )

    signature = private_key.sign(
        nonce,
        ec.ECDSA(hashes.SHA256())
    )

    return signature


# =====================================
# SIGNATURE VERIFICATION
# =====================================

def verify_signature(public_key_pem, signature, nonce):
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode()
    )

    public_key.verify(
        signature,
        nonce,
        ec.ECDSA(hashes.SHA256())
    )

    return True


# =====================================
# SESSION KEY DERIVATION (ECDH)
# =====================================

def derive_session_key(public_key_pem):
    server_private = ec.generate_private_key(ec.SECP256R1())
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode()
    )

    shared_secret = server_private.exchange(
        ec.ECDH(),
        public_key
    )

    session_key = hashlib.sha256(shared_secret).hexdigest()

    return session_key
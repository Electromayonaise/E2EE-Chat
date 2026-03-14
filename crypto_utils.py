import base64
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def generate_identity() -> tuple[x25519.X25519PrivateKey, ed25519.Ed25519PrivateKey]:
    return x25519.X25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()


def public_bytes_x25519(key: x25519.X25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_bytes_ed25519(key: ed25519.Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_x25519_public(raw: bytes) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(raw)


def load_ed25519_public(raw: bytes) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def derive_pair_key(
    my_private: x25519.X25519PrivateKey,
    peer_public: x25519.X25519PublicKey,
    context: bytes = b"encry-room-wrap-v1",
) -> bytes:
    shared_secret = my_private.exchange(peer_public)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(shared_secret)


def wrap_room_key(room_key: bytes, pair_key: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(pair_key).encrypt(nonce, room_key, associated_data=b"room-key")
    return nonce, ciphertext


def unwrap_room_key(nonce: bytes, ciphertext: bytes, pair_key: bytes) -> bytes:
    return AESGCM(pair_key).decrypt(nonce, ciphertext, associated_data=b"room-key")


def encrypt_message(plaintext: str, room_key: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(room_key).encrypt(nonce, plaintext.encode("utf-8"), associated_data=aad)
    return nonce, ciphertext


def decrypt_message(nonce: bytes, ciphertext: bytes, room_key: bytes, aad: bytes) -> str:
    plaintext = AESGCM(room_key).decrypt(nonce, ciphertext, associated_data=aad)
    return plaintext.decode("utf-8")


def sign_payload(payload: bytes, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    return private_key.sign(payload)


def verify_payload(signature: bytes, payload: bytes, public_key: ed25519.Ed25519PublicKey) -> bool:
    try:
        public_key.verify(signature, payload)
        return True
    except InvalidSignature:
        return False

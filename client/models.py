from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from crypto_utils import b64e, public_bytes_ed25519, public_bytes_x25519


@dataclass
class PeerInfo:
    enc_pub: x25519.X25519PublicKey
    sign_pub: ed25519.Ed25519PublicKey


@dataclass
class ChatState:
    user_id: str
    room: str
    enc_private: x25519.X25519PrivateKey
    sign_private: ed25519.Ed25519PrivateKey
    peers: dict[str, PeerInfo] = field(default_factory=dict)
    room_key: bytes | None = None

    @property
    def enc_public_b64(self) -> str:
        return b64e(public_bytes_x25519(self.enc_private.public_key()))

    @property
    def sign_public_b64(self) -> str:
        return b64e(public_bytes_ed25519(self.sign_private.public_key()))

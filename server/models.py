from dataclasses import dataclass, field

import websockets


@dataclass
class ClientInfo:
    user_id: str
    room: str
    enc_pub_b64: str
    sign_pub_b64: str


@dataclass
class ServerState:
    clients: dict[websockets.ServerConnection, ClientInfo] = field(default_factory=dict)
    rooms: dict[str, set[websockets.ServerConnection]] = field(default_factory=dict)

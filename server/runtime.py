import asyncio
import json
import time
from typing import cast

import websockets

from .models import ClientInfo, ServerState


def now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


async def safe_send(ws: websockets.ServerConnection, payload: dict) -> None:
    await ws.send(json.dumps(payload))


async def broadcast_room(
    state: ServerState,
    room: str,
    payload: dict,
    exclude: websockets.ServerConnection | None = None,
) -> None:
    targets = state.rooms.get(room, set()).copy()
    if exclude is not None and exclude in targets:
        targets.remove(exclude)
    if not targets:
        return
    await asyncio.gather(*(safe_send(ws, payload) for ws in targets), return_exceptions=True)


async def handle_join(state: ServerState, ws: websockets.ServerConnection, msg: dict) -> None:
    user_id_raw = msg.get("user_id")
    room_raw = msg.get("room")
    enc_pub_raw = msg.get("enc_pub")
    sign_pub_raw = msg.get("sign_pub")

    if not all([user_id_raw, room_raw, enc_pub_raw, sign_pub_raw]):
        await safe_send(ws, {"type": "error", "message": "join incompleto"})
        return

    if not all(isinstance(value, str) for value in (user_id_raw, room_raw, enc_pub_raw, sign_pub_raw)):
        await safe_send(ws, {"type": "error", "message": "join inválido"})
        return

    user_id = cast(str, user_id_raw)
    room = cast(str, room_raw)
    enc_pub = cast(str, enc_pub_raw)
    sign_pub = cast(str, sign_pub_raw)

    if ws in state.clients:
        await safe_send(ws, {"type": "error", "message": "ya registrado"})
        return

    info = ClientInfo(
        user_id=user_id,
        room=room,
        enc_pub_b64=enc_pub,
        sign_pub_b64=sign_pub,
    )
    state.clients[ws] = info
    state.rooms.setdefault(room, set()).add(ws)

    peers = [
        {
            "user_id": c.user_id,
            "enc_pub": c.enc_pub_b64,
            "sign_pub": c.sign_pub_b64,
        }
        for conn, c in state.clients.items()
        if conn is not ws and c.room == room
    ]

    await safe_send(
        ws,
        {
            "type": "joined",
            "room": room,
            "you": user_id,
            "peers": peers,
        },
    )

    await broadcast_room(
        state,
        room,
        {
            "type": "peer_join",
            "user_id": user_id,
            "enc_pub": enc_pub,
            "sign_pub": sign_pub,
        },
        exclude=ws,
    )

    print(f"[{now()}] JOIN room={room} user={user_id} peers={len(peers)}")


async def forward_targeted(
    state: ServerState,
    ws: websockets.ServerConnection,
    msg: dict,
    expected_type: str,
) -> None:
    info = state.clients.get(ws)
    if not info:
        await safe_send(ws, {"type": "error", "message": "join requerido"})
        return

    if msg.get("type") != expected_type:
        return

    target_id_raw = msg.get("target")
    if not isinstance(target_id_raw, str) or not target_id_raw:
        await safe_send(ws, {"type": "error", "message": "target requerido"})
        return

    target_id = target_id_raw
    target_ws = None
    for conn, client in state.clients.items():
        if client.room == info.room and client.user_id == target_id:
            target_ws = conn
            break

    if not target_ws:
        await safe_send(ws, {"type": "error", "message": "target no encontrado"})
        return

    await safe_send(target_ws, msg)


async def forward_room_message(state: ServerState, ws: websockets.ServerConnection, msg: dict) -> None:
    info = state.clients.get(ws)
    if not info:
        await safe_send(ws, {"type": "error", "message": "join requerido"})
        return

    if msg.get("type") != "message":
        return

    ciphertext = msg.get("ciphertext", "")
    sender = msg.get("sender", "")
    print(
        f"[{now()}] CIPHERTEXT room={info.room} sender={sender} bytes={len(ciphertext)} data={ciphertext[:80]}..."
    )

    await broadcast_room(state, info.room, msg, exclude=ws)


async def cleanup(state: ServerState, ws: websockets.ServerConnection) -> None:
    info = state.clients.pop(ws, None)
    if not info:
        return

    room_peers = state.rooms.get(info.room)
    if room_peers and ws in room_peers:
        room_peers.remove(ws)
        if not room_peers:
            state.rooms.pop(info.room, None)

    await broadcast_room(
        state,
        info.room,
        {
            "type": "peer_leave",
            "user_id": info.user_id,
        },
        exclude=ws,
    )
    print(f"[{now()}] LEAVE room={info.room} user={info.user_id}")


async def handler(state: ServerState, ws: websockets.ServerConnection) -> None:
    try:
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await safe_send(ws, {"type": "error", "message": "json inválido"})
                continue

            msg_type = msg.get("type")
            if msg_type == "join":
                await handle_join(state, ws, msg)
            elif msg_type == "room_key":
                await forward_targeted(state, ws, msg, expected_type="room_key")
            elif msg_type == "message":
                await forward_room_message(state, ws, msg)
            else:
                await safe_send(ws, {"type": "error", "message": f"tipo no soportado: {msg_type}"})
    finally:
        await cleanup(state, ws)


async def run_server(host: str, port: int) -> None:
    state = ServerState()
    print(f"Relay host escuchando en ws://{host}:{port}")

    async def bound_handler(ws: websockets.ServerConnection) -> None:
        await handler(state, ws)

    async with websockets.serve(bound_handler, host, port):
        await asyncio.Future()

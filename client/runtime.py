import asyncio
import json
import os
import time
from typing import cast

import websockets

from crypto_utils import (
    b64d,
    b64e,
    decrypt_message,
    derive_pair_key,
    encrypt_message,
    generate_identity,
    load_ed25519_public,
    load_x25519_public,
    sign_payload,
    unwrap_room_key,
    verify_payload,
    wrap_room_key,
)

from .models import ChatState, PeerInfo


def timestamp() -> str:
    return time.strftime("%H:%M:%S")


def payload_to_sign(sender: str, room: str, ts: str, nonce_b64: str, ciphertext_b64: str) -> bytes:
    return f"{sender}|{room}|{ts}|{nonce_b64}|{ciphertext_b64}".encode("utf-8")


async def send_json(ws: websockets.ClientConnection, payload: dict) -> None:
    await ws.send(json.dumps(payload))


async def send_room_key_to_peer(
    ws: websockets.ClientConnection,
    state: ChatState,
    target_user: str,
) -> None:
    if state.room_key is None:
        return

    peer = state.peers.get(target_user)
    if not peer:
        return

    pair_key = derive_pair_key(state.enc_private, peer.enc_pub)
    nonce, wrapped = wrap_room_key(state.room_key, pair_key)
    await send_json(
        ws,
        {
            "type": "room_key",
            "sender": state.user_id,
            "target": target_user,
            "nonce": b64e(nonce),
            "ciphertext": b64e(wrapped),
        },
    )


async def maybe_init_room_key(state: ChatState, peers_count: int) -> None:
    if state.room_key is None and peers_count == 0:
        state.room_key = os.urandom(32)
        print(f"[{timestamp()}] Sala vacía: clave de sala inicial creada localmente.")
    elif state.room_key is None and peers_count > 0:
        print(f"[{timestamp()}] Esperando clave de sala de un miembro existente...")


async def handle_incoming(ws: websockets.ClientConnection, state: ChatState) -> None:
    async for raw in ws:
        msg = json.loads(raw)
        msg_type = msg.get("type")

        if msg_type == "error":
            print(f"[{timestamp()}] [HOST-ERROR] {msg.get('message')}")
            continue

        if msg_type == "joined":
            peers = msg.get("peers", [])
            if not isinstance(peers, list):
                print(f"[{timestamp()}] Respuesta joined inválida")
                continue

            for peer in peers:
                if not isinstance(peer, dict):
                    continue
                user_id = peer.get("user_id")
                enc_pub = peer.get("enc_pub")
                sign_pub = peer.get("sign_pub")
                if not all(isinstance(v, str) for v in (user_id, enc_pub, sign_pub)):
                    continue
                user_id = cast(str, user_id)
                enc_pub = cast(str, enc_pub)
                sign_pub = cast(str, sign_pub)
                state.peers[user_id] = PeerInfo(
                    enc_pub=load_x25519_public(b64d(enc_pub)),
                    sign_pub=load_ed25519_public(b64d(sign_pub)),
                )

            print(
                f"[{timestamp()}] Conectado a sala '{state.room}' como '{state.user_id}'. "
                f"Pares actuales: {len(state.peers)}"
            )
            await maybe_init_room_key(state, peers_count=len(state.peers))
            continue

        if msg_type == "peer_join":
            peer_user = msg.get("user_id")
            enc_pub = msg.get("enc_pub")
            sign_pub = msg.get("sign_pub")
            if not all(isinstance(v, str) for v in (peer_user, enc_pub, sign_pub)):
                print(f"[{timestamp()}] peer_join inválido")
                continue
            state.peers[peer_user] = PeerInfo(
                enc_pub=load_x25519_public(b64d(enc_pub)),
                sign_pub=load_ed25519_public(b64d(sign_pub)),
            )
            print(f"[{timestamp()}] + '{peer_user}' se unió a la sala")
            await send_room_key_to_peer(ws, state, peer_user)
            continue

        if msg_type == "peer_leave":
            peer_user = msg.get("user_id")
            if isinstance(peer_user, str) and peer_user in state.peers:
                del state.peers[peer_user]
            print(f"[{timestamp()}] - '{peer_user}' salió de la sala")
            continue

        if msg_type == "room_key":
            sender = msg.get("sender")
            nonce_b64 = msg.get("nonce")
            ciphertext_b64 = msg.get("ciphertext")
            if not all(isinstance(v, str) for v in (sender, nonce_b64, ciphertext_b64)):
                print(f"[{timestamp()}] room_key inválido")
                continue

            peer = state.peers.get(sender)
            if not peer:
                print(f"[{timestamp()}] Clave de sala ignorada: peer desconocido '{sender}'")
                continue

            try:
                pair_key = derive_pair_key(state.enc_private, peer.enc_pub)
                state.room_key = unwrap_room_key(
                    nonce=b64d(nonce_b64),
                    ciphertext=b64d(ciphertext_b64),
                    pair_key=pair_key,
                )
                print(f"[{timestamp()}] Clave de sala recibida desde '{sender}'.")
            except Exception as exc:
                print(f"[{timestamp()}] Error al abrir clave de sala: {exc}")
            continue

        if msg_type == "message":
            sender = msg.get("sender")
            nonce_b64 = msg.get("nonce")
            ciphertext_b64 = msg.get("ciphertext")
            ts = msg.get("ts")
            signature_b64 = msg.get("signature")

            if not all(isinstance(v, str) for v in (sender, nonce_b64, ciphertext_b64, ts, signature_b64)):
                print(f"[{timestamp()}] Mensaje inválido recibido")
                continue

            if sender not in state.peers:
                print(f"[{timestamp()}] Mensaje ignorado de remitente desconocido: '{sender}'")
                continue
            if state.room_key is None:
                print(f"[{timestamp()}] Mensaje cifrado recibido, pero aún no hay clave de sala.")
                continue

            signed = payload_to_sign(sender, state.room, ts, nonce_b64, ciphertext_b64)
            ok = verify_payload(
                signature=b64d(signature_b64),
                payload=signed,
                public_key=state.peers[sender].sign_pub,
            )
            if not ok:
                print(f"[{timestamp()}] Firma inválida de '{sender}', mensaje descartado.")
                continue

            try:
                plaintext = decrypt_message(
                    nonce=b64d(nonce_b64),
                    ciphertext=b64d(ciphertext_b64),
                    room_key=state.room_key,
                    aad=f"{state.room}|{sender}|{ts}".encode("utf-8"),
                )
                print(f"[{ts}] {sender}: {plaintext}")
            except Exception as exc:
                print(f"[{timestamp()}] No se pudo descifrar mensaje de '{sender}': {exc}")
            continue


async def handle_outgoing(ws: websockets.ClientConnection, state: ChatState) -> None:
    print("Escribe mensajes. Comandos: /help, /peers, /quit")
    while True:
        text = await asyncio.to_thread(input, "» ")
        text = text.strip()
        if not text:
            continue

        if text == "/help":
            print("/help  muestra ayuda")
            print("/peers lista peers conocidos")
            print("/quit  salir")
            continue

        if text == "/peers":
            peers = ", ".join(sorted(state.peers.keys())) if state.peers else "(sin peers)"
            print(f"Peers: {peers}")
            print("Clave de sala:", "disponible" if state.room_key else "no disponible")
            continue

        if text == "/quit":
            await ws.close()
            return

        if state.room_key is None:
            print("Aún no hay clave de sala. Espera a recibirla o entra primero a la sala.")
            continue

        ts = timestamp()
        aad = f"{state.room}|{state.user_id}|{ts}".encode("utf-8")
        nonce, ciphertext = encrypt_message(text, state.room_key, aad=aad)
        nonce_b64 = b64e(nonce)
        ciphertext_b64 = b64e(ciphertext)
        to_sign = payload_to_sign(state.user_id, state.room, ts, nonce_b64, ciphertext_b64)
        signature = sign_payload(to_sign, state.sign_private)

        await send_json(
            ws,
            {
                "type": "message",
                "sender": state.user_id,
                "room": state.room,
                "ts": ts,
                "nonce": nonce_b64,
                "ciphertext": ciphertext_b64,
                "signature": b64e(signature),
            },
        )
        print(f"[{ts}] yo: {text}")


async def run_client(url: str, user_id: str, room: str) -> None:
    enc_private, sign_private = generate_identity()
    state = ChatState(
        user_id=user_id,
        room=room,
        enc_private=enc_private,
        sign_private=sign_private,
    )

    async with websockets.connect(url) as ws:
        await send_json(
            ws,
            {
                "type": "join",
                "user_id": state.user_id,
                "room": state.room,
                "enc_pub": state.enc_public_b64,
                "sign_pub": state.sign_public_b64,
            },
        )

        incoming = asyncio.create_task(handle_incoming(ws, state))
        outgoing = asyncio.create_task(handle_outgoing(ws, state))
        done, pending = await asyncio.wait({incoming, outgoing}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            exc = task.exception()
            if exc:
                raise cast(BaseException, exc)

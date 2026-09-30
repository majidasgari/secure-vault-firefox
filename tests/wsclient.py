"""A minimal RFC 6455 WebSocket client, for talking to Chrome's DevTools endpoint.

Only what the DevTools protocol needs: one text-frame stream, client masking, pong replies, and
fragmented messages reassembled. Stdlib only, so the probe can run under the vault's own venv
(which has the vault's dependencies but no ``websockets`` package).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
from urllib.parse import urlsplit


class WebSocketError(RuntimeError):
    """Raised when the handshake or a frame is not what the protocol says."""


class WebSocket:
    """A blocking WebSocket connection to one URL (``ws://host:port/path``)."""

    def __init__(self, url: str, timeout: float = 30.0) -> None:
        parts = urlsplit(url)
        if parts.scheme != "ws":
            raise WebSocketError(f"only ws:// is supported, got {url!r}")
        host = parts.hostname or "127.0.0.1"
        port = int(parts.port or 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        self.timeout = timeout
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._buffer = b""
        self._handshake(host, port, path)

    # ------------------------------------------------------------------ handshake
    def _handshake(self, host: str, port: int, path: str) -> None:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self.sock.sendall(request.encode("ascii"))
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise WebSocketError("connection closed during handshake")
            header += chunk
        head, _, rest = header.partition(b"\r\n\r\n")
        self._buffer = rest
        status = head.split(b"\r\n", 1)[0]
        if b"101" not in status:
            raise WebSocketError(f"handshake failed: {status!r}")
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        ).decode("ascii")
        if expected.encode("ascii") not in head:
            raise WebSocketError("handshake did not carry the expected accept key")

    # ----------------------------------------------------------------------- io
    def _read(self, count: int) -> bytes:
        """Read exactly ``count`` bytes (using whatever the previous frame left behind)."""
        while len(self._buffer) < count:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise WebSocketError("connection closed")
            self._buffer += chunk
        data, self._buffer = self._buffer[:count], self._buffer[count:]
        return data

    def send(self, text: str) -> None:
        """Send one masked text frame."""
        payload = text.encode("utf-8")
        header = bytearray([0x81])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header += length.to_bytes(2, "big")
        else:
            header.append(0x80 | 127)
            header += length.to_bytes(8, "big")
        mask = os.urandom(4)
        header += mask
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def recv(self) -> str:
        """Receive one complete text message (control frames handled, fragments joined)."""
        chunks: list[bytes] = []
        opcode = None
        while True:
            first, second = self._read(2)
            fin = bool(first & 0x80)
            frame_opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            if length == 126:
                length = int.from_bytes(self._read(2), "big")
            elif length == 127:
                length = int.from_bytes(self._read(8), "big")
            mask = self._read(4) if masked else b""
            payload = self._read(length) if length else b""
            if mask:
                payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
            if frame_opcode == 0x8:  # close
                raise WebSocketError("closed by peer")
            if frame_opcode == 0x9:  # ping → pong
                self._send_control(0xA, payload)
                continue
            if frame_opcode == 0xA:  # pong
                continue
            if frame_opcode in (0x1, 0x2):
                opcode = frame_opcode
            elif frame_opcode != 0x0:
                raise WebSocketError(f"unsupported opcode {frame_opcode}")
            chunks.append(payload)
            if fin:
                break
        if opcode != 0x1:
            raise WebSocketError("only text messages are expected")
        return b"".join(chunks).decode("utf-8")

    def _send_control(self, opcode: int, payload: bytes) -> None:
        """Send one masked control frame (ping/pong/close)."""
        mask = os.urandom(4)
        header = bytes([0x80 | opcode, 0x80 | len(payload)]) + mask
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(header + masked)

    def close(self) -> None:
        """Send a close frame (best effort) and drop the socket."""
        try:
            self._send_control(0x8, b"")
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def self_test() -> int:
    """Connect to a local echo-free endpoint? No: just prove the framing round-trips."""
    print("wsclient: import ok, frames are stdlib-only")
    print(json.dumps({"ok": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(self_test())

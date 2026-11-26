#!/usr/bin/env python3
"""relay.py — outside-host side of the EQ UDP-over-TCP tunnel.

Runs on a normal internet host (NOT inside the sandbox VM). Accepts
one connection from bridge.py, unwraps framed blobs, emits the
payloads as real UDP to the named destination, and frames any replies
back down the stream.

Blob format (fixed): [4B IPv4 addr][2B port, network order][payload].

Transports between bridge and relay (blob protocol identical):
  * raw TCP (default): each blob is framed on the wire with a 2-byte
    big-endian length prefix.
  * WebSocket: each blob is one WS binary message (WS is already
    message-framed, so no length prefix). Used when the relay sits
    behind an HTTPS proxy that only forwards WebSocket upgrades —
    e.g. a GitHub Codespace forwarded port
    (https://<codespace>-<port>.app.github.dev), where GitHub
    terminates TLS and this process speaks plain WS. Implemented by
    hand (RFC 6455) — Python stdlib only, no pip packages.

UDP side (v3): ONE shared UNCONNECTED socket for all destinations,
sendto()/recvfrom() only. The previous design used one connect()ed
socket per destination; a connected socket makes the kernel silently
discard any datagram whose source is not the connected peer, so a
reply arriving from a different port/address than the request's
destination would vanish without a trace. The unconnected socket
receives everything, and every send and receive is tap-logged with
its true source/destination, length, md5 prefix and first bytes, so
wire-vs-client questions can be settled from relay.log alone.

Env:
  EQ_RELAY_PORT      raw-TCP listen port (default 40000)
  EQ_RELAY_WS_PORT   if set, listen as a WebSocket server on this
                     port INSTEAD of the raw-TCP listener
  EQ_RELAY_WS_CERT   optional PEM cert file: serve the WS listener
  EQ_RELAY_WS_KEY    over TLS (both must be set). Not needed behind
                     a TLS-terminating proxy like Codespaces; used
                     for local wss:// end-to-end tests.

Python stdlib only. No VM-specific assumptions.
"""

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import threading
import time

RELAY_PORT = int(os.environ.get("EQ_RELAY_PORT", "40000"))
WS_PORT = os.environ.get("EQ_RELAY_WS_PORT")
WS_PORT = int(WS_PORT) if WS_PORT else None
WS_CERT = os.environ.get("EQ_RELAY_WS_CERT")
WS_KEY = os.environ.get("EQ_RELAY_WS_KEY")

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Optional static address translation, EQ_RELAY_MAP="sandboxip=realip,..."
# The sandbox VM's resolver hands the game synthesized 198.18.x.x
# addresses that are meaningless on the real internet. When a blob's
# destination matches a mapped sandbox address, the relay sends to the
# real address instead, and stamps replies with the sandbox address so
# the game sees the peer it thinks it contacted.
ADDR_MAP = {}
for _pair in os.environ.get("EQ_RELAY_MAP", "").split(","):
    _pair = _pair.strip()
    if "=" in _pair:
        _k, _v = _pair.split("=", 1)
        ADDR_MAP[_k.strip()] = _v.strip()

# Runtime map updates + optional WS auth (v5, for the Actions chain):
# when EQ_RELAY_TOKEN is set, a bridge must first send a text frame
# {"auth": "<token>", "map": {...}}; the map merges into ADDR_MAP so
# the VM side can push its current synthesized-address map without
# restarting the relay. Later text frames may carry {"map": ...}
# updates. With no token set (Codespace use), behavior is unchanged.
RELAY_TOKEN = os.environ.get("EQ_RELAY_TOKEN") or None


def apply_map_update(new_map):
    if not isinstance(new_map, dict):
        return
    for k, v in new_map.items():
        if isinstance(k, str) and isinstance(v, str):
            ADDR_MAP[k] = v
    log("address map updated: %s" % ADDR_MAP)

# The sandbox resolver synthesizes addresses from all of 198.18.0.0/15
# and the specific address it hands out changes across VM restarts, so
# an exact-match map is brittle. Rule: any blob addressed into
# 198.18.0.0/15 on the login port (15900) goes to the real login
# server (EQ_RELAY_LOGIN_IP, default below). World/zone server
# addresses arrive in packet payloads as real IPs and are unaffected.
LOGIN_IP = os.environ.get("EQ_RELAY_LOGIN_IP", "69.174.201.230")
LOGIN_PORT = 15900


def translate_ip(ip, port):
    if ip in ADDR_MAP:
        return ADDR_MAP[ip]
    if port == LOGIN_PORT:
        parts = ip.split(".")
        if len(parts) == 4 and parts[0] == "198" and parts[1] in ("18", "19"):
            return LOGIN_IP
    return ip


def is_fake(ip):
    parts = ip.split(".")
    return (len(parts) == 4 and parts[0] == "198"
            and parts[1] in ("18", "19"))


# Zone-server discovery (v4): zone handoffs give the client a fresh
# synthesized address whose real host is a zone process somewhere in
# the eqzone block (69.174.201.128-145, eqzone-01..18) on a dynamic
# port. A static map cannot cover it. When a blob targets an unmapped
# synthesized address (and it is not the login port, which the rule
# above already handles), the relay fans the datagram out to every
# candidate host on that port; the first candidate that replies is
# pinned as that address's real host for the rest of the run. Zone
# processes only answer while the world has one spun up for the
# incoming client, which is exactly when the client is retrying.
ZONE_CANDIDATES = [c.strip() for c in os.environ.get(
    "EQ_RELAY_ZONE_CANDIDATES",
    ",".join("69.174.201.%d" % i for i in range(128, 146))).split(",")
    if c.strip()]


def log(msg):
    print("[%s] relay: %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def tap(direction, addr, data):
    """One line per UDP datagram: direction, true addr, length,
    md5 prefix, first 8 payload bytes as hex."""
    log("tap %s %s:%d len=%d md5=%s head=%s"
        % (direction, addr[0], addr[1], len(data),
           hashlib.md5(data).hexdigest()[:8], data[:8].hex()))


# ----------------------------------------------------------------------
# Minimal RFC 6455 helpers (server side: frames sent unmasked,
# frames received from clients are masked).
# ----------------------------------------------------------------------

def ws_accept_key(key):
    digest = hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def ws_frame(opcode, payload):
    """One complete (FIN) frame, unmasked (server -> client)."""
    header = bytearray([0x80 | opcode])
    n = len(payload)
    if n < 126:
        header.append(n)
    elif n < 65536:
        header.append(126)
        header += struct.pack(">H", n)
    else:
        header.append(127)
        header += struct.pack(">Q", n)
    return bytes(header) + payload


def _read_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _read_http_head(conn, cap=65536):
    """Read an HTTP header block one byte at a time (the peer sends
    nothing after the blank line until we answer, so no frame bytes
    can be swallowed). Returns the head without the final CRLFCRLF,
    or None on EOF."""
    data = b""
    while not data.endswith(b"\r\n\r\n"):
        if len(data) > cap:
            return None
        chunk = conn.recv(1)
        if not chunk:
            return None
        data += chunk
    return data[:-4]


def ws_read_message(conn, send_frame):
    """Read frames until one complete data message is assembled.
    Ping -> pong via send_frame(opcode, payload); close -> None.
    Returns (opcode, payload) of the data message, or None on
    close/EOF/protocol error."""
    frag_opcode = None
    frag = bytearray()
    while True:
        head = _read_exact(conn, 2)
        if head is None:
            return None
        fin = head[0] & 0x80
        opcode = head[0] & 0x0F
        masked = head[1] & 0x80
        n = head[1] & 0x7F
        if n == 126:
            ext = _read_exact(conn, 2)
            if ext is None:
                return None
            (n,) = struct.unpack(">H", ext)
        elif n == 127:
            ext = _read_exact(conn, 8)
            if ext is None:
                return None
            (n,) = struct.unpack(">Q", ext)
        mask = _read_exact(conn, 4) if masked else None
        if masked and mask is None:
            return None
        payload = _read_exact(conn, n) if n else b""
        if payload is None:
            return None
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        if opcode == 0x8:            # close
            try:
                send_frame(0x8, b"")
            except OSError:
                pass
            return None
        if opcode == 0x9:            # ping -> pong
            send_frame(0xA, payload)
            continue
        if opcode == 0xA:            # pong: ignore
            continue
        if opcode in (0x1, 0x2):     # text / binary: new message
            if fin:
                return opcode, payload
            frag_opcode = opcode
            frag = bytearray(payload)
            continue
        if opcode == 0x0:            # continuation
            frag += payload
            if fin:
                return frag_opcode, bytes(frag)
            continue
        return None                  # unknown opcode


class Relay:
    def __init__(self):
        self.conn = None               # current bridge connection
        self.conn_is_ws = False
        self.conn_lock = threading.Lock()
        # One shared unconnected UDP socket for all Daybreak traffic.
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("0.0.0.0", 0))
        # real dest (ip, port) -> apparent (ip, port) the game used,
        # learned from emit_blob; used to stamp replies.
        self.apparent_by_real = {}
        # Zone discovery: port -> apparent (ip, port) awaiting a host,
        # and fake ip -> real ip once a candidate has answered.
        self.fanout_pending = {}
        self.discovered = {}
        self.map_lock = threading.Lock()
        t = threading.Thread(target=self.udp_reader, daemon=True)
        t.start()

    # -- framing back to the bridge --------------------------------------
    def send_blob(self, blob):
        with self.conn_lock:
            conn = self.conn
            is_ws = self.conn_is_ws
        if conn is None:
            return
        try:
            if is_ws:
                conn.sendall(ws_frame(0x2, blob))
            else:
                conn.sendall(struct.pack(">H", len(blob)) + blob)
        except OSError:
            pass  # bridge gone; reader side will notice and clean up

    # -- the single UDP reader: receives from ANY source -------------------
    def udp_reader(self):
        while True:
            try:
                data, src = self.udp.recvfrom(65536)
            except OSError:
                return
            tap("recv", src, data)
            with self.map_lock:
                apparent = self.apparent_by_real.get(src)
                if apparent is None and src[0] in ZONE_CANDIDATES:
                    pending = self.fanout_pending.get(src[1])
                    if pending is not None:
                        # A candidate answered a fanned-out datagram:
                        # pin it as this synthesized address's host.
                        self.discovered[pending[0]] = src[0]
                        self.apparent_by_real[src] = pending
                        del self.fanout_pending[src[1]]
                        apparent = pending
                        log("zone discovery: %s -> %s (port %d)"
                            % (pending[0], src[0], src[1]))
            if apparent is None:
                # No game conversation is known for this source. Log
                # it distinctly and forward it stamped with its real
                # source; the bridge/shim decide what to do with it.
                log("tap recv UNKNOWN-SOURCE %s:%d len=%d"
                    % (src[0], src[1], len(data)))
                apparent = src
            blob = (socket.inet_aton(apparent[0])
                    + struct.pack(">H", apparent[1]) + data)
            self.send_blob(blob)

    # -- blob handling (shared by both transports) -------------------------
    def emit_blob(self, blob):
        if len(blob) < 6:
            return
        ip = socket.inet_ntoa(blob[:4])
        (port,) = struct.unpack(">H", blob[4:6])
        payload = blob[6:]
        real_ip = translate_ip(ip, port)
        if real_ip == ip and is_fake(ip):
            # Unmapped synthesized address: a zone host we have not
            # identified. Use the pinned host if discovery already
            # found one; otherwise fan out to every candidate.
            with self.map_lock:
                known = self.discovered.get(ip)
                if known is None:
                    self.fanout_pending[port] = (ip, port)
            if known is not None:
                real = (known, port)
                with self.map_lock:
                    self.apparent_by_real[real] = (ip, port)
                tap("send", real, payload)
                try:
                    self.udp.sendto(payload, real)
                except OSError as e:
                    log("udp send to %s:%d failed (%s)" % (ip, port, e))
            else:
                log("zone fanout: %s:%d -> %d candidates"
                    % (ip, port, len(ZONE_CANDIDATES)))
                for cand in ZONE_CANDIDATES:
                    tap("send", (cand, port), payload)
                    try:
                        self.udp.sendto(payload, (cand, port))
                    except OSError as e:
                        log("udp send to %s:%d failed (%s)"
                            % (cand, port, e))
            return
        real = (real_ip, port)
        with self.map_lock:
            self.apparent_by_real[real] = (ip, port)
        tap("send", real, payload)
        try:
            self.udp.sendto(payload, real)
        except OSError as e:
            log("udp send to %s:%d failed (%s)" % (ip, port, e))

    def _set_conn(self, conn, is_ws):
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        with self.conn_lock:
            old = self.conn
            self.conn = conn
            self.conn_is_ws = is_ws
        if old is not None:
            try:
                old.close()
            except OSError:
                pass

    def _clear_conn(self, conn):
        with self.conn_lock:
            if self.conn is conn:
                self.conn = None
        try:
            conn.close()
        except OSError:
            pass
        log("bridge disconnected")

    # -- raw-TCP bridge connection -----------------------------------------
    def handle_bridge(self, conn):
        log("bridge connected from %s:%d" % conn.getpeername())
        buf = b""
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= 2:
                    (blen,) = struct.unpack(">H", buf[:2])
                    if len(buf) < 2 + blen:
                        break
                    blob = buf[2:2 + blen]
                    buf = buf[2 + blen:]
                    self.emit_blob(blob)
        except OSError as e:
            log("bridge read error (%s)" % e)
        finally:
            self._clear_conn(conn)

    # -- WebSocket bridge connection -----------------------------------------
    def ws_handshake(self, conn):
        head = _read_http_head(conn)
        if head is None:
            return False
        headers = {}
        lines = head.decode("iso-8859-1").split("\r\n")
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        key = headers.get("sec-websocket-key")
        if headers.get("upgrade", "").lower() != "websocket" or not key:
            try:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            except OSError:
                pass
            return False
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "\r\n" % ws_accept_key(key)
        )
        conn.sendall(response.encode("ascii"))
        return True

    def handle_bridge_ws(self, conn):
        peer = conn.getpeername()
        log("ws bridge connecting from %s:%d" % peer)
        try:
            if not self.ws_handshake(conn):
                log("ws handshake failed from %s:%d" % peer)
                try:
                    conn.close()
                except OSError:
                    pass
                return
        except OSError as e:
            log("ws handshake error (%s)" % e)
            try:
                conn.close()
            except OSError:
                pass
            return
        log("ws bridge connected from %s:%d" % peer)
        authed = RELAY_TOKEN is None

        def send_frame(opcode, payload):
            conn.sendall(ws_frame(opcode, payload))

        try:
            while True:
                msg = ws_read_message(conn, send_frame)
                if msg is None:
                    break
                opcode, blob = msg
                if opcode == 0x1:  # text frame: control message
                    try:
                        ctrl = json.loads(blob.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if not authed:
                        if ctrl.get("auth") == RELAY_TOKEN:
                            authed = True
                            log("bridge authenticated")
                        else:
                            log("bridge auth failed; closing")
                            break
                    if "map" in ctrl:
                        apply_map_update(ctrl["map"])
                    continue
                if not authed:
                    log("dropping blob from unauthenticated bridge")
                    continue
                self.emit_blob(blob)
        except OSError as e:
            log("ws bridge read error (%s)" % e)
        finally:
            self._clear_conn(conn)

    # -- listeners -----------------------------------------------------------
    def run(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", RELAY_PORT))
        listener.listen(1)
        log("listening on 0.0.0.0:%d (tcp)" % RELAY_PORT)
        while True:
            conn, _ = listener.accept()
            self._set_conn(conn, False)
            # One bridge at a time; handle it on the main thread.
            self.handle_bridge(conn)

    def run_ws(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", WS_PORT))
        listener.listen(1)
        tls_ctx = None
        if WS_CERT and WS_KEY:
            tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_ctx.load_cert_chain(WS_CERT, WS_KEY)
        log("listening on 0.0.0.0:%d (websocket%s)"
            % (WS_PORT, "+tls" if tls_ctx else ""))
        while True:
            conn, _ = listener.accept()
            if tls_ctx is not None:
                try:
                    conn = tls_ctx.wrap_socket(conn, server_side=True)
                except OSError as e:
                    log("tls accept failed (%s)" % e)
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
            self._set_conn(conn, True)
            # One bridge at a time; handle it on the main thread.
            self.handle_bridge_ws(conn)


if __name__ == "__main__":
    if ADDR_MAP:
        log("address map: %s" % ADDR_MAP)
    log("login rule: 198.18.0.0/15:%d -> %s" % (LOGIN_PORT, LOGIN_IP))
    log("zone discovery: fanout candidates %s" % (ZONE_CANDIDATES,))
    if WS_PORT:
        Relay().run_ws()
    else:
        Relay().run()

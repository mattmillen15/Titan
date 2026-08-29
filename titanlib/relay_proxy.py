#!/usr/bin/env python3
"""
SMB2 credit-booster proxy for ntlmrelayx --socks.

ntlmrelayx forges NEGOTIATE/SESSION_SETUP responses with CreditRequestResponse=1
and MaxTransactSize=65536, which causes "packet too large" errors when Titanis
tries to send DCE/RPC payloads larger than 65536 bytes.

This module provides two interfaces:

  activate_relay_mode()
      Called automatically by titan dump/shell when --no-pass is detected.
      Detects proxychains, starts a credit-booster proxy thread, writes a
      patched proxychains.conf, and returns an env dict so Titanis subprocesses
      pick up the patched conf. Zero user action required.

  run_proxy() / main()
      Manual mode (titan relay-proxy CLI) for debugging.
"""

import argparse
import atexit
import os
import re
import socket
import struct
import sys
import tempfile
import threading
import time

# ── SMB2 constants ──────────────────────────────────────────────────────────

_SMB2_MAGIC          = b'\xfeSMB'
_SMB2_HDR_SIZE       = 64
_CMD_NEGOTIATE       = 0x0000
_CMD_SESSION_SETUP   = 0x0001
_FLAG_SERVER_TO_REDIR = 0x00000001

# Offsets within an SMB2 header (0-indexed, after the 4-byte NetBIOS prefix)
_OFF_PROTOCOL  = 0          # 4 bytes  \xfeSMB
_OFF_CREDIT_RQ = 14         # 2 bytes  CreditRequestResponse (in response)
_OFF_COMMAND   = 12         # 2 bytes
_OFF_FLAGS     = 16         # 4 bytes

# Offsets within SMB2_NEGOTIATE_Response body (after the 64-byte SMB2 header)
_OFF_NEG_MAX_TRANSACT = 28  # 4 bytes
_OFF_NEG_MAX_READ     = 32  # 4 bytes
_OFF_NEG_MAX_WRITE    = 36  # 4 bytes

_CREDIT_BOOST    = 64
_MAX_SIZE_BOOST  = 8388608  # 8 MB — typical Windows server value


def _patch_smb2_frame(frame: bytes) -> bytes:
    """
    Given raw bytes of one NetBIOS-framed SMB2 PDU, patch credits/sizes if
    this is a forged NEGOTIATE or SESSION_SETUP response from ntlmrelayx.
    Returns (possibly modified) frame bytes.
    """
    if len(frame) < 4 + _SMB2_HDR_SIZE:
        return frame

    hdr = frame[4:]  # skip 4-byte NetBIOS length prefix

    if hdr[:4] != _SMB2_MAGIC:
        return frame  # not SMB2

    command = struct.unpack_from('<H', hdr, _OFF_COMMAND)[0]
    flags   = struct.unpack_from('<I', hdr, _OFF_FLAGS)[0]

    if not (flags & _FLAG_SERVER_TO_REDIR):
        return frame  # client → server, don't touch

    if command not in (_CMD_NEGOTIATE, _CMD_SESSION_SETUP):
        return frame

    frame = bytearray(frame)
    hdr_off = 4  # NetBIOS prefix length

    # Boost credit grant
    current = struct.unpack_from('<H', frame, hdr_off + _OFF_CREDIT_RQ)[0]
    if current < _CREDIT_BOOST:
        struct.pack_into('<H', frame, hdr_off + _OFF_CREDIT_RQ, _CREDIT_BOOST)

    if command == _CMD_NEGOTIATE:
        body_off = hdr_off + _SMB2_HDR_SIZE
        if len(frame) >= body_off + _OFF_NEG_MAX_WRITE + 4:
            for field_off in (_OFF_NEG_MAX_TRANSACT, _OFF_NEG_MAX_READ, _OFF_NEG_MAX_WRITE):
                val = struct.unpack_from('<I', frame, body_off + field_off)[0]
                if val < _MAX_SIZE_BOOST:
                    struct.pack_into('<I', frame, body_off + field_off, _MAX_SIZE_BOOST)

    return bytes(frame)


def _recv_netbios_frame(sock: socket.socket) -> bytes:
    """Read exactly one NetBIOS-framed message from sock."""
    header = b''
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return b''
        header += chunk
    # NetBIOS Session Service: byte 0 = type, bytes 1-3 = big-endian length
    length = struct.unpack('>I', header)[0] & 0x00FFFFFF
    payload = b''
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            return b''
        payload += chunk
    return header + payload


def _socks5_connect(proxy_host: str, proxy_port: int,
                    dest_host: str, dest_port: int) -> socket.socket:
    """Open a SOCKS5 connection through the given proxy to dest."""
    s = socket.create_connection((proxy_host, proxy_port))
    # Greeting: no-auth
    s.sendall(b'\x05\x01\x00')
    resp = s.recv(2)
    if resp != b'\x05\x00':
        raise RuntimeError(f'SOCKS5 no-auth rejected: {resp!r}')
    # CONNECT request (IPv4 or hostname)
    try:
        ip = socket.inet_aton(dest_host)
        req = struct.pack('!BBBB4sH', 5, 1, 0, 1, ip, dest_port)
    except OSError:
        enc = dest_host.encode()
        req = struct.pack('!BBBBB', 5, 1, 0, 3, len(enc)) + enc + struct.pack('!H', dest_port)
    s.sendall(req)
    # Response: 4-byte fixed + address
    r = s.recv(4)
    if len(r) < 4 or r[1] != 0:
        raise RuntimeError(f'SOCKS5 CONNECT failed: {r!r}')
    atype = r[3]
    if atype == 1:
        s.recv(6)   # 4-byte IP + 2-byte port
    elif atype == 3:
        n = ord(s.recv(1))
        s.recv(n + 2)
    elif atype == 4:
        s.recv(18)  # 16-byte IPv6 + 2-byte port
    return s


def _relay_direction(src: socket.socket, dst: socket.socket,
                     patch: bool, label: str):
    """Forward frames from src to dst, optionally patching SMB2 credits."""
    try:
        while True:
            frame = _recv_netbios_frame(src)
            if not frame:
                break
            if patch:
                frame = _patch_smb2_frame(frame)
            dst.sendall(frame)
    except Exception:
        pass
    finally:
        try: src.close()
        except Exception: pass
        try: dst.close()
        except Exception: pass


def _handle_client(client_sock: socket.socket,
                   relay_host: str, relay_port: int,
                   dest_host: str, dest_port: int):
    """Handle one incoming SOCKS5 client connection."""
    try:
        # ── SOCKS5 server handshake with client ──────────────────────────
        greeting = client_sock.recv(257)
        if not greeting or greeting[0] != 5:
            return
        client_sock.sendall(b'\x05\x00')  # no-auth

        req = client_sock.recv(262)
        if not req or req[1] != 1:        # only CONNECT
            client_sock.sendall(b'\x05\x07\x00\x01' + b'\x00' * 6)
            return

        # Parse destination from client's CONNECT
        atype = req[3]
        if atype == 1:                    # IPv4
            c_host = socket.inet_ntoa(req[4:8])
            c_port = struct.unpack('!H', req[8:10])[0]
        elif atype == 3:                  # domain name
            n = req[4]
            c_host = req[5:5+n].decode()
            c_port = struct.unpack('!H', req[5+n:7+n])[0]
        else:
            client_sock.sendall(b'\x05\x08\x00\x01' + b'\x00' * 6)
            return

        # ── Connect to ntlmrelayx SOCKS on behalf of the client ──────────
        relay_sock = _socks5_connect(relay_host, relay_port, c_host, c_port)

        # Tell client: success
        client_sock.sendall(b'\x05\x00\x00\x01' + b'\x00' * 6)

        # ── Bidirectional relay, patching server→client frames ────────────
        t1 = threading.Thread(
            target=_relay_direction,
            args=(relay_sock, client_sock, True,  'srv→cli'),
            daemon=True)
        t2 = threading.Thread(
            target=_relay_direction,
            args=(client_sock, relay_sock, False, 'cli→srv'),
            daemon=True)
        t1.start(); t2.start()
        t1.join();  t2.join()

    except Exception as e:
        print(f'  [!] relay_proxy handler error: {e}', file=sys.stderr)
    finally:
        try: client_sock.close()
        except Exception: pass


def run_proxy(listen_host: str = '127.0.0.1', listen_port: int = 1082,
              relay_host: str = '127.0.0.1', relay_port: int = 1080,
              quiet: bool = False):
    """Start the credit-booster proxy (blocks until KeyboardInterrupt)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((listen_host, listen_port))
    srv.listen(32)
    if not quiet:
        print(f'[*] relay-proxy listening on {listen_host}:{listen_port}')
        print(f'[*] forwarding → ntlmrelayx SOCKS {relay_host}:{relay_port}')
        print(f'[*] patching NEGOTIATE/SESSION_SETUP: credits 1→{_CREDIT_BOOST}, '
              f'MaxTransact/Read/WriteSize 65536→{_MAX_SIZE_BOOST}')
        print(f'[*] point proxychains at socks5 {listen_host} {listen_port}')
    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(
                target=_handle_client,
                args=(conn, relay_host, relay_port, '', 0),
                daemon=True)
            t.start()
    except KeyboardInterrupt:
        if not quiet:
            print('\n[*] relay-proxy stopped')
    finally:
        srv.close()


# ── Automatic relay-mode activation (called by dump.py / shell.py) ────────────

_relay_activated = False
_relay_conf_path: str = ''


def _find_proxychains_conf() -> str:
    env_conf = os.environ.get('PROXYCHAINS_CONF_FILE', '')
    if env_conf and os.path.isfile(env_conf):
        return env_conf
    for p in [os.path.expanduser('~/.proxychains/proxychains.conf'),
              '/etc/proxychains4.conf', '/etc/proxychains.conf']:
        if os.path.isfile(p):
            return p
    return ''


def _parse_socks5_upstream(conf_path: str) -> tuple[str, int]:
    """Return (host, port) of the first socks5 line in the conf."""
    with open(conf_path) as f:
        for line in f:
            line = line.strip()
            if line.startswith('#'):
                continue
            m = re.match(r'socks5\s+(\S+)\s+(\d+)', line, re.IGNORECASE)
            if m:
                return m.group(1), int(m.group(2))
    return '127.0.0.1', 1080


def _pick_free_port(start: int = 1082) -> int:
    for port in range(start, start + 20):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('127.0.0.1', port))
            s.close()
            return port
        except OSError:
            continue
    raise OSError('no free port found in range %d-%d' % (start, start + 19))


def _write_patched_conf(orig_conf: str, listen_port: int) -> str:
    """Copy proxychains conf, replacing the socks5 port with listen_port."""
    with open(orig_conf) as f:
        content = f.read()
    content = re.sub(
        r'(socks5\s+\S+\s+)\d+',
        lambda m: m.group(1) + str(listen_port),
        content,
        flags=re.IGNORECASE,
    )
    fd, path = tempfile.mkstemp(prefix='titan_relay_', suffix='.conf')
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    atexit.register(_safe_unlink, path)
    return path


def _safe_unlink(path: str):
    try:
        os.unlink(path)
    except OSError:
        pass


def activate_relay_mode() -> dict:
    """
    Detect proxychains, start credit-booster proxy thread, return env dict.

    Returns {'PROXYCHAINS_CONF_FILE': '<patched_conf>'} so Titanis subprocesses
    route through the proxy. Returns {} if proxychains is not detected.
    Called once by dump.py and shell.py when --no-pass is active.
    """
    global _relay_activated, _relay_conf_path

    if _relay_activated:
        return {'PROXYCHAINS_CONF_FILE': _relay_conf_path} if _relay_conf_path else {}

    _relay_activated = True  # mark early to prevent double-init on concurrent calls

    ld_preload = os.environ.get('LD_PRELOAD', '')
    if 'proxychains' not in ld_preload.lower():
        return {}

    conf = _find_proxychains_conf()
    if not conf:
        print('[!] relay-proxy: proxychains detected but conf not found; '
              'credit fix inactive', file=sys.stderr)
        return {}

    relay_host, relay_port = _parse_socks5_upstream(conf)

    try:
        listen_port = _pick_free_port(1082)
    except OSError as e:
        print(f'[!] relay-proxy: {e}; credit fix inactive', file=sys.stderr)
        return {}

    t = threading.Thread(
        target=run_proxy,
        kwargs=dict(listen_host='127.0.0.1', listen_port=listen_port,
                    relay_host=relay_host, relay_port=relay_port,
                    quiet=True),
        daemon=True,
    )
    t.start()
    time.sleep(0.15)  # wait for socket to bind

    try:
        _relay_conf_path = _write_patched_conf(conf, listen_port)
    except Exception as e:
        print(f'[!] relay-proxy: could not write patched conf: {e}; '
              'credit fix inactive', file=sys.stderr)
        return {}

    print(f'[*] relay-proxy: :{listen_port} → ntlmrelayx :{relay_port} '
          f'(SMB2 credits patched)', file=sys.stderr)
    return {'PROXYCHAINS_CONF_FILE': _relay_conf_path}


# ── Manual CLI (titan relay-proxy) ────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        prog='titan relay-proxy',
        description='SMB2 credit-booster proxy for ntlmrelayx --socks',
    )
    p.add_argument('--listen-port', '-lp', type=int, default=1082, metavar='PORT',
                   help='Port to listen on (default: 1082)')
    p.add_argument('--relay-port', '-rp', type=int, default=1080, metavar='PORT',
                   help='ntlmrelayx SOCKS port (default: 1080)')
    p.add_argument('--listen-host', default='127.0.0.1', metavar='HOST')
    p.add_argument('--relay-host', default='127.0.0.1', metavar='HOST')
    return p.parse_args()


def main():
    args = parse_args()
    run_proxy(args.listen_host, args.listen_port,
              args.relay_host, args.relay_port)


if __name__ == '__main__':
    main()

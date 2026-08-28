#!/usr/bin/env python3
"""Shared utilities for titan — binary discovery, dotnet env, auth, subprocess."""

import argparse
import csv
import io
import os
import re
import subprocess
import sys


# ── Titanis binary discovery ──────────────────────────────────────────────────

def find_titanis_root() -> str:
    """Return path to the linux-x64 directory containing Titanis binaries.

    Resolution order:
      1. TITANIS_PATH env var (points to the linux-x64 dir directly)
      2. ~/tools/titanis/linux-x64  (standard install location)
      3. Sibling of the titan package directory
    """
    env_path = os.environ.get('TITANIS_PATH', '')
    if env_path and os.path.isdir(env_path):
        return env_path

    candidates = [
        os.path.expanduser('~/tools/titanis/linux-x64'),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     'linux-x64'),
    ]
    for c in candidates:
        if os.path.isdir(c):
            return c
    return candidates[0]


def find_binary(name: str):
    """Return full path to a Titanis binary, or None if not found."""
    root = find_titanis_root()
    path = os.path.join(root, name, name)
    return path if os.path.isfile(path) else None


# ── .NET runtime environment ──────────────────────────────────────────────────

def make_env() -> dict:
    """Build an environment dict with DOTNET_ROOT set correctly."""
    env = os.environ.copy()
    dotnet_root = env.get('DOTNET_ROOT', '')

    if not dotnet_root or not os.path.isdir(os.path.join(dotnet_root, 'shared')):
        candidates = [
            os.path.expanduser('~/.dotnet'),
            '/usr/share/dotnet',
            '/usr/local/share/dotnet',
        ]
        loc_file = '/etc/dotnet/install_location'
        if os.path.isfile(loc_file):
            try:
                loc = open(loc_file).read().strip()
                if loc:
                    candidates.insert(0, loc)
            except Exception:
                pass

        for path in candidates:
            if path and os.path.isdir(os.path.join(path, 'shared')):
                dotnet_root = path
                break

    if dotnet_root:
        env['DOTNET_ROOT'] = dotnet_root
        if dotnet_root not in env.get('PATH', ''):
            env['PATH'] = dotnet_root + os.pathsep + env.get('PATH', '')
    return env


# ── Subprocess runner ─────────────────────────────────────────────────────────

def run(binary: str, subcmd: str, auth: list, extra: list,
        verbose: bool = False, timeout: int = 90):
    """Run a Titanis binary subcommand, return (stdout, returncode)."""
    if binary is None:
        print(
            f'  [!] Titanis binary not found for "{subcmd}" — '
            'run install.sh with TITANIS_PATH set to the linux-x64 directory.',
            file=sys.stderr,
        )
        return '', 127
    cmd = [binary, subcmd] + auth + extra
    if verbose:
        print(f'  >> {" ".join(cmd)}', file=sys.stderr)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=make_env())
        if verbose and r.stderr:
            for line in r.stderr.splitlines():
                print(f'  [!] {line.strip()}', file=sys.stderr)
        return r.stdout, r.returncode
    except subprocess.TimeoutExpired:
        print(f'  [!] Timeout: {os.path.basename(binary)} {subcmd}', file=sys.stderr)
        return '', 1
    except FileNotFoundError:
        print(f'  [!] Binary not found: {binary}', file=sys.stderr)
        return '', 127
    except Exception as e:
        print(f'  [!] Error running {os.path.basename(binary)} {subcmd}: {e}',
              file=sys.stderr)
        return '', 1


# ── Argument helpers ──────────────────────────────────────────────────────────

def add_auth_args(parser):
    """Add standard authentication argument groups to an argparse parser."""
    auth = parser.add_argument_group('Authentication')
    auth.add_argument('-u', '--username', metavar='USER')
    auth.add_argument('-d', '--domain', metavar='DOMAIN', default='',
                      help='Active Directory domain (optional for local accounts)')

    cred = auth.add_mutually_exclusive_group()
    cred.add_argument('-p', '--password', metavar='PASS')
    cred.add_argument('--hash', '-hashes', metavar='[LM:]NT', dest='ntlm_hash',
                      help='NTLM hash for pass-the-hash (LM:NT or just NT). '
                           '-hashes is the impacket-style alias.')
    cred.add_argument('--no-pass', '-no-pass', action='store_true', dest='no_pass',
                      help='No password / empty credential. '
                           'Use with proxychains for ntlmrelayx --socks relay sessions.')

    kerb = parser.add_argument_group('Kerberos')
    kerb.add_argument('-k', '--kerberos', action='store_true',
                      help='Use Kerberos auth. Auto-reads KRB5CCNAME env var. '
                           'Combine with --ccache to override the env var.')
    kerb.add_argument('-K', '--kdc', '-dc-ip', metavar='HOST[:PORT]',
                      help='KDC / DC IP or FQDN. -dc-ip is the impacket-style alias.')
    kerb.add_argument('--aes-key', metavar='HEX',
                      help='AES-128 or AES-256 key for Kerberos auth')
    kerb.add_argument('--ccache', '--ticket-cache', metavar='FILE', dest='ticket_cache',
                      help='Service ticket / TGT ccache file (from getST.py/getTGT.py '
                           'or KRB5CCNAME). --ticket-cache is the legacy alias.')
    kerb.add_argument('--tgt', metavar='FILE',
                      help='TGT ccache/kirbi file (legacy — prefer --ccache)')


def ccache_info(args):
    """Load ccache, fill missing username/domain from principal, print ticket validity."""
    path = getattr(args, 'ticket_cache', None) or getattr(args, 'tgt', None)
    if not path:
        return
    try:
        from impacket.krb5.ccache import CCache
        from datetime import datetime, timezone
        cc = CCache.loadFile(path)
        principal = cc.principal
        if not getattr(args, 'username', None) and principal.components:
            args.username = principal.components[0]['data'].decode()
        if not getattr(args, 'domain', None) and principal.realm:
            args.domain = principal.realm['data'].decode()
        print(f'[*] ccache principal: {args.username}@{args.domain}', file=sys.stderr)
        if cc.credentials:
            t = cc.credentials[0]['time']
            start_ts = t['starttime'] or t['authtime']
            end_ts   = t['endtime']
            now      = datetime.now(tz=timezone.utc)
            if start_ts:
                start_dt = datetime.fromtimestamp(start_ts, tz=timezone.utc)
                print(f'[*] ticket issued:  {start_dt.strftime("%Y-%m-%d %H:%M:%S UTC")}',
                      file=sys.stderr)
            if end_ts:
                end_dt  = datetime.fromtimestamp(end_ts, tz=timezone.utc)
                ttl     = end_dt - now
                expired = ttl.total_seconds() < 0
                ttl_str = ('EXPIRED' if expired
                           else f'expires in {int(ttl.total_seconds() // 3600)}h'
                                f'{int((ttl.total_seconds() % 3600) // 60)}m')
                print(f'[*] ticket expiry:  {end_dt.strftime("%Y-%m-%d %H:%M:%S UTC")} ({ttl_str})',
                      file=sys.stderr)
    except Exception:
        pass


def auth_args(args) -> list:
    """Build the Titanis binary auth flag list from parsed args."""
    a = ['-UserName', getattr(args, 'username', None) or '']
    if getattr(args, 'domain', ''):
        a += ['-UserDomain', args.domain]
    ntlm_hash = getattr(args, 'ntlm_hash', None)
    if ntlm_hash:
        nt = ntlm_hash.split(':', 1)[1] if ':' in ntlm_hash else ntlm_hash
        a += ['-NtlmHash', nt]
    elif getattr(args, 'password', None):
        a += ['-Password', args.password]
    elif getattr(args, 'no_pass', False):
        a += ['-Password', '']
    if getattr(args, 'kdc', None):          a += ['-Kdc',        args.kdc]
    if getattr(args, 'aes_key', None):      a += ['-AesKey',     args.aes_key]
    if getattr(args, 'tgt', None):          a += ['-Tgt',        args.tgt]
    if getattr(args, 'ticket_cache', None): a += ['-TicketCache', args.ticket_cache]
    return a


def apply_target_string(args, host_attr: str = 'target'):
    """Parse an impacket-style [[domain/]user[:pass]@]host target string into args."""
    ts = getattr(args, 'target_string', None)
    if not ts:
        return
    at = ts.rfind('@')
    if at >= 0:
        host   = ts[at + 1:]
        prefix = ts[:at]
        m = re.match(r'^(?:(?P<d>[^/]+)/)?(?P<u>[^:]+)(?::(?P<p>.*))?$', prefix)
        if m:
            if m.group('d') and not getattr(args, 'domain', ''):
                args.domain = m.group('d')
            if m.group('u') and not getattr(args, 'username', None):
                args.username = m.group('u')
            pw = m.group('p')
            if pw is not None and not getattr(args, 'password', None) \
                    and not getattr(args, 'ntlm_hash', None):
                args.password = pw
            if host and not getattr(args, host_attr, None):
                setattr(args, host_attr, resolve_host(host))
            return
    if not getattr(args, host_attr, None):
        setattr(args, host_attr, resolve_host(ts))


def validate_auth(args, parser, require_cred: bool = True):
    """Validate auth state; auto-fill ticket_cache from KRB5CCNAME when -k used."""
    if getattr(args, 'kerberos', False) and not getattr(args, 'ticket_cache', None) \
            and not getattr(args, 'tgt', None):
        env_ccache = os.environ.get('KRB5CCNAME', '')
        if env_ccache:
            args.ticket_cache = env_ccache
            print(f'[*] KRB5CCNAME → {env_ccache}', file=sys.stderr)
        else:
            parser.error('-k/--kerberos requires KRB5CCNAME to be set or --ccache to be given')

    if getattr(args, 'ticket_cache', None) or getattr(args, 'tgt', None):
        ccache_info(args)

    has_ccache = bool(getattr(args, 'ticket_cache', None) or getattr(args, 'tgt', None))
    if not getattr(args, 'username', None) and not getattr(args, 'kerberos', False) \
            and not has_ccache:
        parser.error('username is required (-u or target string)')

    if require_cred:
        has_cred = any([getattr(args, 'password', None),
                        getattr(args, 'ntlm_hash', None),
                        getattr(args, 'aes_key', None),
                        getattr(args, 'tgt', None),
                        getattr(args, 'ticket_cache', None),
                        getattr(args, 'no_pass', False)])
        if not has_cred:
            parser.error('credential required: -p, --hash/-hashes, --aes-key, '
                         '--ccache/--tgt, --no-pass, or -k (uses KRB5CCNAME)')


def resolve_host(host: str) -> str:
    """Return FQDN for a bare IP; pass hostnames through unchanged."""
    import socket
    if not re.match(r'^[\d.]+$', host) and ':' not in host:
        return host
    try:
        return socket.gethostbyaddr(host)[0]
    except socket.herror:
        return host

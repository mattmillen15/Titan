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

  SMB relay / proxychains:
    proxychains titan shell -u administrator -d DOMAIN --no-pass -t 192.168.1.10

Built-in commands (prefix with !):
    !upload <local> [remote]   Upload a local file to the remote host
    !download <remote> [local] Download a remote file to local disk
    !ls [remote_path]          List remote directory (default: cwd)
    !cd <remote_path>          Change remote working directory
    !pwd                       Print remote working directory
    !ps                        List remote processes
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
import sys

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

HELP = """\
Built-in commands (prefix with !):
  !upload <local> [remote]   Upload local file to remote host via SMB
  !download <remote> [local] Download remote file to local disk via SMB
  !ls [path]                 List remote directory (default: cwd)
  !cd <path>                 Change remote working directory
  !pwd                       Show remote working directory
  !ps                        List running processes (WMI)
  !services                  List services (SCM)
  !shares                    List SMB shares
  !help                      This help

All other input is sent to cmd.exe on the remote host.
Paths accept both \\ and / separators."""


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


def cmd_services(host, auth, verbose=False):
    if not SCM:
        print('[!] Scm binary not found')
        return
    out, rc = run(SCM, 'query', auth, [host, '-ConsoleOutputStyle', 'Csv'],
                  verbose=verbose, timeout=30)
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


def shell(host, auth, cwd='C:\\Windows\\System32', verbose=False, timeout=120):
    print(BANNER)
    user = auth[auth.index('-UserName') + 1] if '-UserName' in auth else '?'
    print(f'[*] Connected to {host} as {user}')
    print(f'[*] Working directory: {cwd}')
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
            elif cmd == 'upload':   cmd_upload(host, auth, rest, cwd, verbose=verbose)
            elif cmd == 'download': cmd_download(host, auth, rest, verbose=verbose)
            elif cmd == 'ls':       cmd_ls(host, auth, rest, cwd, verbose=verbose)
            elif cmd == 'cd':       cwd = cmd_cd(cwd, rest)
            elif cmd == 'pwd':      print(cwd)
            elif cmd == 'ps':       cmd_ps(host, auth, verbose=verbose)
            elif cmd == 'services': cmd_services(host, auth, verbose=verbose)
            elif cmd == 'shares':   cmd_shares(host, auth, verbose=verbose)
            else: print(f'[!] unknown built-in: !{cmd}  (try !help)')
            continue

        out, rc = run(WMI, 'exec', auth, [host, f'cd /d {cwd} && {line}'],
                      verbose=verbose, timeout=timeout)
        if out:
            sys.stdout.write(out)
            if not out.endswith('\n'):
                print()
        elif rc != 0:
            print(f'[!] command failed (rc={rc}) — run with -v for details')


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

    missing = [n for n, b in [('Wmi', WMI), ('Smb2Client', SMB)] if not b]
    if missing:
        print(f'[!] required binaries not found: {", ".join(missing)}', file=sys.stderr)
        sys.exit(1)
    if not SCM:
        print('[!] Scm binary not found — !services will be unavailable', file=sys.stderr)

    args = parse_args()
    shell(args.target, auth_args(args),
          cwd=args.cwd, verbose=args.verbose, timeout=args.timeout)


if __name__ == '__main__':
    main()

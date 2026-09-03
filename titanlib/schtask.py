#!/usr/bin/env python3
"""
titan schtask — scheduled task operations via Titanis (MS-TSCH)

Create, run, query, and delete scheduled tasks on remote Windows hosts
using native DCE-RPC (no impacket, no psexec, no WMI).

Usage:
    titan schtask query DOMAIN/user:pass@HOST
    titan schtask create DOMAIN/user:pass@HOST -n \\MyTask -c cmd.exe -a "/c whoami > C:\\out.txt"
    titan schtask run   DOMAIN/user:pass@HOST -n \\MyTask
    titan schtask get   DOMAIN/user:pass@HOST -n \\MyTask
    titan schtask stop  DOMAIN/user:pass@HOST -n \\MyTask
    titan schtask del   DOMAIN/user:pass@HOST -n \\MyTask

  Kerberos:
    KRB5CCNAME=admin.ccache titan schtask query -k -t HOST.domain.local

  Quick exec (create + run + cleanup):
    titan schtask exec DOMAIN/user:pass@HOST -c cmd.exe -a "/c whoami > C:\\out.txt"
    titan schtask exec DOMAIN/user:pass@HOST -c cmd.exe -a "/c whoami > C:\\out.txt" --no-delete

  Run as a logged-in user (fires via RegistrationTrigger):
    titan schtask exec DOMAIN/user:pass@HOST --run-as DOMAIN\\targetuser -c net.exe -a "use"
    titan schtask exec DOMAIN/user:pass@HOST --run-as DOMAIN\\targetuser -c beacon.exe

  Trigger on next logon:
    titan schtask exec DOMAIN/user:pass@HOST --run-as DOMAIN\\targetuser --on-logon -c implant.exe --no-delete
"""

import argparse
import os
import random
import string
import subprocess
import sys
import time

from titanlib.common import (find_binary, make_env, add_auth_args, auth_args,
                              apply_target_string, validate_auth)

TSCH = None


def _find_tsch():
    global TSCH
    TSCH = find_binary('Tsch')
    if TSCH is None:
        print('[!] Tsch binary not found. Run install.sh or set TITANIS_PATH.',
              file=sys.stderr)
        sys.exit(1)


def _rand_name():
    return '\\T_' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))


_PREFER_SMB = False


def _tsch(subcmd, auth, extra, verbose=False, timeout=60):
    """Run Tsch binary. Titanis writes data to stderr, so we merge streams."""
    cmd = [TSCH, subcmd] + auth + extra
    if _PREFER_SMB:
        cmd.append('-PreferSmb')
    if verbose:
        print(f'  >> {" ".join(cmd)}', file=sys.stderr)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=make_env())
        combined = (r.stderr or '') + (r.stdout or '')
        rc = r.returncode
        if 'Tool execution failed' in combined or '.Exception' in combined:
            rc = rc or 1
            combined = _clean_error(combined, verbose)
        else:
            combined = _strip_noise(combined)
        return combined, rc
    except subprocess.TimeoutExpired:
        print(f'  [!] Timeout: Tsch {subcmd}', file=sys.stderr)
        return '', 1
    except FileNotFoundError:
        print(f'  [!] Binary not found: {TSCH}', file=sys.stderr)
        return '', 127


def _clean_error(raw, verbose=False):
    if verbose:
        return raw
    lines = raw.splitlines()
    msg = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith('Tsch Version') or s.startswith('at '):
            continue
        if s.startswith('Tool execution failed'):
            continue
        for exc in ('Win32Exception', 'SocketException', 'TschException',
                    'TimeoutException', 'IOException'):
            if exc in s:
                idx = s.index(exc)
                colon = s.find(':', idx)
                msg.append(s[colon + 1:].strip() if colon != -1 else s[idx:])
                return '\n'.join(msg)
        if 'KDC_ERR' in s or 'ERROR:' in s or 'WARN:' in s:
            msg.append(s)
    return '\n'.join(msg) if msg else raw


def _strip_noise(raw):
    lines = []
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith('INFO:'):
            s = s[5:].strip()
        if not s:
            continue
        if s.startswith('Tsch Version'):
            continue
        if s.startswith('WARN:') and ('Kerberos' in s or 'IP address' in s):
            continue
        lines.append(s)
    return '\n'.join(lines)


def _build_auth(args):
    a = auth_args(args)
    if getattr(args, 'kdc', None):
        if '-Kdc' not in a:
            a += ['-Kdc', args.kdc]
    return a


def _needs_kdc(args):
    """Auto-add -Kdc matching target when using password auth (Kerberos needs it)."""
    if getattr(args, 'kdc', None):
        return
    if getattr(args, 'ntlm_hash', None) or getattr(args, 'no_pass', False):
        return
    if getattr(args, 'ticket_cache', None) or getattr(args, 'tgt', None):
        return
    host = getattr(args, 'target_raw', None) or getattr(args, 'target', None)
    if host:
        args.kdc = host


# ── Subcommands ──────────────────────────────────────────────────────────────

def cmd_query(args):
    auth = _build_auth(args)
    extra = []
    if args.path:
        extra += ['-Path', args.path]
    if args.recurse:
        extra += ['-Recurse']
    if args.hidden:
        extra += ['-IncludeHidden']
    out, rc = _tsch('query', auth + [args.target], extra, verbose=args.verbose)
    if out:
        print(out)
    return rc


def cmd_get(args):
    auth = _build_auth(args)
    extra = ['-TaskPath', args.name]
    out, rc = _tsch('get', auth + [args.target], extra, verbose=args.verbose)
    if out:
        print(out)
    return rc


def cmd_create(args):
    auth = _build_auth(args)
    extra = ['-TaskPath', args.name]
    if args.xml_file:
        extra += ['-XmlFile', args.xml_file]
    elif args.command:
        extra += ['-Command', args.command]
        if args.arguments:
            extra += ['-Arguments', args.arguments]
    else:
        print('[!] Specify -c/--command or --xml-file', file=sys.stderr)
        return 1
    if getattr(args, 'run_as', None):
        extra += ['-RunAs', args.run_as]
    if getattr(args, 'logon_type', None):
        extra += ['-RunAsLogon', args.logon_type]
    if getattr(args, 'on_logon', False):
        extra += ['-OnLogon']
    if args.update:
        extra += ['-Update']
    out, rc = _tsch('create', auth + [args.target], extra, verbose=args.verbose)
    if rc == 0:
        print(f'[+] Task created: {args.name}')
    else:
        print(f'[!] Failed to create task (rc={rc})', file=sys.stderr)
        if out:
            print(out.strip(), file=sys.stderr)
    return rc


def cmd_run(args):
    auth = _build_auth(args)
    extra = ['-TaskPath', args.name]
    if getattr(args, 'session_id', None):
        extra += ['-SessionId', str(args.session_id)]
    if getattr(args, 'run_as_user', None):
        extra += ['-RunAsUser', args.run_as_user]
    out, rc = _tsch('run', auth + [args.target], extra, verbose=args.verbose)
    if rc == 0:
        for line in out.splitlines():
            if 'instance:' in line.lower():
                print(f'[+] {line.strip().split("INFO:")[-1].strip()}')
                break
        else:
            print(f'[+] Task {args.name} started')
    else:
        print(f'[!] Failed to run task (rc={rc})', file=sys.stderr)
    return rc


def cmd_stop(args):
    auth = _build_auth(args)
    extra = ['-TaskPath', args.name]
    out, rc = _tsch('stop', auth + [args.target], extra, verbose=args.verbose)
    if rc == 0:
        print(f'[+] Stopped: {args.name}')
    else:
        print(f'[!] Failed to stop task (rc={rc})', file=sys.stderr)
    return rc


def cmd_delete(args):
    auth = _build_auth(args)
    extra = ['-TaskPath', args.name]
    out, rc = _tsch('delete', auth + [args.target], extra, verbose=args.verbose)
    if rc == 0:
        print(f'[+] Deleted: {args.name}')
    else:
        print(f'[!] Failed to delete task (rc={rc})', file=sys.stderr)
    return rc


def cmd_enable(args):
    auth = _build_auth(args)
    extra = ['-TaskPath', args.name]
    if args.disable:
        extra += ['-Disable']
    out, rc = _tsch('enable', auth + [args.target], extra, verbose=args.verbose)
    if rc == 0:
        action = 'Disabled' if args.disable else 'Enabled'
        print(f'[+] {action}: {args.name}')
    else:
        print(f'[!] Failed (rc={rc})', file=sys.stderr)
    return rc


def cmd_folders(args):
    auth = _build_auth(args)
    extra = []
    if args.path:
        extra += ['-Path', args.path]
    if args.recurse:
        extra += ['-Recurse']
    out, rc = _tsch('folders', auth + [args.target], extra, verbose=args.verbose)
    if out:
        print(out)
    return rc


def cmd_exec(args):
    """Create a task, run it immediately, then delete it (one-shot execution)."""
    task_name = args.name or _rand_name()
    auth = _build_auth(args)

    # Create
    create_extra = ['-TaskPath', task_name, '-Command', args.command]
    if args.arguments:
        create_extra += ['-Arguments', args.arguments]
    if getattr(args, 'run_as', None):
        create_extra += ['-RunAs', args.run_as]
    if getattr(args, 'logon_type', None):
        create_extra += ['-RunAsLogon', args.logon_type]
    if getattr(args, 'on_logon', False):
        create_extra += ['-OnLogon']
    out, rc = _tsch('create', auth + [args.target], create_extra, verbose=args.verbose)
    if rc != 0:
        print(f'[!] Failed to create task (rc={rc})', file=sys.stderr)
        if out:
            print(out.strip(), file=sys.stderr)
        return rc

    print(f'[+] Created: {task_name}')

    run_ok = True
    run_as = getattr(args, 'run_as', None)
    if run_as:
        print(f'[*] Task fires via RegistrationTrigger as {run_as}')
    else:
        out, rc = _tsch('run', auth + [args.target], ['-TaskPath', task_name],
                         verbose=args.verbose)
        if rc == 0:
            print(f'[+] Executed: {task_name}')
        else:
            run_ok = False
            print(f'[!] Run failed (rc={rc}) — task left for retry: {task_name}',
                  file=sys.stderr)
            if out:
                print(out.strip(), file=sys.stderr)
            return rc

    wait = getattr(args, 'wait', 5)
    if wait > 0 and not args.no_delete:
        print(f'[*] Waiting {wait}s for execution...')
        time.sleep(wait)

    if not args.no_delete:
        out2, rc2 = _tsch('delete', auth + [args.target], ['-TaskPath', task_name],
                           verbose=args.verbose)
        if rc2 == 0:
            print(f'[+] Deleted: {task_name}')
        else:
            print(f'[!] Delete failed — manually remove {task_name}', file=sys.stderr)
    else:
        print(f'[*] Task left in place: {task_name}')

    return rc


# ── Argument parsing ─────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog='titan schtask',
        description='Scheduled task operations via Titanis MS-TSCH (native DCE-RPC)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument('--prefer-smb', action='store_true',
                   help='Route RPC through SMB named pipes (port 445) instead of TCP (port 135)')
    sub = p.add_subparsers(dest='action', help='Action to perform')

    # -- query --
    q = sub.add_parser('query', aliases=['list', 'ls'],
                       help='Enumerate scheduled tasks')
    q.add_argument('target_string', nargs='?', metavar='[domain/]user[:pass]@host')
    q.add_argument('-t', '--target', metavar='HOST')
    q.add_argument('--path', default='\\', help='Folder path (default: root \\)')
    q.add_argument('-R', '--recurse', action='store_true')
    q.add_argument('--hidden', action='store_true', help='Include hidden tasks')
    add_auth_args(q)
    q.add_argument('-v', '--verbose', action='store_true')
    q.set_defaults(func=cmd_query)

    # -- get --
    g = sub.add_parser('get', aliases=['xml'],
                       help='Retrieve task XML definition')
    g.add_argument('target_string', nargs='?', metavar='[domain/]user[:pass]@host')
    g.add_argument('-t', '--target', metavar='HOST')
    g.add_argument('-n', '--name', required=True, help='Task path (e.g. \\MyTask)')
    add_auth_args(g)
    g.add_argument('-v', '--verbose', action='store_true')
    g.set_defaults(func=cmd_get)

    # -- create --
    c = sub.add_parser('create', aliases=['register'],
                       help='Create a scheduled task')
    c.add_argument('target_string', nargs='?', metavar='[domain/]user[:pass]@host')
    c.add_argument('-t', '--target', metavar='HOST')
    c.add_argument('-n', '--name', required=True, help='Task path (e.g. \\MyTask)')
    c.add_argument('-c', '--command', help='Command to execute')
    c.add_argument('-a', '--arguments', help='Command arguments')
    c.add_argument('--xml-file', help='Task XML file')
    c.add_argument('--run-as', metavar='DOMAIN\\USER',
                   help='Run task as this user (default: SYSTEM)')
    c.add_argument('--logon-type', metavar='TYPE',
                   choices=['Password', 'S4U', 'InteractiveToken'],
                   help='Logon type: InteractiveToken (default with --run-as), Password, S4U')
    c.add_argument('--on-logon', action='store_true',
                   help='Trigger task when the --run-as user next logs in')
    c.add_argument('--update', action='store_true', help='Update if exists')
    add_auth_args(c)
    c.add_argument('-v', '--verbose', action='store_true')
    c.set_defaults(func=cmd_create)

    # -- run --
    r = sub.add_parser('run', aliases=['start'],
                       help='Run a task immediately')
    r.add_argument('target_string', nargs='?', metavar='[domain/]user[:pass]@host')
    r.add_argument('-t', '--target', metavar='HOST')
    r.add_argument('-n', '--name', required=True, help='Task path')
    r.add_argument('--session-id', type=int, metavar='ID',
                   help='Run in this session ID (active RDP session)')
    r.add_argument('--run-as-user', metavar='DOMAIN\\USER',
                   help='Run as this user')
    add_auth_args(r)
    r.add_argument('-v', '--verbose', action='store_true')
    r.set_defaults(func=cmd_run)

    # -- stop --
    s = sub.add_parser('stop', help='Stop running instances of a task')
    s.add_argument('target_string', nargs='?', metavar='[domain/]user[:pass]@host')
    s.add_argument('-t', '--target', metavar='HOST')
    s.add_argument('-n', '--name', required=True, help='Task path')
    add_auth_args(s)
    s.add_argument('-v', '--verbose', action='store_true')
    s.set_defaults(func=cmd_stop)

    # -- delete --
    d = sub.add_parser('del', aliases=['delete', 'rm'],
                       help='Delete a scheduled task')
    d.add_argument('target_string', nargs='?', metavar='[domain/]user[:pass]@host')
    d.add_argument('-t', '--target', metavar='HOST')
    d.add_argument('-n', '--name', required=True, help='Task path')
    add_auth_args(d)
    d.add_argument('-v', '--verbose', action='store_true')
    d.set_defaults(func=cmd_delete)

    # -- enable --
    e = sub.add_parser('enable', help='Enable or disable a task')
    e.add_argument('target_string', nargs='?', metavar='[domain/]user[:pass]@host')
    e.add_argument('-t', '--target', metavar='HOST')
    e.add_argument('-n', '--name', required=True, help='Task path')
    e.add_argument('--disable', action='store_true')
    add_auth_args(e)
    e.add_argument('-v', '--verbose', action='store_true')
    e.set_defaults(func=cmd_enable)

    # -- folders --
    f = sub.add_parser('folders', help='Enumerate task folders')
    f.add_argument('target_string', nargs='?', metavar='[domain/]user[:pass]@host')
    f.add_argument('-t', '--target', metavar='HOST')
    f.add_argument('--path', default='\\', help='Starting folder')
    f.add_argument('-R', '--recurse', action='store_true')
    add_auth_args(f)
    f.add_argument('-v', '--verbose', action='store_true')
    f.set_defaults(func=cmd_folders)

    # -- exec (one-shot) --
    x = sub.add_parser('exec', aliases=['oneshot'],
                       help='Create + run + delete in one shot')
    x.add_argument('target_string', nargs='?', metavar='[domain/]user[:pass]@host')
    x.add_argument('-t', '--target', metavar='HOST')
    x.add_argument('-n', '--name', help='Task name (random if omitted)')
    x.add_argument('-c', '--command', required=True, help='Command to execute')
    x.add_argument('-a', '--arguments', help='Command arguments')
    x.add_argument('--run-as', metavar='DOMAIN\\USER',
                   help='Run task as this user (default: SYSTEM)')
    x.add_argument('--logon-type', metavar='TYPE',
                   choices=['Password', 'S4U', 'InteractiveToken'],
                   help='Logon type: InteractiveToken (default with --run-as), Password, S4U')
    x.add_argument('--on-logon', action='store_true',
                   help='Trigger task when the --run-as user next logs in')
    x.add_argument('--no-delete', action='store_true',
                   help='Leave task in place after execution')
    x.add_argument('--wait', type=int, default=5, metavar='SEC',
                   help='Seconds to wait before cleanup (default: 5)')
    add_auth_args(x)
    x.add_argument('-v', '--verbose', action='store_true')
    x.set_defaults(func=cmd_exec)

    return p


def main():
    global _PREFER_SMB
    _find_tsch()
    parser = build_parser()
    args = parser.parse_args()
    _PREFER_SMB = getattr(args, 'prefer_smb', False)

    if not args.action:
        parser.print_help()
        sys.exit(1)

    apply_target_string(args)
    _needs_kdc(args)
    validate_auth(args, parser, require_cred=True)

    if not getattr(args, 'target', None):
        parser.error('target is required (-t or target string)')

    rc = args.func(args)
    sys.exit(rc or 0)


if __name__ == '__main__':
    main()

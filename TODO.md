# Proxychains / ntlmrelayx --socks relay support — TODO

## Goal
Make `proxychains titan shell --scm DOMAIN/USER@<ip> --no-pass` work
transparently with ntlmrelayx `--socks` relay sessions on engagement machines.

## What was tried

### 1. relay_proxy.py — SMB2 credit-booster proxy
A SOCKS5 proxy thread that sat between Titanis and ntlmrelayx, patching
CreditRequestResponse (1 → 64) and MaxTransactSize (65536 → 8MB) in forged
NEGOTIATE/SESSION_SETUP responses. Removed because the root problem was
socket routing, not credits.

### 2. proxychains 3.x → 4.x lib substitution
`activate_relay_mode()` detected proxychains 3.x in LD_PRELOAD and tried to
swap in libproxychains.so.4 so .NET CoreCLR sockets would be intercepted.
Worked on machines that had proxychains4 installed; engagement machine
(cts-mantis-037) had neither libproxychains.so.4 nor proxychains4.

### 3. Python/impacket SCM exec path (`--socks` flag, susinternals pattern)
Replaced Titanis Scm (.NET binary, not hooked by proxychains 3.x) with a
pure Python/impacket SCM exec on a single SMBConnection. Rationale: Python
uses libc sockets, which proxychains 3.x *should* hook. In practice,
proxychains 3.x on cts-mantis-037 did NOT hook Python socket calls either
(likely ABI/version issue with the installed libproxychains.so.3).

### 4. Local TCP→SOCKS5 forwarder thread
When proxychains-ng 4.x was NOT in LD_PRELOAD, spun up an in-process
forwarder thread that connected directly to ntlmrelayx at 127.0.0.1:1080
(no proxychains hook needed — ntlmrelayx is local) and provided a local port
for SMBConnection to connect to. Also added SOCKS5 username:password auth
(method 0x02, username = DOMAIN/USER) to handle ntlmrelayx versions that
require it. Removed with everything else — did not get to confirm if it
worked before engagement priorities shifted.

## Root causes

- **proxychains 3.x on cts-mantis-037** does not hook .NET CoreCLR OR Python
  socket calls — the installed libproxychains.so.3 appears to have an ABI
  issue with the system libc version.
- **No proxychains4** (`apt install proxychains4`) on the engagement machine.

## Recommended fix (if revisiting)

1. Get proxychains4 on the engagement machine (`apt install proxychains4` or
   copy libproxychains.so.4 from another host into /tmp and point LD_PRELOAD
   at it manually).
2. Either approach then works: the Titanis Scm .NET binary (proxychains4
   hooks CoreCLR) or the Python/impacket path (proxychains4 hooks Python).
3. Alternatively, re-add the local forwarder approach from attempt #4 —
   it is proxychains-independent and only needs ntlmrelayx running on
   localhost:1080.

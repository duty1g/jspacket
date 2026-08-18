#!/usr/bin/env node
/**
 * jspacket - addcomputer
 *
 * Adds a computer account to the domain and sets its password. Supports SAMR
 * over SMB (the way modern Windows joins a machine through the GUI) and LDAPS.
 * Plain LDAP is not supported, as it doesn't allow setting the password.
 *
 * Python implementation by JaGoTu (@jagotu). TypeScript port.
 */

import { Buffer } from 'node:buffer';
import { parseArgs } from 'node:util';

import {
  parseCredentials,
  init as initLogger,
  info,
  error as logError,
  debug as logDebug,
  critical,
  getLevel,
  LogLevel,
  normalizeArgs,
  initProxy,
  BANNER,
} from '@impacket/examples';

import {
  DCERPCTransportFactory,
  heptMap,
  MSRPC_UUID_SAMR,
  MAXIMUM_ALLOWED,
  DELETE,
  SAM_SERVER_ENUMERATE_DOMAINS,
  SAM_SERVER_LOOKUP_DOMAIN,
  DOMAIN_LOOKUP,
  DOMAIN_CREATE_USER,
  USER_FORCE_PASSWORD_CHANGE,
  USER_WORKSTATION_TRUST_ACCOUNT,
  USER_INFORMATION_CLASS,
  SAMPR_USER_INFO_BUFFER,
  hSamrConnect5,
  hSamrEnumerateDomainsInSamServer,
  hSamrLookupDomainInSamServer,
  hSamrOpenDomain,
  hSamrOpenUser,
  hSamrLookupNamesInDomain,
  hSamrCreateUser2InDomain,
  hSamrSetPasswordInternal4New,
  hSamrSetNTInternal1,
  hSamrSetInformationUser2,
  hSamrDeleteUser,
  hSamrCloseHandle,
} from '@impacket/dcerpc';

import {
  LDAPConnection,
  LDAPSessionError,
  Operation,
  Scope,
} from '@impacket/ldap';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const ASCII_LETTERS_DIGITS =
  'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const UPPER_DIGITS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

function randomFrom(charset: string, length: number): string {
  let out = '';
  for (let i = 0; i < length; i++) {
    out += charset[Math.floor(Math.random() * charset.length)];
  }
  return out;
}

function generateComputerName(): string {
  return `DESKTOP-${randomFrom(UPPER_DIGITS, 8)}$`;
}

interface Options {
  domainNetbios: string | null;
  computerName: string | null;
  computerPass: string | null;
  noAdd: boolean;
  delete: boolean;
  method: string;
  port: number | null;
  baseDN: string | null;
  computerGroup: string | null;
  hashes: string | null;
  aesKey: string | null;
  k: boolean;
  dcHost: string | null;
  dcIp: string | null;
}

// ---------------------------------------------------------------------------
// ADDCOMPUTER
// ---------------------------------------------------------------------------

class ADDCOMPUTER {
  private username: string;
  private password: string;
  private domain: string;
  private lmhash = '';
  private nthash = '';
  private hashes: string | null;
  private aesKey: string | null;
  private doKerberos: boolean;
  private target: string | null;
  private kdcHost: string | null;
  private computerName: string | null;
  private computerPassword: string;
  private method: string;
  private port: number;
  private domainNetbios: string;
  private noAdd: boolean;
  private delete: boolean;
  private targetIp: string | null;
  private baseDN: string;
  private computerGroup: string;

  constructor(username: string, password: string, domain: string, opts: Options) {
    this.username = username;
    this.password = password;
    this.domain = domain;
    this.hashes = opts.hashes;
    this.aesKey = opts.aesKey;
    this.doKerberos = opts.k;
    this.target = opts.dcHost;
    this.kdcHost = opts.dcHost;
    this.computerName = opts.computerName;
    this.method = opts.method;
    this.noAdd = opts.noAdd;
    this.delete = opts.delete;
    this.targetIp = opts.dcIp;
    this.domainNetbios = opts.domainNetbios ?? domain;

    if (this.targetIp !== null) {
      this.kdcHost = this.targetIp;
    }

    if (this.method !== 'SAMR' && this.method !== 'LDAPS') {
      throw new Error(`Unsupported method ${this.method}`);
    }

    if (this.doKerberos && opts.dcHost === null) {
      throw new Error('Kerberos auth requires DNS name of the target DC. Use -dc-host.');
    }

    if (this.method === 'LDAPS' && !this.domain.includes('.')) {
      logError(
        `'${this.domain}' doesn't look like a FQDN. Generating baseDN will probably fail.`,
      );
    }

    if (this.hashes !== null) {
      const parts = this.hashes.split(':');
      this.lmhash = parts[0] ?? '';
      this.nthash = parts[1] ?? '';
    }

    if (this.computerName === null) {
      if (this.noAdd) {
        throw new Error('You have to provide a computer name when using -no-add.');
      } else if (this.delete) {
        throw new Error('You have to provide a computer name when using -delete.');
      }
    } else {
      if (this.computerName[this.computerName.length - 1] !== '$') {
        this.computerName += '$';
      }
    }

    if (opts.computerPass === null) {
      this.computerPassword = randomFrom(ASCII_LETTERS_DIGITS, 32);
    } else {
      this.computerPassword = opts.computerPass;
    }

    if (this.target === null) {
      if (!this.domain.includes('.')) {
        logError(
          `No DC host set and '${this.domain}' doesn't look like a FQDN. DNS resolution of short names will probably fail.`,
        );
      }
      this.target = this.domain;
    }

    if (opts.port === null) {
      this.port = this.method === 'SAMR' ? 445 : 636;
    } else {
      this.port = opts.port;
    }

    if (this.method === 'LDAPS' && opts.baseDN === null) {
      this.baseDN = this.domain
        .split('.')
        .map((p) => `dc=${p}`)
        .join(',');
    } else {
      this.baseDN = opts.baseDN ?? '';
    }

    if (this.method === 'LDAPS' && opts.computerGroup === null) {
      this.computerGroup = `CN=Computers,${this.baseDN}`;
    } else {
      this.computerGroup = opts.computerGroup ?? '';
    }
  }

  async run(): Promise<void> {
    if (this.method === 'SAMR') {
      await this.runSamr();
    } else if (this.method === 'LDAPS') {
      await this.runLdaps();
    }
  }

  // -------------------------------------------------------------------------
  // SAMR
  // -------------------------------------------------------------------------

  private async runSamr(): Promise<void> {
    const destHost = this.targetIp !== null ? this.targetIp : this.target!;
    const stringBinding = await heptMap(destHost, MSRPC_UUID_SAMR, undefined, 'ncacn_np');
    if (!stringBinding) {
      critical('Could not obtain a SAMR string binding from the endpoint mapper.');
      return;
    }
    const rpctransport = DCERPCTransportFactory(stringBinding);
    rpctransport.setDport(this.port);

    if (this.targetIp !== null) {
      rpctransport.setRemoteHost(this.targetIp);
      rpctransport.setRemoteName(this.target!);
    }

    if ('setCredentials' in rpctransport) {
      rpctransport.setCredentials(
        this.username,
        this.password,
        this.domain,
        this.lmhash,
        this.nthash,
        this.aesKey,
      );
    }
    rpctransport.setKerberos(this.doKerberos, this.kdcHost);
    await this.doSAMRAdd(rpctransport);
  }

  private async doSAMRAdd(
    rpctransport: ReturnType<typeof DCERPCTransportFactory>,
  ): Promise<void> {
    const dce = rpctransport.getDceRpc();
    let servHandle: unknown = null;
    let domainHandle: unknown = null;
    let userHandle: unknown = null;
    try {
      await dce.connect();
      await dce.bind(MSRPC_UUID_SAMR);

      const samrConnectResponse = await hSamrConnect5(
        dce,
        `\\\\${this.target}\x00`,
        SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN,
      );
      servHandle = samrConnectResponse.get('ServerHandle');

      const samrEnumResponse = await hSamrEnumerateDomainsInSamServer(
        dce,
        servHandle as never,
      );
      const domains = (samrEnumResponse.get('Buffer') as any).get('Buffer') as any[];
      const domainsWithoutBuiltin = domains.filter(
        (x) => String(x.get('Name')).toLowerCase() !== 'builtin',
      );

      let selectedDomain: string;
      if (domainsWithoutBuiltin.length > 1) {
        const domain = domains.filter(
          (x) => String(x.get('Name')).toLowerCase() === this.domainNetbios.toLowerCase(),
        );
        if (domain.length !== 1) {
          critical(
            `This server provides multiple domains and '${this.domainNetbios}' isn't one of them.`,
          );
          critical('Available domain(s):');
          for (const d of domains) {
            logError(` * ${d.get('Name')}`);
          }
          critical('Consider using -domain-netbios argument to specify which one you meant.');
          throw new Error();
        } else {
          selectedDomain = String(domain[0].get('Name'));
        }
      } else {
        selectedDomain = String(domainsWithoutBuiltin[0].get('Name'));
      }

      const samrLookupDomainResponse = await hSamrLookupDomainInSamServer(
        dce,
        servHandle as never,
        selectedDomain,
      );
      const domainSID = samrLookupDomainResponse.get('DomainId');

      if (getLevel() === LogLevel.DEBUG) {
        info(`Opening domain ${selectedDomain}...`);
      }
      const samrOpenDomainResponse = await hSamrOpenDomain(
        dce,
        servHandle as never,
        DOMAIN_LOOKUP | DOMAIN_CREATE_USER,
        domainSID as never,
      );
      domainHandle = samrOpenDomainResponse.get('DomainHandle');

      if (this.noAdd || this.delete) {
        let checkForUser: any;
        try {
          checkForUser = await hSamrLookupNamesInDomain(dce, domainHandle as never, [
            this.computerName!,
          ]);
        } catch (e) {
          if ((e as any).error_code === 0xc0000073) {
            throw new Error(
              `Account ${this.computerName} not found in domain ${selectedDomain}!`,
            );
          }
          throw e;
        }

        const userRID = (checkForUser.get('RelativeIds') as any).get('Element')[0];
        const access = this.delete ? DELETE : USER_FORCE_PASSWORD_CHANGE;
        const message = this.delete ? 'delete' : 'set password for';
        try {
          const openUser = await hSamrOpenUser(dce, domainHandle as never, access, userRID);
          userHandle = openUser.get('UserHandle');
        } catch (e) {
          if ((e as any).error_code === 0xc0000022) {
            throw new Error(
              `User ${this.username} doesn't have right to ${message} ${this.computerName}!`,
            );
          }
          throw e;
        }
      } else {
        if (this.computerName !== null) {
          try {
            await hSamrLookupNamesInDomain(dce, domainHandle as never, [this.computerName]);
            throw new Error(
              `Account ${this.computerName} already exists! If you just want to set a password, use -no-add.`,
            );
          } catch (e) {
            if ((e as any).error_code !== undefined && (e as any).error_code !== 0xc0000073) {
              throw e;
            }
            if ((e as any).error_code === undefined) {
              throw e;
            }
          }
        } else {
          let foundUnused = false;
          while (!foundUnused) {
            this.computerName = generateComputerName();
            try {
              await hSamrLookupNamesInDomain(dce, domainHandle as never, [this.computerName]);
            } catch (e) {
              if ((e as any).error_code === 0xc0000073) {
                foundUnused = true;
              } else {
                throw e;
              }
            }
          }
        }

        const createUser = await hSamrCreateUser2InDomain(
          dce,
          domainHandle as never,
          this.computerName!,
          USER_WORKSTATION_TRUST_ACCOUNT,
          USER_FORCE_PASSWORD_CHANGE,
        );
        userHandle = createUser.get('UserHandle');
      }

      if (this.delete) {
        await hSamrDeleteUser(dce, userHandle as never);
        info(`Successfully deleted ${this.computerName}.`);
        userHandle = null;
      } else {
        try {
          await hSamrSetPasswordInternal4New(
            dce,
            userHandle as never,
            this.computerPassword,
          );
        } catch {
          await hSamrSetNTInternal1(dce, userHandle as never, this.computerPassword);
        }
        if (this.noAdd) {
          info(
            `Successfully set password of ${this.computerName} to ${this.computerPassword}.`,
          );
        } else {
          const checkForUser = await hSamrLookupNamesInDomain(dce, domainHandle as never, [
            this.computerName!,
          ]);
          const userRID = (checkForUser.get('RelativeIds') as any).get('Element')[0];
          const openUser = await hSamrOpenUser(
            dce,
            domainHandle as never,
            MAXIMUM_ALLOWED,
            userRID,
          );
          userHandle = openUser.get('UserHandle');
          const req = new SAMPR_USER_INFO_BUFFER();
          req.set('tag', USER_INFORMATION_CLASS.enumValues.UserControlInformation);
          (req.fields['Control'] as any).set(
            'UserAccountControl',
            USER_WORKSTATION_TRUST_ACCOUNT,
          );
          await hSamrSetInformationUser2(dce, userHandle as never, req);
          info(
            `Successfully added machine account ${this.computerName} with password ${this.computerPassword}.`,
          );
        }
      }
    } catch (e) {
      if (getLevel() === LogLevel.DEBUG) console.error(e);
      const msg = (e as Error).message;
      if (msg) critical(msg);
    } finally {
      try {
        if (userHandle !== null) await hSamrCloseHandle(dce, userHandle as never);
        if (domainHandle !== null) await hSamrCloseHandle(dce, domainHandle as never);
        if (servHandle !== null) await hSamrCloseHandle(dce, servHandle as never);
      } catch {
        /* ignore */
      }
      await dce.disconnect();
    }
  }

  // -------------------------------------------------------------------------
  // LDAPS
  // -------------------------------------------------------------------------

  private async ldapComputerExists(
    conn: LDAPConnection,
    computerName: string,
  ): Promise<boolean> {
    const entries = await conn.search({
      searchBase: this.baseDN,
      searchFilter: `(sAMAccountName=${computerName})`,
    });
    return entries.length === 1;
  }

  private async ldapGetComputerDN(
    conn: LDAPConnection,
    computerName: string,
  ): Promise<string | null> {
    const entries = await conn.search({
      searchBase: this.baseDN,
      searchFilter: `(sAMAccountName=${computerName})`,
    });
    if (entries.length > 0) {
      return entries[0]!.objectName;
    }
    return null;
  }

  private async runLdaps(): Promise<void> {
    const targetHost = this.target ?? this.domain;
    const ldapUrl = `ldaps://${targetHost}`;
    const ldapConn = new LDAPConnection({
      url: ldapUrl,
      baseDN: this.baseDN,
      dstIp: this.targetIp ?? undefined,
      ...(this.doKerberos ? { signing: false } : {}),
    });

    try {
      await ldapConn.connect();
      if (this.doKerberos) {
        await ldapConn.kerberosLogin({
          user: this.username,
          password: this.password,
          domain: this.domain,
          lmhash: this.lmhash,
          nthash: this.nthash,
          aesKey: this.aesKey ?? '',
          kdcHost: this.kdcHost,
        });
      } else {
        await ldapConn.login({
          user: this.username,
          password: this.password,
          domain: this.domain,
          lmhash: this.lmhash,
          nthash: this.nthash,
        });
      }

      if (this.noAdd || this.delete) {
        if (!(await this.ldapComputerExists(ldapConn, this.computerName!))) {
          throw new Error(`Account ${this.computerName} not found in ${this.baseDN}!`);
        }

        const computerDn = await this.ldapGetComputerDN(ldapConn, this.computerName!);
        const message = this.delete ? 'delete' : 'set password for';

        try {
          if (this.delete) {
            await ldapConn.delete(computerDn!);
          } else {
            const pwd = Buffer.from(`"${this.computerPassword}"`, 'utf-16le');
            await ldapConn.modify(computerDn!, [
              {
                operation: Operation.replace,
                modification: { type: 'unicodePwd', vals: [pwd] },
              },
            ]);
          }
        } catch (e) {
          if (e instanceof LDAPSessionError) {
            if (e.getErrorCode() === 50) {
              // insufficientAccessRights
              throw new Error(
                `User ${this.username} doesn't have right to ${message} ${this.computerName}!`,
              );
            }
            throw new Error(String(e));
          }
          throw e;
        }

        if (this.noAdd) {
          info(
            `Succesfully set password of ${this.computerName} to ${this.computerPassword}.`,
          );
        } else {
          info(`Succesfully deleted ${this.computerName}.`);
        }
      } else {
        if (this.computerName !== null) {
          if (await this.ldapComputerExists(ldapConn, this.computerName)) {
            throw new Error(
              `Account ${this.computerName} already exists! If you just want to set a password, use -no-add.`,
            );
          }
        } else {
          for (;;) {
            this.computerName = generateComputerName();
            if (!(await this.ldapComputerExists(ldapConn, this.computerName))) {
              break;
            }
          }
        }

        const computerHostname = this.computerName!.slice(0, -1);
        const computerDn = `CN=${computerHostname},${this.computerGroup}`;

        // Default computer SPNs
        const spns = [
          `HOST/${computerHostname}`,
          `HOST/${computerHostname}.${this.domain}`,
          `RestrictedKrbHost/${computerHostname}`,
          `RestrictedKrbHost/${computerHostname}.${this.domain}`,
        ];

        const pwd = Buffer.from(`"${this.computerPassword}"`, 'utf-16le');

        try {
          await ldapConn.add(computerDn, [
            { type: 'objectClass', vals: ['top', 'person', 'organizationalPerson', 'user', 'computer'] },
            { type: 'dnsHostName', vals: [`${computerHostname}.${this.domain}`] },
            { type: 'userAccountControl', vals: ['4096'] }, // 0x1000
            { type: 'servicePrincipalName', vals: spns },
            { type: 'sAMAccountName', vals: [this.computerName!] },
            { type: 'unicodePwd', vals: [pwd] },
          ]);
          info(
            `Successfully added machine account ${this.computerName} with password ${this.computerPassword}.`,
          );
        } catch (e) {
          if (e instanceof LDAPSessionError) {
            if (e.getErrorCode() === 53) {
              // unwillingToPerform
              let errorCode = 0;
              try {
                errorCode = parseInt(e.getErrorString().split(':')[1]!.trim(), 16);
              } catch {
                /* ignore */
              }
              if (errorCode === 0x216d) {
                throw new Error(`User ${this.username} machine quota exceeded!`);
              }
              throw new Error(String(e));
            } else if (e.getErrorCode() === 50) {
              // insufficientAccessRights
              throw new Error(
                `User ${this.username} doesn't have right to create a machine account!`,
              );
            }
            throw new Error(String(e));
          }
          throw e;
        }
      }
      ldapConn.close();
    } catch (e) {
      if (getLevel() === LogLevel.DEBUG) console.error(e);
      critical(String((e as Error).message ?? e));
    }
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function usage(): void {
  console.log(`Adds a computer account to domain

usage: addcomputer [-h] [-domain-netbios NETBIOSNAME]
                   [-computer-name COMPUTER-NAME$] [-computer-pass password]
                   [-no-add] [-delete] [-ts] [-debug]
                   [-method {SAMR,LDAPS}] [-port {139,445,636}]
                   [-baseDN DC=test,DC=local]
                   [-computer-group CN=Computers,DC=test,DC=local]
                   [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                   [-dc-host hostname] [-dc-ip ip]
                   [domain/]username[:password]

positional arguments:
  [domain/]username[:password]   Account used to authenticate to DC.

options:
  -h, --help            show this help message and exit
  -domain-netbios NETBIOSNAME   Domain NetBIOS name. Required if the DC has multiple domains.
  -computer-name COMPUTER-NAME$ Name of computer to add. If omitted, a random DESKTOP-[A-Z0-9]{8} is used.
  -computer-pass password       Password to set to computer. If omitted, a random [A-Za-z0-9]{32} is used.
  -no-add               Don't add a computer, only set password on existing one.
  -delete               Delete an existing computer.
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -method {SAMR,LDAPS}  Method of adding the computer. SAMR works over SMB. LDAPS has certificate requirements.
  -port {139,445,636}   Destination port to connect to. SAMR defaults to 445, LDAPS to 636.

LDAP:
  -baseDN DC=test,DC=local      Set baseDN for LDAP. If omitted, derived from the domain part of the account.
  -computer-group CN=Computers,DC=test,DC=local  Group to which the account will be added.

authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication (KRB5CCNAME ccache)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-host hostname     Hostname of the domain controller to use.
  -dc-ip ip             IP of the domain controller to use.
`);
}

async function main(): Promise<void> {
  const args = normalizeArgs(process.argv.slice(2));

  console.log(BANNER + '\n');

  if (args.length === 0) {
    usage();
    process.exit(1);
  }

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        'domain-netbios': { type: 'string' },
        'computer-name': { type: 'string' },
        'computer-pass': { type: 'string' },
        'no-add': { type: 'boolean', default: false },
        delete: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        method: { type: 'string', default: 'SAMR' },
        port: { type: 'string' },
        baseDN: { type: 'string' },
        'computer-group': { type: 'string' },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-host': { type: 'string' },
        'dc-ip': { type: 'string' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    usage();
    process.exit(1);
  }

  if (values.help || positionals.length < 1) {
    usage();
    process.exit(values.help ? 0 : 1);
  }

  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  const method = (values.method ?? 'SAMR').toUpperCase();
  if (method !== 'SAMR' && method !== 'LDAPS') {
    critical(`Unsupported method ${values.method}`);
    process.exit(1);
  }

  const [domain, username, password] = parseCredentials(positionals[0]!);
  if (domain === '') {
    critical('Domain should be specified!');
    process.exit(1);
  }

  let doKerberos = values.k ?? false;
  if (values.aesKey) doKerberos = true;

  const opts: Options = {
    domainNetbios: values['domain-netbios'] ?? null,
    computerName: values['computer-name'] ?? null,
    computerPass: values['computer-pass'] ?? null,
    noAdd: values['no-add'] ?? false,
    delete: values.delete ?? false,
    method,
    port: values.port ? parseInt(values.port, 10) : null,
    baseDN: values.baseDN ?? null,
    computerGroup: values['computer-group'] ?? null,
    hashes: values.hashes ?? null,
    aesKey: values.aesKey ?? null,
    k: doKerberos,
    dcHost: values['dc-host'] ?? null,
    dcIp: values['dc-ip'] ?? null,
  };

  try {
    const executer = new ADDCOMPUTER(username, password, domain, opts);
    await executer.run();
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) console.error(e);
    console.log(String((e as Error).message ?? e));
  }
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

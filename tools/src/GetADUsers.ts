#!/usr/bin/env node
/**
 * Impacket-js - GetADUsers
 *
 * Queries target domain for Active Directory user accounts via LDAP. Can
 * enumerate all users or filter by a specific sAMAccountName and displays
 * useful attributes such as email, password-last-set, last logon, account
 * status and description.
 *
 * Python implementation by Alberto Solino (@agsolino).
 * TypeScript port.
 */

import { parseArgs } from 'node:util';

import {
  parseTarget,
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
  LDAPConnection,
  LDAPSessionError,
  LDAPSearchError,
  type SearchResultEntry,
  createSimplePagedResultsControl,
} from '@impacket/ldap';

// ---------- UserAccountControl flags ----------
const UAC_ACCOUNTDISABLE = 0x0002;
const UAC_LOCKOUT = 0x0010;
const UAC_PASSWD_NOTREQD = 0x0020;
const UAC_DONT_EXPIRE_PASSWORD = 0x10000;
const UAC_PASSWORD_EXPIRED = 0x800000;

// ---------- LDAP attributes to retrieve ----------
const SEARCH_ATTRIBUTES = [
  'sAMAccountName',
  'displayName',
  'mail',
  'description',
  'lastLogon',
  'lastLogonTimestamp',
  'pwdLastSet',
  'userAccountControl',
  'memberOf',
  'whenCreated',
  'whenChanged',
  'badPwdCount',
  'logonCount',
  'adminCount',
];

// ---------- helpers ----------

/**
 * Convert a Windows FILETIME (100-nanosecond intervals since 1601-01-01) to a
 * human-readable UTC string, or return "<never>" for sentinel values.
 */
function formatWindowsFiletime(raw: string): string {
  const value = BigInt(raw);
  // 0 or the "never expires" sentinel 0x7FFFFFFFFFFFFFFF
  if (value === 0n || value >= 0x7FFFFFFFFFFFFFFFn) {
    return '<never>';
  }
  const epochMs = Number(value / 10000n - 11644473600000n);
  if (epochMs < 0) {
    return '<never>';
  }
  return new Date(epochMs).toISOString().replace('T', ' ').slice(0, 19);
}

/**
 * Decode a subset of userAccountControl flags into a short human label.
 */
function describeAccountStatus(uac: number): string {
  const parts: string[] = [];
  if (uac & UAC_ACCOUNTDISABLE) parts.push('Disabled');
  if (uac & UAC_LOCKOUT) parts.push('Locked');
  if (uac & UAC_PASSWD_NOTREQD) parts.push('PwdNotReqd');
  if (uac & UAC_DONT_EXPIRE_PASSWORD) parts.push('PwdNoExpire');
  if (uac & UAC_PASSWORD_EXPIRED) parts.push('PwdExpired');
  if (parts.length === 0) return 'Enabled';
  return parts.join(', ');
}

/**
 * Print a list of string arrays as a padded, column-aligned table with a
 * header and separator row.
 */
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

interface GetADUsersOptions {
  targetUser: string | null;
  showAll: boolean;
  aesKey: string;
  doKerberos: boolean;
  kdcIp: string | null;
  kdcHost: string | null;
  debug: boolean;
  ts: boolean;
}

class GetADUsers {
  private username: string;
  private password: string;
  private domain: string;
  private lmhash: string;
  private nthash: string;
  private aesKey: string;
  private doKerberos: boolean;
  private kdcHost: string | null;
  private kdcIp: string | null;
  private targetUser: string | null;
  private showAll: boolean;
  private baseDN: string;

  constructor(
    username: string,
    password: string,
    domain: string,
    lmhash: string,
    nthash: string,
    opts: GetADUsersOptions,
  ) {
    this.username = username;
    this.password = password;
    this.domain = domain;
    this.lmhash = lmhash;
    this.nthash = nthash;
    this.aesKey = opts.aesKey;
    this.doKerberos = opts.doKerberos;
    this.kdcIp = opts.kdcIp;
    this.kdcHost = opts.kdcHost;
    this.targetUser = opts.targetUser;
    this.showAll = opts.showAll;

    // Build baseDN from domain: "example.com" -> "dc=example,dc=com"
    this.baseDN = domain
      .split('.')
      .map((p) => `dc=${p}`)
      .join(',');
  }

  /**
   * Build the LDAP search filter for user enumeration.
   *
   *  - Always require objectCategory=person AND objectClass=user
   *  - If a specific user was requested, match sAMAccountName
   *  - Unless -all, exclude disabled accounts via the bit-wise AND OID
   */
  private buildSearchFilter(): string {
    let filter = '(&(objectCategory=person)(objectClass=user)';

    if (this.targetUser !== null) {
      filter += `(sAMAccountName=${this.targetUser})`;
    }

    if (!this.showAll) {
      // Exclude disabled accounts (UAC bit 0x0002)
      filter += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))';
    }

    filter += ')';
    return filter;
  }

  /**
   * Connect to the domain controller via LDAP, authenticate, and return the
   * live connection.
   */
  private async connectLdap(): Promise<LDAPConnection> {
    const target = this.kdcIp ?? this.domain;
    const ldapUrl = `ldap://${target}`;

    logDebug(`Connecting to ${ldapUrl} (baseDN: ${this.baseDN})`);

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

    info(`Successfully authenticated to ${target}`);
    return ldapConn;
  }

  /**
   * Extract a single string value from an LDAP attribute, falling back to
   * `fallback` when the attribute has no values.
   */
  private static attrString(vals: (string | Buffer)[], fallback = ''): string {
    const v = vals[0];
    if (v === undefined) return fallback;
    return Buffer.isBuffer(v) ? v.toString('utf-8') : String(v);
  }

  /**
   * Process search result entries and print them as a formatted table.
   */
  private printUsers(entries: SearchResultEntry[]): void {
    type Row = [string, string, string, string, string, string];
    const rows: Row[] = [];

    for (const entry of entries) {
      let sAMAccountName = '';
      let mail = '';
      let pwdLastSet = '';
      let lastLogon = '';
      let uac = 0;
      let description = '';
      let found = false;

      try {
        for (const attr of entry.attributes) {
          switch (attr.type) {
            case 'sAMAccountName':
              sAMAccountName = GetADUsers.attrString(attr.vals);
              found = true;
              break;
            case 'mail':
              mail = GetADUsers.attrString(attr.vals);
              break;
            case 'pwdLastSet':
              pwdLastSet = formatWindowsFiletime(GetADUsers.attrString(attr.vals, '0'));
              break;
            case 'lastLogon':
              lastLogon = formatWindowsFiletime(GetADUsers.attrString(attr.vals, '0'));
              break;
            case 'lastLogonTimestamp': {
              // Use lastLogonTimestamp only if lastLogon was not already set
              // to a real value (lastLogon is per-DC; lastLogonTimestamp is
              // replicated but less precise).
              const ts = formatWindowsFiletime(GetADUsers.attrString(attr.vals, '0'));
              if (lastLogon === '' || lastLogon === '<never>') {
                lastLogon = ts;
              }
              break;
            }
            case 'userAccountControl':
              uac = parseInt(GetADUsers.attrString(attr.vals, '0'), 10);
              break;
            case 'description':
              description = GetADUsers.attrString(attr.vals);
              break;
            default:
              // Other attributes (displayName, memberOf, etc.) are retrieved
              // for potential future use / debug output but not shown in the
              // default table.
              break;
          }
        }

        if (found) {
          const status = describeAccountStatus(uac);
          rows.push([sAMAccountName, mail, pwdLastSet, lastLogon, status, description]);
        }
      } catch (e) {
        logError(`Skipping entry, cannot process due to error: ${String(e)}`);
      }
    }

    if (rows.length === 0) {
      info('No entries found!');
      return;
    }

    info(`Found ${rows.length} user(s):\n`);
    printTable(rows, ['Name', 'Email', 'PasswordLastSet', 'LastLogon', 'Status', 'Description']);
    console.log('');
  }

  /**
   * Main entry point: connect to LDAP, search for users, print the results.
   */
  async run(): Promise<void> {
    let ldapConn: LDAPConnection;
    try {
      ldapConn = await this.connectLdap();
    } catch (e) {
      if (e instanceof LDAPSessionError) {
        const errStr = e.getErrorString();
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

    const searchFilter = this.buildSearchFilter();
    logDebug(`Search filter: ${searchFilter}`);

    let results: SearchResultEntry[];
    try {
      const pagedControl = createSimplePagedResultsControl(1000);
      results = await ldapConn.search({
        searchFilter,
        attributes: SEARCH_ATTRIBUTES,
        searchControls: [pagedControl],
      });
    } catch (e) {
      if (e instanceof LDAPSearchError && e.getErrorString().includes('sizeLimitExceeded')) {
        logDebug('sizeLimitExceeded exception caught, processing the data received so far');
        results = e.getAnswers();
      } else {
        ldapConn.close();
        throw e;
      }
    }

    logDebug(`Total records returned: ${results.length}`);
    this.printUsers(results);
    ldapConn.close();
  }
}

// ---------- CLI ----------

function usage(): never {
  console.log(`Queries target domain for users data

usage: GetADUsers [-h] [-user username] [-all] [-ts] [-debug]
                  [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                  [-dc-ip ip address] [-dc-host hostname]
                  target

positional arguments:
  target                domain[/username[:password]]

options:
  -h, --help            show this help message and exit
  -user username        Requests data for specific user
  -all                  Return all users, including those with no email
                        addresses and disabled accounts
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
        user: { type: 'string' },
        all: { type: 'boolean', default: false },
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

  // Parse target string: domain/username:password@host
  const [domain, username, password, remoteName] = parseTarget(target);

  if (domain === '') {
    critical('Domain should be specified!');
    process.exit(1);
  }

  // Parse hashes
  let lmhash = '';
  let nthash = '';
  if (values.hashes) {
    const parts = values.hashes.split(':');
    lmhash = parts[0] ?? '';
    nthash = parts[1] ?? '';
  }

  // Kerberos flag
  let doKerberos = values.k ?? false;
  if (values.aesKey) {
    doKerberos = true;
  }

  // Require password unless an alternative auth method is provided
  if (
    password === '' &&
    username !== '' &&
    !values.hashes &&
    !values['no-pass'] &&
    !values.aesKey &&
    !doKerberos
  ) {
    critical(
      'Password required. Use --hashes, --no-pass, -k, or provide password in the target string.',
    );
    process.exit(1);
  }

  const opts: GetADUsersOptions = {
    targetUser: values.user ?? null,
    showAll: values.all ?? false,
    aesKey: values.aesKey ?? '',
    doKerberos,
    kdcIp: values['dc-ip'] ?? null,
    kdcHost: values['dc-host'] ?? null,
    debug: values.debug ?? false,
    ts: values.ts ?? false,
  };

  try {
    const executer = new GetADUsers(
      username,
      password,
      domain,
      lmhash,
      nthash,
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

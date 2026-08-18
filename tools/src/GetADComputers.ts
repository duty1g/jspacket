#!/usr/bin/env node
/**
 * Impacket-js - GetADComputers
 *
 * Queries target domain for Active Directory computer accounts via LDAP and
 * displays useful attributes such as SAM account name, DNS hostname,
 * operating system and OS version. With -resolveIP it additionally performs a
 * DNS A-record lookup against the domain controller to resolve each host.
 *
 * Python implementation by Fowz Masood, inspired by Alberto Solino (@agsolino).
 * TypeScript port.
 */

import { Resolver } from 'node:dns/promises';
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

// ---------- LDAP attributes to retrieve ----------
const SEARCH_ATTRIBUTES = [
  'sAMAccountName',
  'dNSHostName',
  'operatingSystem',
  'operatingSystemVersion',
];

// ---------- helpers ----------

/**
 * Print a list of string arrays as a padded, column-aligned table matching the
 * impacket fixed-column layout, with a header row and a separator row.
 */
function printTable(items: string[][], header: string[], colLen: number[]): void {
  const formatRow = (row: string[]): string =>
    row.map((cell, i) => (cell ?? '').padEnd(colLen[i]!)).join(' ') + ' ';

  console.log(formatRow(header));
  console.log(colLen.map((l) => '-'.repeat(l)).join('  '));
  for (const row of items) {
    console.log(formatRow(row));
  }
}

/**
 * Extract a single string value from an LDAP attribute, falling back to
 * `fallback` when the attribute has no values.
 */
function attrString(vals: (string | Buffer)[], fallback = ''): string {
  const v = vals[0];
  if (v === undefined) return fallback;
  return Buffer.isBuffer(v) ? v.toString('utf-8') : String(v);
}

// ---------- main class ----------

interface GetADComputersOptions {
  requestUser: string | null;
  resolveIP: boolean;
  aesKey: string;
  doKerberos: boolean;
  kdcIp: string | null;
  kdcHost: string | null;
  debug: boolean;
  ts: boolean;
}

class GetADComputers {
  private username: string;
  private password: string;
  private domain: string;
  private lmhash: string;
  private nthash: string;
  private aesKey: string;
  private doKerberos: boolean;
  private kdcHost: string | null;
  private kdcIp: string | null;
  private requestUser: string | null;
  private resolveIP: boolean;
  private baseDN: string;
  private header: string[];
  private colLen: number[];
  private resolver: Resolver | null = null;

  constructor(
    username: string,
    password: string,
    domain: string,
    lmhash: string,
    nthash: string,
    opts: GetADComputersOptions,
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
    this.requestUser = opts.requestUser;
    this.resolveIP = opts.resolveIP;

    // Build baseDN from domain: "example.com" -> "dc=example,dc=com"
    this.baseDN = domain
      .split('.')
      .map((p) => `dc=${p}`)
      .join(',');

    // Fixed-length columns, matching the impacket output layout.
    if (this.resolveIP) {
      this.header = ['SAM AcctName', 'DNS Hostname', 'OS Version', 'OS', 'IPAddress'];
      this.colLen = [15, 35, 15, 35, 20];
    } else {
      this.header = ['SAM AcctName', 'DNS Hostname', 'OS Version', 'OS'];
      this.colLen = [15, 35, 15, 20];
    }
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
   * Resolve an A record for `hostname` using the domain controller as the DNS
   * nameserver (mirroring impacket's dns.resolver against -dc-ip). Returns the
   * resolved IP or a sentinel string when resolution fails.
   */
  private async resolveHost(hostname: string): Promise<string> {
    if (this.resolver === null) {
      this.resolver = new Resolver();
      if (this.kdcIp) {
        this.resolver.setServers([this.kdcIp]);
      }
    }
    try {
      const answers = await this.resolver.resolve4(hostname);
      // impacket keeps the last A record returned
      return answers.length > 0 ? answers[answers.length - 1]! : '<unable to resolve>';
    } catch {
      return '<unable to resolve>';
    }
  }

  /**
   * Extract the relevant attributes from a single search result entry.
   */
  private extractRecord(entry: SearchResultEntry): {
    sAMAccountName: string;
    dNSHostName: string;
    operatingSystem: string;
    operatingSystemVersion: string;
  } {
    let sAMAccountName = '';
    let dNSHostName = '';
    let operatingSystem = '';
    let operatingSystemVersion = '';

    for (const attr of entry.attributes) {
      switch (attr.type) {
        case 'sAMAccountName': {
          const v = attrString(attr.vals);
          // Computer account SAM names end with '$'
          if (v.endsWith('$')) sAMAccountName = v;
          break;
        }
        case 'dNSHostName': {
          const v = attrString(attr.vals);
          if (!v.endsWith('$')) dNSHostName = v;
          break;
        }
        case 'operatingSystem': {
          const v = attrString(attr.vals);
          if (!v.endsWith('$')) operatingSystem = v;
          break;
        }
        case 'operatingSystemVersion': {
          const v = attrString(attr.vals);
          if (!v.endsWith('$')) operatingSystemVersion = v;
          break;
        }
        default:
          break;
      }
    }

    return { sAMAccountName, dNSHostName, operatingSystem, operatingSystemVersion };
  }

  /**
   * Process search result entries and print them as a formatted table.
   */
  private async printComputers(entries: SearchResultEntry[]): Promise<void> {
    const rows: string[][] = [];

    for (const entry of entries) {
      try {
        const rec = this.extractRecord(entry);

        if (this.resolveIP) {
          let ip = '';
          if (rec.dNSHostName !== '') {
            ip = await this.resolveHost(rec.dNSHostName);
          }
          rows.push([
            rec.sAMAccountName,
            rec.dNSHostName,
            rec.operatingSystemVersion,
            rec.operatingSystem,
            ip,
          ]);
        } else {
          rows.push([
            rec.sAMAccountName,
            rec.dNSHostName,
            rec.operatingSystemVersion,
            rec.operatingSystem,
          ]);
        }
      } catch (e) {
        logDebug('Exception');
        logError(`Skipping item, cannot process due to error ${String(e)}`);
      }
    }

    printTable(rows, this.header, this.colLen);
  }

  /**
   * Main entry point: connect to LDAP, search for computers, print the results.
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

    info(`Querying ${this.kdcIp ?? this.domain} for information about domain.`);

    // Building the search filter
    const searchFilter = '(&(objectCategory=computer)(objectClass=computer))';
    logDebug(`Search Filter=${searchFilter}`);

    let results: SearchResultEntry[];
    try {
      const pagedControl = createSimplePagedResultsControl(100);
      results = await ldapConn.search({
        searchFilter,
        attributes: SEARCH_ATTRIBUTES,
        sizeLimit: 0,
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
    await this.printComputers(results);
    ldapConn.close();
  }
}

// ---------- CLI ----------

function usage(): never {
  console.log(`Queries target domain for computer data

usage: GetADComputers [-h] [-user username] [-ts] [-debug] [-resolveIP]
                      [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                      [-dc-ip ip address] [-dc-host hostname]
                      target

positional arguments:
  target                domain[/username[:password]]

options:
  -h, --help            show this help message and exit
  -user username        Requests data for specific user
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -resolveIP            Tries to resolve the IP address of computer objects, by
                        performing the nslookup on the DC.

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
  console.log(BANNER + '\n');
  const args = normalizeArgs(process.argv.slice(2));

  if (args.length === 0) {
    usage();
  }

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        user: { type: 'string' },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        resolveIP: { type: 'boolean', default: false },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
        'dc-host': { type: 'string' },
        all: { type: 'boolean', default: false },
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
  const [domain, username, password] = parseTarget(target);

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

  const opts: GetADComputersOptions = {
    requestUser: values.user ?? null,
    resolveIP: values.resolveIP ?? false,
    aesKey: values.aesKey ?? '',
    doKerberos,
    kdcIp: values['dc-ip'] ?? null,
    kdcHost: values['dc-host'] ?? null,
    debug: values.debug ?? false,
    ts: values.ts ?? false,
  };

  try {
    const executer = new GetADComputers(
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

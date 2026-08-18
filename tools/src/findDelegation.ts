#!/usr/bin/env node
/**
 * Impacket-js - findDelegation
 *
 * Queries target domain for delegation configurations:
 *   - Unconstrained delegation (TRUSTED_FOR_DELEGATION)
 *   - Constrained delegation (msDS-AllowedToDelegateTo)
 *   - Resource-based constrained delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)
 *
 * Python implementation by @agsolino and @simondotsh.
 * TypeScript port.
 */

import { Buffer } from 'node:buffer';
import { parseArgs } from 'node:util';

import {
  parseIdentity,
  init as initLogger,
  initProxy,
  info,
  error as logError,
  debug as logDebug,
  warning,
  critical,
  getLevel,
  LogLevel,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';

import {
  LDAPConnection,
  LDAPSearchError,
  type SearchResultEntry,
  createSimplePagedResultsControl,
  SR_SECURITY_DESCRIPTOR,
  ACL,
  ACE,
  ACCESS_ALLOWED_ACE,
  LDAP_SID,
} from '@impacket/ldap';

// ---------- UserAccountControl flags ----------
const UF_ACCOUNTDISABLE = 0x0002;
const UF_SERVER_TRUST_ACCOUNT = 0x2000;
const UF_TRUSTED_FOR_DELEGATION = 0x80000;
const UF_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000;

// ---------- helpers ----------

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

/**
 * Determine the account type from objectClass attribute values.
 */
function getAccountType(objectClasses: string[]): string {
  const lower = objectClasses.map((c) => c.toLowerCase());
  if (lower.includes('computer')) return 'Computer';
  if (lower.includes('user') || lower.includes('person')) return 'User';
  return 'Unknown';
}

// ---------- types ----------

interface DelegationEntry {
  accountName: string;
  accountType: string;
  delegationType: string;
  delegationRightsTo: string;
}

// ---------- main class ----------

class FindDelegation {
  private username: string;
  private password: string;
  private domain: string;
  private targetDomain: string;
  private lmhash: string;
  private nthash: string;
  private aesKey: string;
  private doKerberos: boolean;
  private kdcHost: string;
  private kdcIp: string | null;
  private baseDN: string;
  private userFilter: string;
  private includeDisabled: boolean;

  constructor(
    username: string,
    password: string,
    userDomain: string,
    targetDomain: string,
    lmhash: string,
    nthash: string,
    opts: {
      aesKey: string;
      doKerberos: boolean;
      kdcHost: string;
      kdcIp: string | null;
      userFilter: string;
      includeDisabled: boolean;
    },
  ) {
    this.username = username;
    this.password = password;
    this.domain = userDomain;
    this.targetDomain = targetDomain;
    this.lmhash = lmhash;
    this.nthash = nthash;
    this.aesKey = opts.aesKey;
    this.doKerberos = opts.doKerberos;
    this.kdcHost = opts.kdcHost;
    this.kdcIp = opts.kdcIp;
    this.userFilter = opts.userFilter;
    this.includeDisabled = opts.includeDisabled;

    this.baseDN = targetDomain
      .split('.')
      .map((p) => `dc=${p}`)
      .join(',');
  }

  /**
   * Connect and authenticate to LDAP.
   */
  private async connectLdap(): Promise<LDAPConnection> {
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
        kdcHost: this.kdcHost || null,
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
    return ldapConn;
  }

  /**
   * Parse a binary security descriptor (msDS-AllowedToActOnBehalfOfOtherIdentity)
   * and extract the SIDs from its DACL.
   */
  private parseSecurityDescriptor(data: Buffer): string[] {
    const sids: string[] = [];
    try {
      const sd = new SR_SECURITY_DESCRIPTOR(data);
      const dacl = sd.get('Dacl');
      if (dacl instanceof ACL) {
        for (const ace of dacl.aces) {
          const aceData = ace.aceData;
          if (aceData instanceof ACCESS_ALLOWED_ACE || hasProperty(aceData, 'Sid')) {
            const sid = (aceData as ACCESS_ALLOWED_ACE).get('Sid');
            if (sid instanceof LDAP_SID) {
              sids.push(sid.formatCanonical());
            }
          }
        }
      }
    } catch (e) {
      logDebug(`Failed to parse security descriptor: ${String(e)}`);
    }
    return sids;
  }

  /**
   * Resolve a SID to an account name via LDAP.
   */
  private async resolveSid(ldapConn: LDAPConnection, sid: string): Promise<string> {
    try {
      // Build a SID binary for the LDAP search
      const sidObj = new LDAP_SID();
      sidObj.fromCanonical(sid);
      const sidBytes = sidObj.getData();

      // Escape the binary SID for the LDAP filter
      let escapedSid = '';
      for (let i = 0; i < sidBytes.length; i++) {
        escapedSid += `\\${sidBytes[i]!.toString(16).padStart(2, '0')}`;
      }

      const searchFilter = `(objectSid=${escapedSid})`;
      const resp = await ldapConn.search({
        searchFilter,
        attributes: ['sAMAccountName'],
      });

      for (const item of resp) {
        for (const attr of item.attributes) {
          if (attr.type === 'sAMAccountName') {
            return attr.vals[0]?.toString() ?? sid;
          }
        }
      }
    } catch (e) {
      logDebug(`Failed to resolve SID ${sid}: ${String(e)}`);
    }
    return sid;
  }

  /**
   * Extract attribute values from a search result entry.
   */
  private extractAttributes(item: SearchResultEntry): {
    sAMAccountName: string;
    objectClasses: string[];
    userAccountControl: number;
    allowedToDelegateTo: string[];
    rbcdDescriptor: Buffer | null;
  } {
    let sAMAccountName = '';
    const objectClasses: string[] = [];
    let userAccountControl = 0;
    const allowedToDelegateTo: string[] = [];
    let rbcdDescriptor: Buffer | null = null;

    for (const attr of item.attributes) {
      switch (attr.type) {
        case 'sAMAccountName':
          sAMAccountName = attr.vals[0]?.toString() ?? '';
          break;
        case 'objectClass':
          for (const val of attr.vals) {
            objectClasses.push(Buffer.isBuffer(val) ? val.toString('utf-8') : String(val));
          }
          break;
        case 'userAccountControl':
          userAccountControl = parseInt(attr.vals[0]?.toString() ?? '0', 10);
          break;
        case 'msDS-AllowedToDelegateTo':
          for (const val of attr.vals) {
            allowedToDelegateTo.push(Buffer.isBuffer(val) ? val.toString('utf-8') : String(val));
          }
          break;
        case 'msDS-AllowedToActOnBehalfOfOtherIdentity': {
          const rawVal = attr.vals[0];
          if (rawVal !== undefined) {
            rbcdDescriptor = Buffer.isBuffer(rawVal) ? rawVal : Buffer.from(String(rawVal));
          }
          break;
        }
      }
    }

    return { sAMAccountName, objectClasses, userAccountControl, allowedToDelegateTo, rbcdDescriptor };
  }

  /**
   * Format and print the delegation results as a table.
   */
  private formatResults(entries: DelegationEntry[]): void {
    if (entries.length === 0) {
      info('No delegation entries found!');
      return;
    }

    const rows = entries.map((e) => [
      e.accountName,
      e.accountType,
      e.delegationType,
      e.delegationRightsTo,
    ]);

    printTable(rows, ['AccountName', 'AccountType', 'DelegationType', 'DelegationRightsTo']);
  }

  /**
   * Perform an LDAP search, handling paged results and size limit errors.
   */
  private async ldapSearch(
    ldapConn: LDAPConnection,
    searchFilter: string,
    attributes: string[],
  ): Promise<SearchResultEntry[]> {
    try {
      const pagedControl = createSimplePagedResultsControl(1000);
      return await ldapConn.search({
        searchFilter,
        attributes,
        searchControls: [pagedControl],
      });
    } catch (e) {
      if (e instanceof LDAPSearchError && e.getErrorString().includes('sizeLimitExceeded')) {
        logDebug('sizeLimitExceeded exception caught, processing the data received');
        return e.getAnswers();
      }
      throw e;
    }
  }

  /**
   * Main entry point: connect, search, and report.
   */
  async run(): Promise<void> {
    const ldapConn = await this.connectLdap();
    info(`Querying ${this.targetDomain} for delegation configurations...`);

    const entries: DelegationEntry[] = [];

    const requestedAttributes = [
      'sAMAccountName',
      'objectClass',
      'userAccountControl',
      'msDS-AllowedToDelegateTo',
      'msDS-AllowedToActOnBehalfOfOtherIdentity',
    ];

    // ---- 1. Unconstrained delegation ----
    // TRUSTED_FOR_DELEGATION (0x80000), not disabled (0x2) unless -disabled, not a domain controller (0x2000)
    const disabledClause = this.includeDisabled
      ? ''
      : '(!(userAccountControl:1.2.840.113556.1.4.803:=2))';

    const unconstrainedFilter =
      '(&' +
      '(userAccountControl:1.2.840.113556.1.4.803:=524288)' +
      disabledClause +
      '(!(userAccountControl:1.2.840.113556.1.4.803:=8192))' +
      ')';

    logDebug(`Searching for unconstrained delegation: ${unconstrainedFilter}`);
    const unconstrainedResp = await this.ldapSearch(ldapConn, unconstrainedFilter, requestedAttributes);
    logDebug(`Unconstrained delegation results: ${unconstrainedResp.length}`);

    for (const item of unconstrainedResp) {
      const attrs = this.extractAttributes(item);
      if (attrs.sAMAccountName === '') continue;

      entries.push({
        accountName: attrs.sAMAccountName,
        accountType: getAccountType(attrs.objectClasses),
        delegationType: 'Unconstrained',
        delegationRightsTo: 'N/A',
      });
    }

    // ---- 2. Constrained delegation ----
    // Has msDS-AllowedToDelegateTo, not disabled unless -disabled
    const constrainedFilter =
      '(&' +
      '(msDS-AllowedToDelegateTo=*)' +
      disabledClause +
      ')';

    logDebug(`Searching for constrained delegation: ${constrainedFilter}`);
    const constrainedResp = await this.ldapSearch(ldapConn, constrainedFilter, requestedAttributes);
    logDebug(`Constrained delegation results: ${constrainedResp.length}`);

    for (const item of constrainedResp) {
      const attrs = this.extractAttributes(item);
      if (attrs.sAMAccountName === '') continue;

      // Check if protocol transition is enabled (TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000)
      const hasProtocolTransition =
        (attrs.userAccountControl & UF_TRUSTED_TO_AUTH_FOR_DELEGATION) !== 0;
      const delegationType = hasProtocolTransition
        ? 'Constrained w/ Protocol Transition'
        : 'Constrained';

      const delegationRightsTo =
        attrs.allowedToDelegateTo.length > 0
          ? attrs.allowedToDelegateTo.join(' / ')
          : 'N/A';

      entries.push({
        accountName: attrs.sAMAccountName,
        accountType: getAccountType(attrs.objectClasses),
        delegationType,
        delegationRightsTo,
      });
    }

    // ---- 3. Resource-based constrained delegation (RBCD) ----
    // Has msDS-AllowedToActOnBehalfOfOtherIdentity, not disabled unless -disabled
    const rbcdFilter =
      '(&' +
      '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' +
      disabledClause +
      ')';

    logDebug(`Searching for RBCD: ${rbcdFilter}`);
    const rbcdResp = await this.ldapSearch(ldapConn, rbcdFilter, requestedAttributes);
    logDebug(`RBCD results: ${rbcdResp.length}`);

    for (const item of rbcdResp) {
      const attrs = this.extractAttributes(item);
      if (attrs.sAMAccountName === '') continue;

      let delegationRightsTo = 'N/A';
      if (attrs.rbcdDescriptor !== null) {
        const sids = this.parseSecurityDescriptor(attrs.rbcdDescriptor);
        if (sids.length > 0) {
          // Resolve SIDs to account names
          const resolvedNames: string[] = [];
          for (const sid of sids) {
            const name = await this.resolveSid(ldapConn, sid);
            resolvedNames.push(name);
          }
          delegationRightsTo = resolvedNames.join(' / ');
        }
      }

      entries.push({
        accountName: attrs.sAMAccountName,
        accountType: getAccountType(attrs.objectClasses),
        delegationType: 'Resource-Based Constrained',
        delegationRightsTo,
      });
    }

    // ---- Filter by user if requested ----
    const filteredEntries = this.userFilter
      ? entries.filter(
          (e) => e.accountName.toLowerCase() === this.userFilter.toLowerCase(),
        )
      : entries;

    // ---- Output ----
    console.log('');
    this.formatResults(filteredEntries);
    console.log('');

    ldapConn.close();
  }
}

/**
 * Type guard: check if a value has a given property (for accessing Sid on ACE sub-types).
 */
function hasProperty<K extends string>(obj: unknown, key: K): obj is Record<K, unknown> {
  return typeof obj === 'object' && obj !== null && key in obj;
}

// ---------- CLI ----------

function usage(): never {
  console.log(`Queries target domain for delegation relationships

usage: findDelegation [-h] [-target-domain target_domain] [-ts] [-debug]
                      [-user USER] [-disabled]
                      [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                      [-aesKey hex key] [-dc-ip ip address]
                      [-dc-host hostname]
                      target

positional arguments:
  target                domain[/username[:password]]

options:
  -h, --help            show this help message and exit
  -target-domain target_domain
                        Domain to query/request if different than the domain
                        of the user. Allows for retrieving delegation info
                        across trusts.
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -user USER            Requests data for specific user
  -disabled             Query disabled users too

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
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        user: { type: 'string' },
        disabled: { type: 'boolean', default: false },
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

  initProxy(values.proxy);

  const target = positionals[0]!;

  initLogger({ ts: values.ts, debug: values.debug });

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

  const targetDomain = values['target-domain'] ?? identity.domain;

  try {
    const finder = new FindDelegation(
      identity.username,
      identity.password,
      identity.domain,
      targetDomain,
      identity.lmhash,
      identity.nthash,
      {
        aesKey: values.aesKey ?? '',
        doKerberos: identity.doKerberos,
        kdcHost: values['dc-host'] ?? '',
        kdcIp: values['dc-ip'] ?? null,
        userFilter: values.user ?? '',
        includeDisabled: values.disabled ?? false,
      },
    );
    await finder.run();
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) {
      console.error(e);
    }
    logError(String(e));
  }
}

main();

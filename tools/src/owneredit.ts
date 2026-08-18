#!/usr/bin/env node
/**
 * jspacket - owneredit
 *
 * Read and modify the Owner (OwnerSid) of an Active Directory object's
 * nTSecurityDescriptor. Uses the SD flags control to touch only the OWNER
 * portion of the security descriptor.
 *
 * Python implementation by Charlie Bromberg (@_nwodtuhs) and
 * Yannick Méheut (@__Meffed). TypeScript port.
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
  SR_SECURITY_DESCRIPTOR,
  LDAP_SID,
  createSDFlagsControl,
  type SearchResultEntry,
  type LdapControl,
} from '@impacket/ldap';

const SD_ATTR = 'nTSecurityDescriptor';
const OWNER_SECURITY_INFORMATION = 0x01;

// A handful of well-known SIDs so read output is friendly even off-domain.
const WELL_KNOWN_SIDS: Record<string, string> = {
  'S-1-5-32-544': 'BUILTIN\\Administrators',
  'S-1-5-18': 'NT AUTHORITY\\SYSTEM',
  'S-1-5-32-512': 'Domain Admins',
  'S-1-5-32-519': 'Enterprise Admins',
};

/** First value of a named attribute on a search entry, as a Buffer. */
function attrBuf(entry: SearchResultEntry, name: string): Buffer | null {
  const attr = entry.attributes.find((a) => a.type.toLowerCase() === name.toLowerCase());
  if (!attr || attr.vals.length === 0) return null;
  const v = attr.vals[0]!;
  return Buffer.isBuffer(v) ? v : Buffer.from(v, 'binary');
}

type Action = 'read' | 'write';

interface Principal {
  sam?: string | null;
  sid?: string | null;
  dn?: string | null;
}

class OwnerEdit {
  private ldapConn: LDAPConnection;
  private baseDN: string;
  private target: Principal;
  private newOwner: Principal;
  private sdControls: LdapControl[];

  private targetEntry: SearchResultEntry | null = null;
  private targetSD: SR_SECURITY_DESCRIPTOR | null = null;
  private newOwnerSID: string | null = null;

  constructor(ldapConn: LDAPConnection, baseDN: string, target: Principal, newOwner: Principal) {
    this.ldapConn = ldapConn;
    this.baseDN = baseDN;
    this.target = target;
    this.newOwner = newOwner;
    this.newOwnerSID = newOwner.sid ?? null;
    // OWNER_SECURITY_INFORMATION only — lets us read/write the owner without SACL rights.
    this.sdControls = [createSDFlagsControl(OWNER_SECURITY_INFORMATION, true)];
  }

  private filterFor(p: Principal): string | null {
    if (p.sam) return `(sAMAccountName=${p.sam})`;
    if (p.sid) return `(objectSid=${p.sid})`;
    if (p.dn) return `(distinguishedName=${p.dn})`;
    return null;
  }

  /** Locate the target and load its security descriptor. Returns false on failure. */
  async load(): Promise<boolean> {
    const filter = this.filterFor(this.target);
    if (filter === null) {
      logError('A target (-target / -target-sid / -target-dn) must be specified.');
      return false;
    }
    const entries = await this.ldapConn.search({
      searchBase: this.baseDN,
      searchFilter: filter,
      attributes: [SD_ATTR],
      searchControls: this.sdControls,
    });
    if (entries.length === 0) {
      logError('Target principal not found in LDAP');
      return false;
    }
    this.targetEntry = entries[0]!;
    const rawSd = attrBuf(this.targetEntry, SD_ATTR);
    if (rawSd === null) {
      logError('Target has no nTSecurityDescriptor (insufficient rights?)');
      return false;
    }
    this.targetSD = new SR_SECURITY_DESCRIPTOR(rawSd);

    // Resolve the new-owner SID if only a name/DN was given.
    if (this.newOwnerSID === null && (this.newOwner.sam || this.newOwner.dn)) {
      const ownerFilter = this.newOwner.sam
        ? `(sAMAccountName=${this.newOwner.sam})`
        : `(distinguishedName=${this.newOwner.dn})`;
      const owner = await this.ldapConn.search({
        searchBase: this.baseDN,
        searchFilter: ownerFilter,
        attributes: ['objectSid'],
      });
      const sidBuf = owner.length > 0 ? attrBuf(owner[0]!, 'objectSid') : null;
      if (sidBuf === null) {
        logError(`New owner SID not found in LDAP (${this.newOwner.sam ?? this.newOwner.dn})`);
        return false;
      }
      this.newOwnerSID = new LDAP_SID(sidBuf).formatCanonical();
      logDebug(`Found new owner SID: ${this.newOwnerSID}`);
    }
    return true;
  }

  private async resolveSID(sid: string): Promise<string> {
    if (WELL_KNOWN_SIDS[sid]) return WELL_KNOWN_SIDS[sid]!;
    const entries = await this.ldapConn.search({
      searchBase: this.baseDN,
      searchFilter: `(objectSid=${sid})`,
      attributes: ['sAMAccountName'],
    });
    const buf = entries.length > 0 ? attrBuf(entries[0]!, 'sAMAccountName') : null;
    return buf ? buf.toString('utf8') : '';
  }

  async read(): Promise<void> {
    const owner = this.targetSD!.get('OwnerSid') as LDAP_SID;
    const sid = owner.formatCanonical();
    info('Current owner information below');
    info(`- SID: ${sid}`);
    info(`- sAMAccountName: ${await this.resolveSID(sid)}`);
    const dnEntries = await this.ldapConn.search({
      searchBase: this.baseDN,
      searchFilter: `(objectSid=${sid})`,
      attributes: ['distinguishedName'],
    });
    const dnBuf = dnEntries.length > 0 ? attrBuf(dnEntries[0]!, 'distinguishedName') : null;
    info(`- distinguishedName: ${dnBuf ? dnBuf.toString('utf8') : ''}`);
  }

  async write(): Promise<void> {
    if (this.newOwnerSID === null) {
      logError('Could not determine the new owner SID.');
      return;
    }
    logDebug('Attempt to modify the OwnerSid');
    const newOwner = new LDAP_SID();
    newOwner.fromCanonical(this.newOwnerSID);
    this.targetSD!.set('OwnerSid', newOwner);

    try {
      await this.ldapConn.modify(
        this.targetEntry!.objectName,
        [
          {
            operation: 2, // replace
            modification: { type: SD_ATTR, vals: [this.targetSD!.getData()] },
          },
        ],
        this.sdControls,
      );
      info('OwnerSid modified successfully!');
    } catch (e) {
      if (e instanceof LDAPSessionError) logError(`Could not modify object: ${e.getErrorString()}`);
      else throw e;
    }
  }
}

// ---------- CLI ----------

function usage(): never {
  console.log(`Read and modify the Owner (OwnerSid) of an Active Directory object.

usage: owneredit [-h] (-target NAME | -target-sid SID | -target-dn DN)
                 [-new-owner NAME | -new-owner-sid SID | -new-owner-dn DN]
                 [-action {read,write}] [-use-ldaps] [-ts] [-debug]
                 [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                 [-dc-ip ip address] [-dc-host hostname]
                 identity

positional arguments:
  identity              domain.local/username[:password]

target:
  -target NAME          Target object sAMAccountName
  -target-sid SID       Target object SID
  -target-dn DN         Target object distinguishedName

owner (attacker-controlled object to set as owner):
  -new-owner NAME       New owner sAMAccountName
  -new-owner-sid SID    New owner SID
  -new-owner-dn DN      New owner distinguishedName

options:
  -h, --help            show this help message and exit
  -action {read,write}  Action on the owner attribute (default: read)
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
        target: { type: 'string' },
        'target-sid': { type: 'string' },
        'target-dn': { type: 'string' },
        'new-owner': { type: 'string' },
        'new-owner-sid': { type: 'string' },
        'new-owner-dn': { type: 'string' },
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

  const target: Principal = {
    sam: values.target ?? null,
    sid: values['target-sid'] ?? null,
    dn: values['target-dn'] ?? null,
  };
  const newOwner: Principal = {
    sam: values['new-owner'] ?? null,
    sid: values['new-owner-sid'] ?? null,
    dn: values['new-owner-dn'] ?? null,
  };

  if (values.help || positionals.length < 1 || !(target.sam || target.sid || target.dn)) usage();

  const action = (values.action ?? 'read') as Action;
  if (action !== 'read' && action !== 'write') {
    critical(`Invalid -action: ${action}`);
    process.exit(1);
  }
  if (action === 'write' && !(newOwner.sam || newOwner.sid || newOwner.dn)) {
    critical('-new-owner, -new-owner-sid, or -new-owner-dn should be specified when using -action write');
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

  logDebug(`Connecting to ${scheme}://${targetHost} (baseDN: ${baseDN})`);

  const ldapConn = new LDAPConnection({
    url: `${scheme}://${targetHost}`,
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

    const editor = new OwnerEdit(ldapConn, baseDN, target, newOwner);
    if (await editor.load()) {
      if (action === 'read') {
        await editor.read();
      } else {
        await editor.read();
        await editor.write();
      }
    }
    ldapConn.close();
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) console.error(e);
    logError(String(e));
  }
}

main();

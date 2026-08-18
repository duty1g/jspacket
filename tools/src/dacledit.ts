#!/usr/bin/env node
/**
 * jspacket - dacledit
 *
 * Read and manage the Discretionary Access Control List (DACL) of an
 * Active Directory object's nTSecurityDescriptor. Supports reading a parsed
 * DACL, adding/removing ACEs granting rights to a principal, and
 * backing up / restoring the whole security descriptor.
 *
 * Python implementation by Charlie Bromberg (@_nwodtuhs), Guillaume Daumas
 * (@BlWasp_) and Lucien Doustaly (@Wlayzz). TypeScript port.
 */

import { Buffer } from 'node:buffer';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
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
  Operation,
  Scope,
  SR_SECURITY_DESCRIPTOR,
  ACL,
  ACE,
  ACCESS_ALLOWED_ACE,
  ACCESS_DENIED_ACE,
  ACCESS_ALLOWED_OBJECT_ACE,
  ACCESS_DENIED_OBJECT_ACE,
  ACCESS_MASK as ACCESS_MASK_STRUCT,
  LDAP_SID,
  createSDFlagsControl,
  type SearchResultEntry,
  type LdapControl,
} from '@impacket/ldap';

import { stringToBin, binToString } from '@impacket/uuid';

const SD_ATTR = 'nTSecurityDescriptor';

// Universal / well-known SIDs (subset, matches impacket WELL_KNOWN_SIDS)
const WELL_KNOWN_SIDS: Record<string, string> = {
  'S-1-0': 'Null Authority',
  'S-1-0-0': 'Nobody',
  'S-1-1': 'World Authority',
  'S-1-1-0': 'Everyone',
  'S-1-2': 'Local Authority',
  'S-1-2-0': 'Local',
  'S-1-2-1': 'Console Logon',
  'S-1-3': 'Creator Authority',
  'S-1-3-0': 'Creator Owner',
  'S-1-3-1': 'Creator Group',
  'S-1-3-2': 'Creator Owner Server',
  'S-1-3-3': 'Creator Group Server',
  'S-1-3-4': 'Owner Rights',
  'S-1-5-80-0': 'All Services',
  'S-1-4': 'Non-unique Authority',
  'S-1-5': 'NT Authority',
  'S-1-5-1': 'Dialup',
  'S-1-5-2': 'Network',
  'S-1-5-3': 'Batch',
  'S-1-5-4': 'Interactive',
  'S-1-5-6': 'Service',
  'S-1-5-7': 'Anonymous',
  'S-1-5-8': 'Proxy',
  'S-1-5-9': 'Enterprise Domain Controllers',
  'S-1-5-10': 'Principal Self',
  'S-1-5-11': 'Authenticated Users',
  'S-1-5-12': 'Restricted Code',
  'S-1-5-13': 'Terminal Server Users',
  'S-1-5-14': 'Remote Interactive Logon',
  'S-1-5-15': 'This Organization',
  'S-1-5-17': 'This Organization',
  'S-1-5-18': 'Local System',
  'S-1-5-19': 'NT Authority',
  'S-1-5-20': 'NT Authority',
  'S-1-5-32-544': 'Administrators',
  'S-1-5-32-545': 'Users',
  'S-1-5-32-546': 'Guests',
  'S-1-5-32-547': 'Power Users',
  'S-1-5-32-548': 'Account Operators',
  'S-1-5-32-549': 'Server Operators',
  'S-1-5-32-550': 'Print Operators',
  'S-1-5-32-551': 'Backup Operators',
  'S-1-5-32-552': 'Replicators',
  'S-1-5-64-10': 'NTLM Authentication',
  'S-1-5-64-14': 'SChannel Authentication',
  'S-1-5-64-21': 'Digest Authority',
  'S-1-5-80': 'NT Service',
  'S-1-5-83-0': 'NT VIRTUAL MACHINE\\Virtual Machines',
  'S-1-16-0': 'Untrusted Mandatory Level',
  'S-1-16-4096': 'Low Mandatory Level',
  'S-1-16-8192': 'Medium Mandatory Level',
  'S-1-16-8448': 'Medium Plus Mandatory Level',
  'S-1-16-12288': 'High Mandatory Level',
  'S-1-16-16384': 'System Mandatory Level',
  'S-1-16-20480': 'Protected Process Mandatory Level',
  'S-1-16-28672': 'Secure Process Mandatory Level',
  'S-1-5-32-554': 'BUILTIN\\Pre-Windows 2000 Compatible Access',
  'S-1-5-32-555': 'BUILTIN\\Remote Desktop Users',
  'S-1-5-32-557': 'BUILTIN\\Incoming Forest Trust Builders',
  'S-1-5-32-556': 'BUILTIN\\Network Configuration Operators',
  'S-1-5-32-558': 'BUILTIN\\Performance Monitor Users',
  'S-1-5-32-559': 'BUILTIN\\Performance Log Users',
  'S-1-5-32-560': 'BUILTIN\\Windows Authorization Access Group',
  'S-1-5-32-561': 'BUILTIN\\Terminal Server License Servers',
  'S-1-5-32-562': 'BUILTIN\\Distributed COM Users',
  'S-1-5-32-569': 'BUILTIN\\Cryptographic Operators',
  'S-1-5-32-573': 'BUILTIN\\Event Log Readers',
  'S-1-5-32-574': 'BUILTIN\\Certificate Service DCOM Access',
  'S-1-5-32-575': 'BUILTIN\\RDS Remote Access Servers',
  'S-1-5-32-576': 'BUILTIN\\RDS Endpoint Servers',
  'S-1-5-32-577': 'BUILTIN\\RDS Management Servers',
  'S-1-5-32-578': 'BUILTIN\\Hyper-V Administrators',
  'S-1-5-32-579': 'BUILTIN\\Access Control Assistance Operators',
  'S-1-5-32-580': 'BUILTIN\\Remote Management Users',
};

// GUIDs identifying extended rights in an ACE (RIGHTS_GUID enum)
const RIGHTS_GUID = {
  WriteMembers: 'bf9679c0-0de6-11d0-a285-00aa003049e2',
  ResetPassword: '00299570-246d-11d0-a768-00aa006e0529',
  DS_Replication_Get_Changes: '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
  DS_Replication_Get_Changes_All: '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
} as const;

// Minimal GUID -> friendly-name map for pretty-printing object-specific ACEs.
// The full impacket schema/extended-rights tables live in @impacket/msada-guids
// (not a declared dependency of tools/), so only the rights this tool writes are
// resolved here; anything else prints as UNKNOWN.
const OBJECT_TYPES_GUID: Record<string, string> = {
  'bf9679c0-0de6-11d0-a285-00aa003049e2': 'Self-Membership',
  '00299570-246d-11d0-a768-00aa006e0529': 'User-Force-Change-Password',
  '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes',
  '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All',
};

// ACE flags (name -> value), for parsing/printing
const ACE_FLAGS: Array<[string, number]> = [
  ['CONTAINER_INHERIT_ACE', ACE.CONTAINER_INHERIT_ACE],
  ['FAILED_ACCESS_ACE_FLAG', ACE.FAILED_ACCESS_ACE_FLAG],
  ['INHERIT_ONLY_ACE', ACE.INHERIT_ONLY_ACE],
  ['INHERITED_ACE', ACE.INHERITED_ACE],
  ['NO_PROPAGATE_INHERIT_ACE', ACE.NO_PROPAGATE_INHERIT_ACE],
  ['OBJECT_INHERIT_ACE', ACE.OBJECT_INHERIT_ACE],
  ['SUCCESSFUL_ACCESS_ACE_FLAG', ACE.SUCCESSFUL_ACCESS_ACE_FLAG],
];

// Object-ACE flags: ObjectType / InheritedObjectType present
const OBJECT_ACE_FLAGS: Array<[string, number]> = [
  ['ACE_OBJECT_TYPE_PRESENT', ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT],
  ['ACE_INHERITED_OBJECT_TYPE_PRESENT', ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT],
];

// Access mask individual rights (name -> value)
const ACCESS_MASK_BITS: Array<[string, number]> = [
  ['GenericRead', 0x80000000],
  ['GenericWrite', 0x40000000],
  ['GenericExecute', 0x20000000],
  ['GenericAll', 0x10000000],
  ['MaximumAllowed', 0x02000000],
  ['AccessSystemSecurity', 0x01000000],
  ['Synchronize', 0x00100000],
  ['WriteOwner', 0x00080000],
  ['WriteDACL', 0x00040000],
  ['ReadControl', 0x00020000],
  ['Delete', 0x00010000],
  ['AllExtendedRights', 0x00000100],
  ['ListObject', 0x00000080],
  ['DeleteTree', 0x00000040],
  ['WriteProperties', 0x00000020],
  ['ReadProperties', 0x00000010],
  ['Self', 0x00000008],
  ['ListChildObjects', 0x00000004],
  ['DeleteChild', 0x00000002],
  ['CreateChild', 0x00000001],
];

// Simple permissions (combinations of extended permissions)
const SIMPLE_PERMISSIONS: Array<[string, number]> = [
  ['FullControl', 0xf01ff],
  ['Modify', 0x0301bf],
  ['ReadAndExecute', 0x0200a9],
  ['ReadAndWrite', 0x02019f],
  ['Read', 0x20094],
  ['Write', 0x200bc],
];

// Object-specific ACE mask flags (used when printing object ACEs)
const ALLOWED_OBJECT_ACE_MASK_FLAGS: Array<[string, number]> = [
  ['ControlAccess', ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS],
  ['CreateChild', ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CREATE_CHILD],
  ['DeleteChild', ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_DELETE_CHILD],
  ['ReadProperty', ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_READ_PROP],
  ['WriteProperty', ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP],
  ['Self', ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_SELF],
];

/** First value of a named attribute on a search entry, as a Buffer. */
function attrBuf(entry: SearchResultEntry, name: string): Buffer | null {
  const attr = entry.attributes.find((a) => a.type.toLowerCase() === name.toLowerCase());
  if (!attr || attr.vals.length === 0) return null;
  const v = attr.vals[0]!;
  return Buffer.isBuffer(v) ? v : Buffer.from(v, 'binary');
}

type AceType = 'allowed' | 'denied';

interface Args {
  target_sam: string | null;
  target_sid: string | null;
  target_dn: string | null;
  principal_sam: string | null;
  principal_sid: string | null;
  principal_dn: string | null;
  ace_type: AceType;
  rights: string;
  rights_guid: string | null;
  filename: string | null;
  inheritance: boolean;
  mask: string | null;
}

class DACLedit {
  private ldapConn: LDAPConnection;
  private baseDN: string;
  private args: Args;
  private daclControls: LdapControl[];
  private forceMask: number | null = null;

  private targetPrincipal: SearchResultEntry | null = null;
  private rawSD: Buffer | null = null;
  private sd: SR_SECURITY_DESCRIPTOR | null = null;
  private principalSID: string | null;
  private filename: string | null;

  constructor(ldapConn: LDAPConnection, baseDN: string, args: Args) {
    this.ldapConn = ldapConn;
    this.baseDN = baseDN;
    this.args = args;
    this.principalSID = args.principal_sid;
    this.filename = args.filename;

    if (args.inheritance) {
      info('NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU');
    }

    // DACL_SECURITY_INFORMATION only
    this.daclControls = [createSDFlagsControl(0x04, true)];

    if (args.mask !== null) {
      if (args.mask.startsWith('0x')) {
        this.forceMask = Number.parseInt(args.mask, 16);
      } else if (args.mask === 'readwrite') {
        this.forceMask =
          ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_READ_PROP +
          ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP;
      } else if (args.mask === 'write') {
        this.forceMask = ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP;
      } else if (args.mask === 'self') {
        this.forceMask = ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_SELF;
      } else if (args.mask === 'allext') {
        this.forceMask = ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS;
      }
    }
  }

  private targetLabel(): string {
    return this.args.target_sid || this.args.target_sam || this.args.target_dn || '';
  }

  /** Load the target's security descriptor and resolve the principal SID. */
  async setup(): Promise<boolean> {
    if (this.args.target_sam || this.args.target_sid || this.args.target_dn) {
      if (!(await this.searchTargetSD())) return false;
      this.rawSD = attrBuf(this.targetPrincipal!, SD_ATTR);
      if (this.rawSD === null) {
        logError('Target has no nTSecurityDescriptor (insufficient rights?)');
        return false;
      }
      this.sd = new SR_SECURITY_DESCRIPTOR(this.rawSD);
    }

    // Resolve principal SID from name/DN when not explicitly given.
    if (
      this.principalSID === null &&
      (this.args.principal_sam !== null || this.args.principal_dn !== null)
    ) {
      const sid = await this.resolvePrincipalSID();
      if (sid === null) return false;
      this.principalSID = sid;
      logDebug(`Found principal SID: ${this.principalSID}`);
    }
    return true;
  }

  private async resolvePrincipalSID(): Promise<string | null> {
    let filter = '';
    let lookedup = '';
    if (this.args.principal_sam !== null) {
      lookedup = this.args.principal_sam;
      filter = `(sAMAccountName=${lookedup})`;
    } else if (this.args.principal_dn !== null) {
      lookedup = this.args.principal_dn;
      filter = `(distinguishedName=${lookedup})`;
    }
    const entries = await this.ldapConn.search({
      searchBase: this.baseDN,
      searchFilter: filter,
      attributes: ['objectSid'],
    });
    const sidBuf = entries.length > 0 ? attrBuf(entries[0]!, 'objectSid') : null;
    if (sidBuf === null) {
      logError(`Principal SID not found in LDAP (${lookedup})`);
      return null;
    }
    return new LDAP_SID(sidBuf).formatCanonical();
  }

  private async searchTargetSD(): Promise<boolean> {
    let filter = '';
    let lookedup = '';
    if (this.args.target_sam !== null) {
      lookedup = this.args.target_sam;
      filter = `(sAMAccountName=${lookedup})`;
    } else if (this.args.target_sid !== null) {
      lookedup = this.args.target_sid;
      filter = `(objectSid=${lookedup})`;
    } else if (this.args.target_dn !== null) {
      lookedup = this.args.target_dn;
      filter = '(objectClass=*)';
    }
    const searchBase = this.args.target_dn !== null ? this.args.target_dn : this.baseDN;
    const scope = this.args.target_dn !== null ? Scope.baseObject : Scope.wholeSubtree;
    const entries = await this.ldapConn.search({
      searchBase,
      searchFilter: filter,
      scope,
      attributes: [SD_ATTR],
      searchControls: this.daclControls,
    });
    if (entries.length === 0) {
      logError(`Target principal not found in LDAP (${lookedup})`);
      return false;
    }
    this.targetPrincipal = entries[0]!;
    logDebug(`Target principal found in LDAP (${lookedup})`);
    return true;
  }

  // ---- SID resolution ----

  private async resolveSID(sid: string): Promise<string> {
    if (WELL_KNOWN_SIDS[sid]) return WELL_KNOWN_SIDS[sid]!;
    const entries = await this.ldapConn.search({
      searchBase: this.baseDN,
      searchFilter: `(objectSid=${sid})`,
      attributes: ['sAMAccountName'],
    });
    const buf = entries.length > 0 ? attrBuf(entries[0]!, 'sAMAccountName') : null;
    if (buf === null) {
      logDebug(`SID not found in LDAP: ${sid}`);
      return '';
    }
    return buf.toString('utf8');
  }

  // ---- Parsing / printing ----

  private currentDacl(): ACL {
    const dacl = this.sd!.get('Dacl');
    if (dacl instanceof ACL) return dacl;
    // Empty DACL fallback
    const acl = new ACL();
    acl.set('AclRevision', 4);
    acl.set('Sbz1', 0);
    acl.set('Sbz2', 0);
    acl.aces = [];
    this.sd!.set('Dacl', acl);
    return acl;
  }

  private parsePerms(fsrIn: number): string[] {
    const perms: string[] = [];
    let fsr = fsrIn >>> 0;
    for (const [name, val] of SIMPLE_PERMISSIONS) {
      if ((fsr & (val >>> 0)) >>> 0 === (val >>> 0)) {
        perms.push(name);
        fsr = (fsr & ~(val >>> 0)) >>> 0;
      }
    }
    for (const [name, val] of ACCESS_MASK_BITS) {
      if ((fsr & (val >>> 0)) >>> 0) perms.push(name);
    }
    return perms;
  }

  private parseACE(ace: ACE): Record<string, string> {
    const typeName = ace.typeName;
    const parsed: Record<string, string> = {};
    const supported = [
      'ACCESS_ALLOWED_ACE',
      'ACCESS_ALLOWED_OBJECT_ACE',
      'ACCESS_DENIED_ACE',
      'ACCESS_DENIED_OBJECT_ACE',
    ];
    if (supported.includes(typeName)) {
      parsed['ACE Type'] = typeName;
      const flags: string[] = [];
      for (const [name, val] of ACE_FLAGS) if (ace.hasFlag(val)) flags.push(name);
      parsed['ACE flags'] = flags.join(', ') || 'None';

      if (typeName === 'ACCESS_ALLOWED_ACE' || typeName === 'ACCESS_DENIED_ACE') {
        const inner = ace.aceData as ACCESS_ALLOWED_ACE;
        const mask = (inner.get('Mask') as ACCESS_MASK_STRUCT).get('Mask') as number;
        parsed['Access mask'] = `${this.parsePerms(mask).join(', ')} (0x${(mask >>> 0).toString(16)})`;
        const sid = (inner.get('Sid') as LDAP_SID).formatCanonical();
        parsed['Trustee (SID)'] = `${WELL_KNOWN_SIDS[sid] ?? 'RESOLVE'} (${sid})`;
      } else {
        const inner = ace.aceData as ACCESS_ALLOWED_OBJECT_ACE;
        const maskStruct = inner.get('Mask') as ACCESS_MASK_STRUCT;
        const maskVal = maskStruct.get('Mask') as number;
        const maskFlags: string[] = [];
        for (const [name, val] of ALLOWED_OBJECT_ACE_MASK_FLAGS)
          if (maskStruct.hasPriv(val)) maskFlags.push(name);
        parsed['Access mask'] = `${maskFlags.join(', ')} (0x${(maskVal >>> 0).toString(16)})`;
        const objFlags: string[] = [];
        for (const [name, val] of OBJECT_ACE_FLAGS) if (inner.hasFlag(val)) objFlags.push(name);
        parsed['Flags'] = objFlags.join(', ') || 'None';
        const objTypeLen = inner.get('ObjectTypeLen') as number;
        if (objTypeLen !== 0) {
          const objType = binToString(inner.get('ObjectType') as Buffer).toLowerCase();
          parsed['Object type (GUID)'] =
            `${OBJECT_TYPES_GUID[objType] ?? 'UNKNOWN'} (${objType})`;
        }
        const inhTypeLen = inner.get('InheritedObjectTypeLen') as number;
        if (inhTypeLen !== 0) {
          const inhType = binToString(inner.get('InheritedObjectType') as Buffer).toLowerCase();
          parsed['Inherited type (GUID)'] =
            `${OBJECT_TYPES_GUID[inhType] ?? 'UNKNOWN'} (${inhType})`;
        }
        const sid = (inner.get('Sid') as LDAP_SID).formatCanonical();
        parsed['Trustee (SID)'] = `${WELL_KNOWN_SIDS[sid] ?? 'RESOLVE'} (${sid})`;
      }
    } else {
      logDebug(`ACE Type (${typeName}) unsupported for parsing yet, feel free to contribute`);
      parsed['ACE type'] = typeName;
      const flags: string[] = [];
      for (const [name, val] of ACE_FLAGS) if (ace.hasFlag(val)) flags.push(name);
      parsed['ACE flags'] = flags.join(', ') || 'None';
      parsed['DEBUG'] = 'ACE type not supported for parsing by dacledit, feel free to contribute';
    }
    return parsed;
  }

  /** Second pass: resolve the "RESOLVE" placeholder SIDs to sAMAccountNames. */
  private async resolveTrustees(parsed: Record<string, string>[]): Promise<void> {
    for (const p of parsed) {
      const t = p['Trustee (SID)'];
      if (t && t.startsWith('RESOLVE (')) {
        const sid = t.slice('RESOLVE ('.length, -1);
        const name = (await this.resolveSID(sid)) || 'UNKNOWN';
        p['Trustee (SID)'] = `${name} (${sid})`;
      }
    }
  }

  private async parseDACL(dacl: ACL): Promise<Record<string, string>[]> {
    info('Parsing DACL');
    const out: Record<string, string>[] = [];
    for (const ace of dacl.aces) out.push(this.parseACE(ace));
    await this.resolveTrustees(out);
    return out;
  }

  private printParsedACE(parsed: Record<string, string>): void {
    for (const key of Object.keys(parsed)) {
      info(`    ${key.padEnd(26)}: ${parsed[key]}`);
    }
  }

  private printParsedDACL(parsed: Record<string, string>[]): void {
    info('Printing parsed DACL');
    if (this.principalSID !== null) info(`Filtering results for SID (${this.principalSID})`);
    let i = 0;
    for (const parsedAce of parsed) {
      let printAce = true;
      if (this.principalSID !== null) {
        const trustee = parsedAce['Trustee (SID)'] ?? '';
        if (!trustee.includes(this.principalSID)) printAce = false;
      }
      if (printAce) {
        info(`  ${`ACE[${i}] info`.padEnd(28)}`);
        this.printParsedACE(parsedAce);
      }
      i += 1;
    }
  }

  // ---- ACE builders ----

  private buildGuidsForRights(): string[] {
    if (this.args.rights_guid !== null) return [this.args.rights_guid];
    if (this.args.rights === 'WriteMembers') return [RIGHTS_GUID.WriteMembers];
    if (this.args.rights === 'ResetPassword') return [RIGHTS_GUID.ResetPassword];
    if (this.args.rights === 'DCSync')
      return [RIGHTS_GUID.DS_Replication_Get_Changes, RIGHTS_GUID.DS_Replication_Get_Changes_All];
    return [];
  }

  private aceFlags(): number {
    return this.args.inheritance
      ? ACE.OBJECT_INHERIT_ACE + ACE.CONTAINER_INHERIT_ACE
      : 0x00;
  }

  private createAce(accessMask: number, sid: string, aceType: AceType): ACE {
    const nace = new ACE();
    let acedata: ACCESS_ALLOWED_ACE;
    if (aceType === 'allowed') {
      nace.set('AceType', ACCESS_ALLOWED_ACE.ACE_TYPE);
      acedata = new ACCESS_ALLOWED_ACE();
    } else {
      nace.set('AceType', ACCESS_DENIED_ACE.ACE_TYPE);
      acedata = new ACCESS_DENIED_ACE();
    }
    nace.set('AceFlags', this.aceFlags());
    const mask = new ACCESS_MASK_STRUCT();
    mask.set('Mask', accessMask >>> 0);
    acedata.set('Mask', mask);
    const s = new LDAP_SID();
    s.fromCanonical(sid);
    acedata.set('Sid', s);
    nace.aceData = acedata;
    nace.set('Ace', acedata);
    logDebug('ACE created.');
    return nace;
  }

  private createObjectAce(
    privguid: string,
    sid: string,
    aceType: AceType,
    forceMask: number | null,
  ): ACE {
    const nace = new ACE();
    let acedata: ACCESS_ALLOWED_OBJECT_ACE;
    if (aceType === 'allowed') {
      nace.set('AceType', ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE);
      acedata = new ACCESS_ALLOWED_OBJECT_ACE();
    } else {
      nace.set('AceType', ACCESS_DENIED_OBJECT_ACE.ACE_TYPE);
      acedata = new ACCESS_DENIED_OBJECT_ACE();
    }
    nace.set('AceFlags', this.aceFlags());
    const mask = new ACCESS_MASK_STRUCT();
    if (forceMask !== null) {
      mask.set('Mask', forceMask >>> 0);
    } else if (privguid === RIGHTS_GUID.WriteMembers) {
      mask.set(
        'Mask',
        ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_READ_PROP +
          ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP,
      );
    } else {
      mask.set('Mask', ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS);
    }
    acedata.set('Mask', mask);
    acedata.set('ObjectType', stringToBin(privguid));
    acedata.set('InheritedObjectType', Buffer.alloc(0));
    const s = new LDAP_SID();
    s.fromCanonical(sid);
    acedata.set('Sid', s);
    acedata.set('Flags', ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT);
    nace.aceData = acedata;
    nace.set('Ace', acedata);
    logDebug('Object-specific ACE created.');
    return nace;
  }

  // ---- Actions ----

  async read(): Promise<void> {
    // Late principal SID resolution for filtering (matches impacket printparsedDACL)
    if (
      this.principalSID === null &&
      (this.args.principal_sam !== null || this.args.principal_dn !== null)
    ) {
      this.principalSID = await this.resolvePrincipalSID();
    }
    const parsed = await this.parseDACL(this.currentDacl());
    this.printParsedDACL(parsed);
  }

  private newAcesForAction(): ACE[] {
    const aces: ACE[] = [];
    if (this.args.rights === 'FullControl' && this.args.rights_guid === null) {
      logDebug(`Appending ACE (${this.principalSID} --(FullControl)--> ${this.targetLabel()})`);
      aces.push(this.createAce(0xf01ff, this.principalSID!, this.args.ace_type));
    } else if (this.args.rights === 'Custom' && this.forceMask !== null) {
      logDebug(`Appending ACE (${this.principalSID} --(Custom)--> ${this.targetLabel()})`);
      aces.push(this.createAce(this.forceMask, this.principalSID!, this.args.ace_type));
    } else {
      for (const guid of this.buildGuidsForRights()) {
        logDebug(`Appending ACE (${this.principalSID} --(${guid})--> ${this.targetLabel()})`);
        aces.push(this.createObjectAce(guid, this.principalSID!, this.args.ace_type, this.forceMask));
      }
    }
    return aces;
  }

  async write(): Promise<void> {
    for (const ace of this.newAcesForAction()) this.currentDacl().aces.push(ace);
    this.backup();
    await this.modifySecDescForDN(this.targetPrincipal!.objectName, this.sd!);
  }

  private aceInnerFields(ace: ACE): {
    mask: number;
    rev: number;
    subCount: number;
    subAuth: Buffer;
    idAuth: Buffer;
    objectType: Buffer | null;
  } {
    const inner = ace.aceData as ACCESS_ALLOWED_ACE | ACCESS_ALLOWED_OBJECT_ACE;
    const mask = (inner.get('Mask') as ACCESS_MASK_STRUCT).get('Mask') as number;
    const sid = inner.get('Sid') as LDAP_SID;
    const idAuthStruct = sid.get('IdentifierAuthority') as { get(k: string): Buffer };
    let objectType: Buffer | null = null;
    if (inner instanceof ACCESS_ALLOWED_OBJECT_ACE) {
      const ot = inner.get('ObjectType');
      objectType = Buffer.isBuffer(ot) ? ot : null;
    }
    return {
      mask: mask >>> 0,
      rev: sid.get('Revision') as number,
      subCount: sid.get('SubAuthorityCount') as number,
      subAuth: sid.get('SubAuthority') as Buffer,
      idAuth: idAuthStruct.get('Value'),
      objectType,
    };
  }

  async remove(): Promise<void> {
    const compareAces = this.newAcesForAction();
    const newDacl: ACE[] = [];
    let daclMustBeReplaced = false;
    const dacl = this.currentDacl();

    for (const ace of dacl.aces) {
      let aceMustBeRemoved = false;
      const a = this.aceInnerFields(ace);
      for (const cmp of compareAces) {
        const c = this.aceInnerFields(cmp);
        if (
          (ace.get('AceType') as number) === (cmp.get('AceType') as number) &&
          (ace.get('AceFlags') as number) === (cmp.get('AceFlags') as number) &&
          a.mask === c.mask &&
          a.rev === c.rev &&
          a.subCount === c.subCount &&
          a.subAuth.equals(c.subAuth) &&
          a.idAuth.equals(c.idAuth)
        ) {
          if (a.objectType !== null && c.objectType !== null) {
            if (a.objectType.equals(c.objectType)) {
              aceMustBeRemoved = true;
              daclMustBeReplaced = true;
            }
          } else {
            aceMustBeRemoved = true;
            daclMustBeReplaced = true;
          }
        }
      }
      if (!aceMustBeRemoved) {
        newDacl.push(ace);
      } else if (getLevel() === LogLevel.DEBUG) {
        logDebug('This ACE will be removed');
        this.printParsedACE(this.parseACE(ace));
      }
    }

    if (daclMustBeReplaced) {
      dacl.aces = newDacl;
      this.backup();
      await this.modifySecDescForDN(this.targetPrincipal!.objectName, this.sd!);
    } else {
      info('Nothing to remove...');
    }
  }

  backup(): void {
    const backup = {
      sd: (this.rawSD ?? Buffer.alloc(0)).toString('hex'),
      dn: this.targetPrincipal ? this.targetPrincipal.objectName : (this.args.target_dn ?? ''),
    };
    let filename = this.filename;
    if (!filename) {
      filename = `dacledit-${timestamp()}.bak`;
    } else if (existsSync(filename)) {
      info(
        `File ${filename} already exists, I'm refusing to overwrite it, setting another filename`,
      );
      filename = `dacledit-${timestamp()}.bak`;
    }
    writeFileSync(filename, JSON.stringify(backup), 'utf-8');
    this.filename = filename;
    info(`DACL backed up to ${filename}`);
  }

  async restore(): Promise<void> {
    if (!this.filename) {
      logError('-file is required when using -action restore');
      return;
    }
    const restore = JSON.parse(readFileSync(this.filename, 'utf-8')) as { sd: string; dn: string };
    if (!('sd' in restore) || !('dn' in restore)) {
      logError('Invalid backup file (missing sd/dn)');
      return;
    }
    const newRawSD = Buffer.from(restore.sd, 'hex');
    const newSD = new SR_SECURITY_DESCRIPTOR(newRawSD);

    this.args.target_dn = restore.dn;
    this.args.target_sam = null;
    this.args.target_sid = null;
    if (!(await this.searchTargetSD())) return;
    this.rawSD = attrBuf(this.targetPrincipal!, SD_ATTR);
    this.sd = new SR_SECURITY_DESCRIPTOR(this.rawSD ?? Buffer.alloc(0));

    this.backup();
    info('Restoring DACL');
    await this.modifySecDescForDN(restore.dn, newSD);
  }

  private async modifySecDescForDN(dn: string, secDesc: SR_SECURITY_DESCRIPTOR): Promise<void> {
    const data = secDesc.getData();
    logDebug('Attempts to modify the Security Descriptor.');
    try {
      await this.ldapConn.modify(
        dn,
        [{ operation: Operation.replace, modification: { type: SD_ATTR, vals: [data] } }],
        this.daclControls,
      );
      info('DACL modified successfully!');
    } catch (e) {
      if (e instanceof LDAPSessionError) logError(`Could not modify object: ${e.getErrorString()}`);
      else throw e;
    }
  }
}

function timestamp(): string {
  const d = new Date();
  const p = (n: number, l = 2) => n.toString().padStart(l, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

// ---------- CLI ----------

function usage(): never {
  console.log(`Editor for a principal's DACL.

usage: dacledit [-h] [-use-ldaps] [-ts] [-debug]
                [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                [-dc-ip ip address] [-dc-host hostname]
                [-principal NAME] [-principal-sid SID] [-principal-dn DN]
                [-target NAME] [-target-sid SID] [-target-dn DN]
                [-action {read,write,remove,backup,restore}] [-file FILE]
                [-ace-type {allowed,denied}]
                [-rights {FullControl,ResetPassword,WriteMembers,DCSync,Custom}]
                [-rights-guid RIGHTS_GUID] [-mask MASK] [-inheritance]
                identity

positional arguments:
  identity              domain.local/username[:password]

options:
  -h, --help            show this help message and exit
  -use-ldaps            Use LDAPS instead of LDAP
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

authentication & connection:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication (KRB5CCNAME ccache)
  -aesKey hex key       AES key for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller / KDC
  -dc-host hostname     Hostname of the domain controller to use

principal (attacker-controlled object referenced in the ACE / filter):
  -principal NAME       sAMAccountName
  -principal-sid SID    Security IDentifier
  -principal-dn DN      Distinguished Name

target (principal object to read/edit the DACL of):
  -target NAME          sAMAccountName
  -target-sid SID       Security IDentifier
  -target-dn DN         Distinguished Name

dacl editor:
  -action {read,write,remove,backup,restore}
                        Action to operate on the DACL (default: read)
  -file FILE            Filename/path (optional for -action backup, required for -restore)
  -ace-type {allowed,denied}
                        The ACE Type to add/remove (default: allowed)
  -rights {FullControl,ResetPassword,WriteMembers,DCSync,Custom}
                        Rights to write/remove in the target DACL (default: FullControl)
  -rights-guid GUID     Manual GUID representing the right to write/remove
  -mask MASK            Force access mask: readwrite, write, self, allext, 0xXXXXX
  -inheritance          Enable inheritance (CONTAINER_INHERIT_ACE + OBJECT_INHERIT_ACE)
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
        'use-ldaps': { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
        'dc-host': { type: 'string' },
        principal: { type: 'string' },
        'principal-sid': { type: 'string' },
        'principal-dn': { type: 'string' },
        target: { type: 'string' },
        'target-sid': { type: 'string' },
        'target-dn': { type: 'string' },
        action: { type: 'string', default: 'read' },
        file: { type: 'string' },
        'ace-type': { type: 'string', default: 'allowed' },
        rights: { type: 'string', default: 'FullControl' },
        'rights-guid': { type: 'string' },
        mask: { type: 'string' },
        inheritance: { type: 'boolean', default: false },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    usage();
  }

  if (values.help || positionals.length < 1) usage();

  initProxy(values.proxy);

  const action = (values.action ?? 'read') as string;
  const validActions = ['read', 'write', 'remove', 'backup', 'restore'];
  if (!validActions.includes(action)) {
    critical(`Invalid -action: ${action}`);
    process.exit(1);
  }

  const aceType = (values['ace-type'] ?? 'allowed') as string;
  if (aceType !== 'allowed' && aceType !== 'denied') {
    critical(`Invalid -ace-type: ${aceType}`);
    process.exit(1);
  }

  initLogger({ ts: values.ts, debug: values.debug });

  if (
    action === 'write' &&
    values.principal == null &&
    values['principal-sid'] == null &&
    values['principal-dn'] == null
  ) {
    critical('-principal, -principal-sid, or -principal-dn should be specified when using -action write');
    process.exit(1);
  }
  if (action === 'restore' && !values.file) {
    critical('-file is required when using -action restore');
    process.exit(1);
  }

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

  const args: Args = {
    target_sam: values.target ?? null,
    target_sid: values['target-sid'] ?? null,
    target_dn: values['target-dn'] ?? null,
    principal_sam: values.principal ?? null,
    principal_sid: values['principal-sid'] ?? null,
    principal_dn: values['principal-dn'] ?? null,
    ace_type: aceType,
    rights: values.rights ?? 'FullControl',
    rights_guid: values['rights-guid'] ?? null,
    filename: values.file ?? null,
    inheritance: values.inheritance ?? false,
    mask: values.mask ?? null,
  };

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

    const dacledit = new DACLedit(ldapConn, baseDN, args);
    if (await dacledit.setup()) {
      if (action === 'read') await dacledit.read();
      else if (action === 'write') await dacledit.write();
      else if (action === 'remove') await dacledit.remove();
      else if (action === 'backup') dacledit.backup();
      else if (action === 'restore') await dacledit.restore();
    }
    ldapConn.close();
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) console.error(e);
    logError(String(e));
  }
}

main();

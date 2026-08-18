#!/usr/bin/env node
/**
 * jspacket - net
 *
 * Impacket alternative for the Windows net.exe commandline utility. Thanks to
 * the RPC protocol (MS-SAMR / MS-LSAT), this tool makes net.exe functionality
 * available against a remote computer.
 *
 *   e.g:
 *     net Administrator:password@targetMachine localgroup
 *     net Administrator:password@targetMachine user
 *     net Administrator:password@targetMachine group
 *     net Administrator:password@targetMachine computer
 *     net Administrator:password@targetMachine localgroup -name Administrators
 *     net Administrator:password@targetMachine user -name Administrator
 *     net Administrator:password@targetMachine group -name "Domain Admins"
 *     net Administrator:password@targetMachine computer -name DC$
 *     net Administrator:password@targetMachine group -name "Domain Admins" -join EvilUs3r
 *     net Administrator:password@targetMachine user -enable EvilUs3r
 *     net Administrator:password@targetMachine user -disable EvilUs3r
 *
 * Author (original impacket net.py):
 *   Alex Romero (@NtAlexio2)
 *
 * TypeScript port.
 *
 * Reference for: [MS-SAMR]
 */

import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';

import {
  parseTarget,
  init as initLogger,
  initProxy,
  error as logError,
  getLevel,
  LogLevel,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';

import {
  DCERPCTransportFactory,
  DCERPCException,
  MSRPC_UUID_SAMR,
  MSRPC_UUID_LSAT,
  MAXIMUM_ALLOWED,
  // SAMR helpers
  hSamrConnect,
  hSamrEnumerateDomainsInSamServer,
  hSamrLookupDomainInSamServer,
  hSamrOpenDomain,
  hSamrOpenUser,
  hSamrOpenGroup,
  hSamrOpenAlias,
  hSamrCloseHandle,
  hSamrLookupNamesInDomain,
  hSamrLookupIdsInDomain,
  hSamrEnumerateUsersInDomain,
  hSamrEnumerateGroupsInDomain,
  hSamrEnumerateAliasesInDomain,
  hSamrQueryInformationUser2,
  hSamrSetInformationUser2,
  hSamrGetGroupsForUser,
  hSamrGetAliasMembership,
  hSamrGetMembersInGroup,
  hSamrGetMembersInAlias,
  hSamrRidToSid,
  hSamrAddMemberToGroup,
  hSamrRemoveMemberFromGroup,
  hSamrAddMemberToAlias,
  hSamrRemoveMemberFromAlias,
  hSamrCreateUser2InDomain,
  hSamrDeleteUser,
  hSamrSetNTInternal1,
  // LSA helpers
  hLsarOpenPolicy2,
  hLsarClose,
  hLsarLookupNames3,
  hLsarLookupSids2,
  // Constants
  USER_INFORMATION_CLASS,
  USER_NORMAL_ACCOUNT,
  USER_WORKSTATION_TRUST_ACCOUNT,
  USER_SERVER_TRUST_ACCOUNT,
  USER_ALL_ACCESS,
  USER_ACCOUNT_DISABLED,
  USER_PASSWORD_NOT_REQUIRED,
  UF_PASSWD_CANT_CHANGE,
  SE_GROUP_ENABLED_BY_DEFAULT,
  // Structures
  SAMPR_USER_INFO_BUFFER,
  SAMPR_PSID_ARRAY,
  PSAMPR_SID_INFORMATION,
} from '@impacket/dcerpc';

import { SMBConnection } from '@impacket/smb-connection';
import { STATUS_MORE_ENTRIES } from '@impacket/nt-errors';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/* eslint-disable @typescript-eslint/no-explicit-any */
type Any = any;

/** Chained NDR getter that keeps the value loosely typed. */
function g(obj: Any, ...keys: string[]): Any {
  let cur: Any = obj;
  for (const k of keys) cur = cur.get(k);
  return cur;
}

/**
 * Await an RPC that may complete with STATUS_MORE_ENTRIES. Impacket's net.py
 * treats STATUS_MORE_ENTRIES on the enumeration calls as a benign terminal
 * status; the (partial) packet is still returned to the caller.
 */
async function callAllowMoreEntries(p: Promise<Any>): Promise<Any> {
  try {
    return await p;
  } catch (e) {
    if (e instanceof DCERPCException) {
      const code = (e as Any).error_code;
      if (code === STATUS_MORE_ENTRIES) {
        return (e as Any).packet ?? (typeof (e as Any).getPacket === 'function' ? (e as Any).getPacket() : null);
      }
    }
    if (String(e).includes('STATUS_MORE_ENTRIES')) {
      return null;
    }
    throw e;
  }
}

function getUnixTime(t: number): number {
  t -= 116444736000000000;
  t /= 10000000;
  return t;
}

function b2s(b: boolean): string {
  return b ? 'Yes' : 'No';
}

function pad2(n: number): string {
  return String(n).padStart(2, '0');
}

function getTimeString(largeInteger: Any): string {
  const high = Number(largeInteger.get('HighPart'));
  const low = Number(largeInteger.get('LowPart')) >>> 0;
  const time = BigInt(high) * 0x100000000n + BigInt(low);
  if (time === 0n || time === 0x7fffffffffffffffn) {
    return 'Never';
  }
  const d = new Date(getUnixTime(Number(time)) * 1000);
  // Mirror impacket's "%m/%d/%Y %H:%M:%S %p"
  const ampm = d.getHours() >= 12 ? 'PM' : 'AM';
  return (
    `${pad2(d.getMonth() + 1)}/${pad2(d.getDate())}/${d.getFullYear()} ` +
    `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())} ${ampm}`
  );
}

function formatLogonHours(raw: Any): string {
  let bytes: number[];
  if (Buffer.isBuffer(raw)) {
    bytes = Array.from(raw);
  } else if (Array.isArray(raw)) {
    bytes = raw.map((x) => Number(x) & 0xff);
  } else {
    return 'All';
  }
  const hex = bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
  if (hex === 'f'.repeat(42)) {
    return 'All';
  }
  return hex;
}

function ljust(s: string, width: number): string {
  return s.length >= width ? s : s + ' '.repeat(width - s.length);
}

function ustr(v: Any): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'string') return v;
  if (typeof v.get === 'function') {
    try {
      const d = v.get('Data');
      if (typeof d === 'string') return d;
    } catch {
      /* ignore */
    }
  }
  return String(v);
}

// ---------------------------------------------------------------------------
// LsaTranslator
// ---------------------------------------------------------------------------

class LsaTranslator {
  private smbConnection: SMBConnection;
  private stringBinding = 'ncacn_np:445[\\pipe\\lsarpc]';
  private dce: Any = null;

  constructor(smbConnection: SMBConnection) {
    this.smbConnection = smbConnection;
  }

  async connect(): Promise<void> {
    const rpc = DCERPCTransportFactory(this.stringBinding);
    if ('setSmbConnection' in rpc) {
      (rpc as Any).setSmbConnection(this.smbConnection);
    }
    this.dce = rpc.getDceRpc();
    await this.dce.connect();
    await this.dce.bind(MSRPC_UUID_LSAT);
  }

  async lookupName(name: string): Promise<Any> {
    const policyHandle = g(await hLsarOpenPolicy2(this.dce), 'PolicyHandle');
    const resp = await hLsarLookupNames3(this.dce, policyHandle, [name]);
    await hLsarClose(this.dce, policyHandle);
    return g(resp, 'TranslatedSids', 'Sids')[0].get('Sid');
  }

  async lookupSids(sidList: string[]): Promise<Any[]> {
    const policyHandle = g(await hLsarOpenPolicy2(this.dce), 'PolicyHandle');
    const resp = await hLsarLookupSids2(this.dce, policyHandle, sidList);
    await hLsarClose(this.dce, policyHandle);
    return g(resp, 'TranslatedNames', 'Names');
  }
}

// ---------------------------------------------------------------------------
// SamrObject
// ---------------------------------------------------------------------------

class SamrObject {
  protected smbConnection: SMBConnection;
  private stringBinding = 'ncacn_np:445[\\pipe\\samr]';
  protected dce: Any = null;
  protected domainHandle: Any = null;
  private translator: LsaTranslator | null = null;

  constructor(smbConnection: SMBConnection) {
    this.smbConnection = smbConnection;
  }

  async connect(): Promise<void> {
    const rpc = DCERPCTransportFactory(this.stringBinding);
    if ('setSmbConnection' in rpc) {
      (rpc as Any).setSmbConnection(this.smbConnection);
    }
    this.dce = rpc.getDceRpc();
    await this.dce.connect();
    await this.dce.bind(MSRPC_UUID_SAMR);
  }

  protected async getUserSid(username: string): Promise<Any> {
    if (this.translator === null) {
      this.translator = new LsaTranslator(this.smbConnection);
      await this.translator.connect();
    }
    return this.translator.lookupName(username);
  }

  protected async resolveSid(sidList: string[]): Promise<Any[]> {
    if (this.translator === null) {
      this.translator = new LsaTranslator(this.smbConnection);
      await this.translator.connect();
    }
    return this.translator.lookupSids(sidList);
  }

  protected async getObjectRid(domainHandle: Any, objectName: string): Promise<number> {
    const response = await hSamrLookupNamesInDomain(this.dce, domainHandle, [objectName]);
    return g(response, 'RelativeIds', 'Element')[0] as number;
  }

  protected async getUserHandle(domainHandle: Any, username: string): Promise<Any> {
    const userRid = await this.getObjectRid(domainHandle, username);
    const response = await hSamrOpenUser(this.dce, domainHandle, MAXIMUM_ALLOWED, userRid);
    return g(response, 'UserHandle');
  }

  protected async getGroupHandle(domainHandle: Any, groupName: string): Promise<Any> {
    const groupRid = await this.getObjectRid(domainHandle, groupName);
    const response = await hSamrOpenGroup(this.dce, domainHandle, MAXIMUM_ALLOWED, groupRid);
    return g(response, 'GroupHandle');
  }

  protected async getAliasHandle(domainHandle: Any, aliasName: string): Promise<Any> {
    const aliasRid = await this.getObjectRid(domainHandle, aliasName);
    const response = await hSamrOpenAlias(this.dce, domainHandle, MAXIMUM_ALLOWED, aliasRid);
    return g(response, 'AliasHandle');
  }

  protected async openDomain(builtin = false): Promise<Any> {
    if (this.domainHandle === null) {
      this.domainHandle = await this.getDomainHandle(builtin);
    }
    return this.domainHandle;
  }

  protected async closeDomain(): Promise<void> {
    if (this.domainHandle !== null) {
      await hSamrCloseHandle(this.dce, this.domainHandle);
      this.domainHandle = null;
    }
  }

  private async getDomainHandle(builtin = false): Promise<Any> {
    const index = builtin ? 1 : 0;
    const serverHandle = g(await hSamrConnect(this.dce), 'ServerHandle');
    const domainName = g(await hSamrEnumerateDomainsInSamServer(this.dce, serverHandle), 'Buffer', 'Buffer')[
      index
    ].get('Name');
    const domainId = g(await hSamrLookupDomainInSamServer(this.dce, serverHandle, domainName), 'DomainId');
    const domainHandle = g(
      await hSamrOpenDomain(this.dce, serverHandle, MAXIMUM_ALLOWED, domainId),
      'DomainHandle',
    );
    return domainHandle;
  }
}

// ---------------------------------------------------------------------------
// User
// ---------------------------------------------------------------------------

interface UserQueryResult {
  info: Any;
  globalGroups: string[];
  localGroups: string[];
}

class User extends SamrObject {
  protected createAccountType = USER_NORMAL_ACCOUNT;
  protected enumAccountType = USER_NORMAL_ACCOUNT;

  async enumerate(): Promise<Any[]> {
    const domainHandle = await this.openDomain();
    try {
      const response = await callAllowMoreEntries(
        hSamrEnumerateUsersInDomain(this.dce, domainHandle, this.enumAccountType),
      );
      if (response === null) return [];
      return g(response, 'Buffer', 'Buffer') as Any[];
    } finally {
      await this.closeDomain();
    }
  }

  async query(name: string): Promise<UserQueryResult | null> {
    let domainHandle = await this.openDomain(false);
    try {
      const userHandle = await this.getUserHandle(domainHandle, name);
      const info = g(
        await hSamrQueryInformationUser2(
          this.dce,
          userHandle,
          USER_INFORMATION_CLASS.enumValues.UserAllInformation!,
        ),
        'Buffer',
        'All',
      );

      // Get groups that user is member of
      const groups = g(await hSamrGetGroupsForUser(this.dce, userHandle), 'Groups', 'Groups') as Any[];
      const groupIdList = groups.map((grp) => grp.get('RelativeId') as number);

      const sidArray = new SAMPR_PSID_ARRAY();
      const sidsPtr = sidArray.fields['Sids'] as Any;
      const sidsArr = sidsPtr.fields['Data'] as Any;
      const sidItems = sidsArr.fields['Data'] as Any[];

      for (const gid of groupIdList) {
        const groupHandle = g(await hSamrOpenGroup(this.dce, domainHandle, MAXIMUM_ALLOWED, gid), 'GroupHandle');
        const groupSid = g(await hSamrRidToSid(this.dce, groupHandle, gid), 'Sid');
        const si = new PSAMPR_SID_INFORMATION();
        (si.fields['Data'] as Any).set('SidPointer', groupSid);
        sidItems.push(si);
        await hSamrCloseHandle(this.dce, groupHandle);
      }

      const globalLookupIds = await hSamrLookupIdsInDomain(this.dce, domainHandle, groupIdList);
      const globalGroups = (g(globalLookupIds, 'Names', 'Element') as Any[]).map((a) => ustr(a));

      await this.closeDomain();
      domainHandle = await this.openDomain(true);

      const aliasMembership = await hSamrGetAliasMembership(this.dce, domainHandle, sidArray);
      const aliasIdList = (g(aliasMembership, 'Membership', 'Element') as Any[]).map((a) => Number(g(a, 'Data')));

      const localLookupIds = await hSamrLookupIdsInDomain(this.dce, domainHandle, aliasIdList);
      const localGroups = (g(localLookupIds, 'Names', 'Element') as Any[]).map((a) => ustr(a));

      return { info, globalGroups, localGroups };
    } finally {
      await this.closeDomain();
    }
  }

  async create(name: string, newPassword: string, newNtHash = ''): Promise<void> {
    const domainHandle = await this.openDomain();
    try {
      const userHandle = g(
        await hSamrCreateUser2InDomain(this.dce, domainHandle, name, this.createAccountType, USER_ALL_ACCESS),
        'UserHandle',
      );
      try {
        await hSamrSetNTInternal1(this.dce, userHandle, newPassword, newNtHash);
      } catch (e) {
        await hSamrDeleteUser(this.dce, userHandle);
        throw e;
      }
      await this.hEnableAccount(userHandle);
    } finally {
      await this.closeDomain();
    }
  }

  async remove(name: string): Promise<void> {
    const domainHandle = await this.openDomain();
    try {
      const userHandle = await this.getUserHandle(domainHandle, name);
      await hSamrDeleteUser(this.dce, userHandle);
    } finally {
      await this.closeDomain();
    }
  }

  protected async hEnableAccount(userHandle: Any): Promise<void> {
    const uac = g(
      await hSamrQueryInformationUser2(
        this.dce,
        userHandle,
        USER_INFORMATION_CLASS.enumValues.UserAllInformation!,
      ),
      'Buffer',
      'All',
      'UserAccountControl',
    ) as number;
    const buffer = new SAMPR_USER_INFO_BUFFER();
    buffer.set('tag', USER_INFORMATION_CLASS.enumValues.UserControlInformation);
    (buffer.fields['Control'] as Any).set('UserAccountControl', uac ^ USER_ACCOUNT_DISABLED);
    await hSamrSetInformationUser2(this.dce, userHandle, buffer);
  }

  protected async hDisableAccount(userHandle: Any): Promise<void> {
    const uac = g(
      await hSamrQueryInformationUser2(
        this.dce,
        userHandle,
        USER_INFORMATION_CLASS.enumValues.UserAllInformation!,
      ),
      'Buffer',
      'All',
      'UserAccountControl',
    ) as number;
    const buffer = new SAMPR_USER_INFO_BUFFER();
    buffer.set('tag', USER_INFORMATION_CLASS.enumValues.UserControlInformation);
    (buffer.fields['Control'] as Any).set('UserAccountControl', USER_ACCOUNT_DISABLED | uac);
    await hSamrSetInformationUser2(this.dce, userHandle, buffer);
  }

  async setUserAccountControl(name: string, action: 'enable' | 'disable'): Promise<void> {
    await this.query(name);
    const domainHandle = await this.openDomain();
    try {
      const userHandle = await this.getUserHandle(domainHandle, name);
      if (action === 'enable') {
        await this.hEnableAccount(userHandle);
      } else {
        await this.hDisableAccount(userHandle);
      }
    } finally {
      await this.closeDomain();
    }
  }
}

// ---------------------------------------------------------------------------
// Computer
// ---------------------------------------------------------------------------

class Computer extends User {
  protected override createAccountType = USER_WORKSTATION_TRUST_ACCOUNT;
  protected override enumAccountType = USER_WORKSTATION_TRUST_ACCOUNT | USER_SERVER_TRUST_ACCOUNT;
}

// ---------------------------------------------------------------------------
// Group
// ---------------------------------------------------------------------------

class Group extends SamrObject {
  async enumerate(): Promise<Any[]> {
    const domainHandle = await this.openDomain();
    try {
      const response = await callAllowMoreEntries(hSamrEnumerateGroupsInDomain(this.dce, domainHandle));
      if (response === null) return [];
      return g(response, 'Buffer', 'Buffer') as Any[];
    } finally {
      await this.closeDomain();
    }
  }

  async query(groupName: string): Promise<string[]> {
    const domainHandle = await this.openDomain();
    try {
      const groupHandle = await this.getGroupHandle(domainHandle, groupName);
      const members = await hSamrGetMembersInGroup(this.dce, groupHandle);
      const memberIds = (g(members, 'Members', 'Members') as Any[]).map((a) => Number(g(a, 'Data')));
      const resolved = await hSamrLookupIdsInDomain(this.dce, domainHandle, memberIds);
      return (g(resolved, 'Names', 'Element') as Any[]).map((a) => ustr(a));
    } finally {
      await this.closeDomain();
    }
  }

  async join(groupName: string, username: string): Promise<void> {
    const domainHandle = await this.openDomain();
    try {
      const groupHandle = await this.getGroupHandle(domainHandle, groupName);
      const userRid = await this.getObjectRid(domainHandle, username);
      await hSamrAddMemberToGroup(this.dce, groupHandle, userRid, SE_GROUP_ENABLED_BY_DEFAULT);
    } finally {
      await this.closeDomain();
    }
  }

  async unJoin(groupName: string, username: string): Promise<void> {
    const domainHandle = await this.openDomain();
    try {
      const groupHandle = await this.getGroupHandle(domainHandle, groupName);
      const userRid = await this.getObjectRid(domainHandle, username);
      await hSamrRemoveMemberFromGroup(this.dce, groupHandle, userRid);
    } finally {
      await this.closeDomain();
    }
  }
}

// ---------------------------------------------------------------------------
// Localgroup
// ---------------------------------------------------------------------------

class Localgroup extends Group {
  override async enumerate(): Promise<Any[]> {
    const domainHandle = await this.openDomain(true);
    try {
      const response = await callAllowMoreEntries(hSamrEnumerateAliasesInDomain(this.dce, domainHandle));
      if (response === null) return [];
      return g(response, 'Buffer', 'Buffer') as Any[];
    } finally {
      await this.closeDomain();
    }
  }

  override async query(groupName: string): Promise<string[]> {
    const domainHandle = await this.openDomain(true);
    try {
      const aliasHandle = await this.getAliasHandle(domainHandle, groupName);
      const members = await hSamrGetMembersInAlias(this.dce, aliasHandle);
      const sidList = (g(members, 'Members', 'Sids') as Any[]).map((s) =>
        s.get('Data').get('SidPointer').formatCanonical(),
      );
      const resolved = await this.resolveSid(sidList);
      return resolved.map((x) => ustr(x.get('Name')));
    } finally {
      await this.closeDomain();
    }
  }

  override async join(groupName: string, username: string): Promise<void> {
    const domainHandle = await this.openDomain(true);
    try {
      const aliasHandle = await this.getAliasHandle(domainHandle, groupName);
      const userSid = await this.getUserSid(username);
      await hSamrAddMemberToAlias(this.dce, aliasHandle, userSid);
    } finally {
      await this.closeDomain();
    }
  }

  override async unJoin(groupName: string, username: string): Promise<void> {
    const domainHandle = await this.openDomain(true);
    try {
      const aliasHandle = await this.getAliasHandle(domainHandle, groupName);
      const userSid = await this.getUserSid(username);
      await hSamrRemoveMemberFromAlias(this.dce, aliasHandle, userSid);
    } finally {
      await this.closeDomain();
    }
  }
}

// ---------------------------------------------------------------------------
// Net
// ---------------------------------------------------------------------------

interface NetOptions {
  entry: string;
  name?: string;
  create?: string;
  remove?: string;
  newPasswd?: string;
  enable?: string;
  disable?: string;
  join?: string;
  unjoin?: string;
  hashes: string | null;
  aesKey: string | null;
  k: boolean;
  dcIp: string | null;
  port: number;
  debug: boolean;
}

type ActionObject = User | Computer | Group | Localgroup;

class Net {
  private domain: string;
  private username: string;
  private password: string;
  private options: NetOptions;
  private action: string;
  private lmhash = '';
  private nthash = '';
  private aesKey: string | null;
  private doKerberos: boolean;
  private kdcHost: string | null;
  private smbConnection: SMBConnection | null = null;

  constructor(domain: string, username: string, password: string, options: NetOptions) {
    this.domain = domain;
    this.username = username;
    this.password = password;
    this.options = options;
    this.action = options.entry.toLowerCase();
    this.aesKey = options.aesKey;
    this.doKerberos = options.k;
    this.kdcHost = options.dcIp;

    if (options.hashes !== null) {
      const parts = options.hashes.split(':');
      this.lmhash = parts[0] ?? '';
      this.nthash = parts[1] ?? '';
    }
  }

  async connect(remoteName: string, remoteHost: string): Promise<void> {
    this.smbConnection = new SMBConnection(remoteName, remoteHost, { sessPort: this.options.port });
    await this.smbConnection.negotiateSession();

    if (this.doKerberos) {
      await this.smbConnection.kerberosLogin(
        this.username,
        this.password,
        this.domain,
        this.lmhash,
        this.nthash,
        this.aesKey ?? '',
        this.kdcHost,
      );
    } else {
      await this.smbConnection.login(this.username, this.password, this.domain, this.lmhash, this.nthash);
    }
  }

  async disconnect(): Promise<void> {
    if (this.smbConnection !== null) {
      await this.smbConnection.close();
      this.smbConnection = null;
    }
  }

  private getActionObject(): ActionObject {
    switch (this.action) {
      case 'user':
        return new User(this.smbConnection!);
      case 'computer':
        return new Computer(this.smbConnection!);
      case 'group':
        return new Group(this.smbConnection!);
      case 'localgroup':
        return new Localgroup(this.smbConnection!);
      default:
        throw new Error(`Unknown entry: ${this.action}`);
    }
  }

  async run(remoteName: string, remoteHost: string): Promise<void> {
    await this.connect(remoteName, remoteHost);

    const actionObject = this.getActionObject();
    await actionObject.connect();

    const o = this.options;

    if (o.create) {
      console.log(`[*] Creating ${this.action} account '${o.create}'`);
      await (actionObject as User).create(o.create, o.newPasswd ?? '');
      console.log(`[+] ${this.action} account created succesfully: ${o.create}:${o.newPasswd}`);
    } else if (o.remove) {
      console.log(`[*] Deleting ${this.action} account '${o.remove}'`);
      await (actionObject as User).remove(o.remove);
      console.log(`[+] ${this.action} account deleted succesfully!`);
    } else if (o.enable) {
      console.log(`[*] Enabling ${this.action} account '${o.enable}'`);
      await (actionObject as User).setUserAccountControl(o.enable, 'enable');
      console.log(`[+] ${this.action} account enabled succesfully!`);
    } else if (o.disable) {
      console.log(`[*] Disabling ${this.action} account '${o.disable}'`);
      await (actionObject as User).setUserAccountControl(o.disable, 'disable');
      console.log(`[+] ${this.action} account disabled succesfully!`);
    } else if (o.join) {
      console.log(`[*] Adding user account '${o.join}' to group '${o.name}'`);
      await (actionObject as Group).join(o.name!, o.join);
      console.log(`[+] User account added to ${o.name} succesfully!`);
    } else if (o.unjoin) {
      console.log(`[*] Removing user account '${o.unjoin}' from group '${o.name}'`);
      await (actionObject as Group).unJoin(o.name!, o.unjoin);
      console.log(`[+] User account removed from ${o.name} succesfully!`);
    } else if (o.name) {
      const info = await (actionObject as Any).query(o.name);
      if (Array.isArray(info)) {
        let i = 1;
        for (const member of info) {
          console.log(`  ${i}. ${member}`);
          i += 1;
        }
      } else if (info) {
        this.printUserInfo(info);
      }
    } else {
      console.log(`[*] Enumerating ${this.action}s ..`);
      let i = 1;
      const objects = await (actionObject as Any).enumerate();
      for (const object of objects) {
        let message = `  ${i}. ${ustr(object.get('Name'))}`;
        if (o.debug) {
          message += ` (${object.get('RelativeId')})`;
        }
        console.log(message);
        i += 1;
      }
    }

    await this.disconnect();
  }

  private printUserInfo(result: UserQueryResult): void {
    const info = result.info;
    const uac = info.get('UserAccountControl') as number;
    const which = info.get('WhichFields') as number;
    const country = info.get('CountryCode') as number;
    const workstations = ustr(info.get('WorkStations'));

    console.log(ljust('User name', 30) + ' ' + ustr(info.get('UserName')));
    console.log(ljust('Full name', 30) + ' ' + ustr(info.get('FullName')));
    console.log(ljust('Comment', 30) + ' ' + ustr(info.get('AdminComment')));
    console.log(ljust("User's comment", 30) + ' ' + ustr(info.get('UserComment')));
    console.log(
      ljust('Country/region code', 30) + ' ' + (country === 0 ? '000 (System Default)' : String(country)),
    );
    console.log(
      ljust('Account active', 30) + ' ' + b2s((uac & USER_ACCOUNT_DISABLED) !== USER_ACCOUNT_DISABLED),
    );
    console.log(ljust('Account expires', 30) + ' ' + getTimeString(info.get('AccountExpires')));
    console.log('');
    console.log(ljust('Password last set', 30) + ' ' + getTimeString(info.get('PasswordLastSet')));
    console.log(ljust('Password expires', 30) + ' ' + getTimeString(info.get('PasswordMustChange')));
    console.log(ljust('Password changeable', 30) + ' ' + getTimeString(info.get('PasswordCanChange')));
    console.log(
      ljust('Password required', 30) +
        ' ' +
        b2s((which & USER_PASSWORD_NOT_REQUIRED) === USER_PASSWORD_NOT_REQUIRED),
    );
    console.log(
      ljust('User may change password', 30) +
        ' ' +
        b2s((which & UF_PASSWD_CANT_CHANGE) === UF_PASSWD_CANT_CHANGE),
    );
    console.log('');
    console.log(ljust('Workstations allowed', 30) + ' ' + (workstations === '' ? 'All' : workstations));
    console.log(ljust('Logon script', 30) + ' ' + ustr(info.get('ScriptPath')));
    console.log(ljust('User profile', 30) + ' ' + ustr(info.get('ProfilePath')));
    console.log(ljust('Home directory', 30) + ' ' + ustr(info.get('HomeDirectory')));
    console.log(ljust('Last logon', 30) + ' ' + getTimeString(info.get('LastLogon')));
    console.log(ljust('Logon count', 30) + ' ' + String(info.get('LogonCount')));
    console.log('');
    let logonHoursRaw: Any = '';
    try {
      logonHoursRaw = g(info, 'LogonHours', 'LogonHours');
    } catch {
      /* ignore */
    }
    console.log(ljust('Logon hours allowed', 30) + ' ' + formatLogonHours(logonHoursRaw));
    console.log('');
    console.log('Local Group Memberships');
    for (const group of result.localGroups) {
      console.log(`  * ${group}`);
    }
    console.log('');
    console.log('Global Group memberships');
    for (const group of result.globalGroups) {
      console.log(`  * ${group}`);
    }
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------


function printUsage(): void {
  console.log(`SAMR rpc client implementation.

usage: net [-h] [-debug] [-ts] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
           [-aesKey hex key] [-dc-ip ip address] [-target-ip ip address]
           [-port [{139,445}]]
           target {user,computer,localgroup,group} ...

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  {user,computer,localgroup,group}
                        An account entry name
    user                Enumerate all domain/local user accounts
                          -name NAME      Display single user information.
                          -create NAME    Add new user account to domain/computer.
                          -remove NAME    Remove existing user account from domain/computer.
                          -newPasswd PASSWORD  New password to set for creating account.
                          -enable NAME    Enables account.
                          -disable NAME   Disables account.
    computer            Enumerate all computers in domain level
                          -name NAME      Display single computer information.
                          -create NAME    Add new computer account to domain.
                          -remove NAME    Remove existing computer account from domain.
                          -newPasswd PASSWORD  New password to set for creating account.
                          -enable NAME    Enables account.
                          -disable NAME   Disables account.
    localgroup          Enumerate local groups (aliases) of local computer
                          -name NAME      Operate on single specific domain group account.
                          -join USER      Add user account to specific group.
                          -unjoin USER    Remove user account from specific group.
    group               Enumerate domain groups registered in domain controller
                          -name NAME      Operate on single specific localgroup account.
                          -join USER      Add user account to specific group.
                          -unjoin USER    Remove user account from specific group.

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output

authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it will
                        use the domain part (FQDN) specified in the target parameter
  -target-ip ip address IP Address of the target machine. If omitted it will use
                        whatever was specified as target
  -port [{139,445}]     Destination port to connect to SMB Server`);
}

async function main(): Promise<void> {
  console.log(`${BANNER}\n`);

  const args = normalizeArgs(process.argv.slice(2));

  if (args.length === 0) {
    printUsage();
    process.exit(1);
  }

  let values: Any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      strict: true,
      options: {
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        name: { type: 'string' },
        create: { type: 'string' },
        remove: { type: 'string' },
        newPasswd: { type: 'string' },
        enable: { type: 'string' },
        disable: { type: 'string' },
        join: { type: 'string' },
        unjoin: { type: 'string' },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
        'target-ip': { type: 'string' },
        port: { type: 'string', default: '445' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    logError(String((e as Error).message ?? e));
    printUsage();
    process.exit(1);
  }

  if (values.help) {
    printUsage();
    process.exit(0);
  }

  // positionals[0] = target, positionals[1] = entry (subcommand)
  const target = positionals[0];
  const entry = positionals[1];

  if (!target || !entry) {
    printUsage();
    process.exit(1);
  }

  const validEntries = ['user', 'computer', 'localgroup', 'group'];
  if (!validEntries.includes(entry.toLowerCase())) {
    logError(`invalid choice: '${entry}' (choose from 'user', 'computer', 'localgroup', 'group')`);
    process.exit(1);
  }

  // Validation mirroring impacket
  if ((values.join || values.unjoin) && !values.name) {
    logError("argument '-name' is required with join/unjoin operations.");
    process.exit(1);
  }
  if (values.create && !values.newPasswd) {
    logError("argument '-newPasswd' is required for creating new account.");
    process.exit(1);
  }

  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  let [domain, username, password, address] = parseTarget(target);

  let targetIp = values['target-ip'] as string | undefined;
  if (targetIp === undefined || targetIp === null) {
    targetIp = address;
  }
  if (domain === null || domain === undefined) {
    domain = '';
  }

  let doKerberos = values.k as boolean;
  if (values.aesKey) {
    doKerberos = true;
  }

  let resolvedPassword = password;
  if (
    resolvedPassword === '' &&
    username !== '' &&
    !values.hashes &&
    !values['no-pass'] &&
    !values.aesKey
  ) {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    resolvedPassword = await new Promise<string>((resolve) => {
      rl.question('Password: ', (answer) => {
        rl.close();
        resolve(answer);
      });
    });
  }

  const options: NetOptions = {
    entry: entry.toLowerCase(),
    name: values.name,
    create: values.create,
    remove: values.remove,
    newPasswd: values.newPasswd,
    enable: values.enable,
    disable: values.disable,
    join: values.join,
    unjoin: values.unjoin,
    hashes: values.hashes ?? null,
    aesKey: values.aesKey ?? null,
    k: doKerberos,
    dcIp: values['dc-ip'] ?? null,
    port: parseInt(values.port ?? '445', 10),
    debug: values.debug,
  };

  const net = new Net(domain, username, resolvedPassword, options);
  try {
    await net.run(address, targetIp);
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) {
      console.error(e);
    }
    logError(String((e as Error).message ?? e));
  }
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

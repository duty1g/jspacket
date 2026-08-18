import { Buffer } from 'node:buffer';
import os from 'node:os';
import * as nmb from '@impacket/nmb';
import { getGlobalProxy } from '@impacket/socks';
import { SMB, type SMBOptions, SharedFile } from '@impacket/smb';
import * as smbConsts from '@impacket/smb';
import {
  FLAGS1_CANONICALIZED_PATHS,
  FLAGS1_PATHCASELESS,
  FLAGS2_EXTENDED_SECURITY,
  FLAGS2_LONG_NAMES,
  FLAGS2_NT_STATUS,
  FLAGS2_UNICODE,
  SMBQueryFileStandardInfo,
  SessionError as SMBSessionError,
  SMB_DIALECT,
} from '@impacket/smb';
import { SMB3, type SMB3Options, SessionError as SMB3SessionError } from '@impacket/smb3';
import * as smb3structs from '@impacket/smb3';
import {
  FILE_ATTRIBUTE_NORMAL,
  FILE_DIRECTORY_FILE,
  FILE_FULL_DIRECTORY_INFORMATION,
  FILE_NON_DIRECTORY_FILE,
  FILE_OPEN,
  FILE_OPEN_REPARSE_POINT,
  FILE_OVERWRITE_IF,
  FILE_READ_ATTRIBUTES,
  FILE_READ_DATA,
  FILE_READ_EA,
  DELETE,
  FILE_DELETE_ON_CLOSE,
  FILE_SHARE_DELETE,
  FILE_SHARE_READ,
  FILE_SHARE_WRITE,
  FILE_SYNCHRONOUS_IO_NONALERT,
  FILE_WRITE_DATA,
  FSCTL_DELETE_REPARSE_POINT,
  FSCTL_DFS_GET_REFERRALS,
  FSCTL_SET_REPARSE_POINT,
  FSCTL_SRV_ENUMERATE_SNAPSHOTS,
  GENERIC_ALL,
  GENERIC_READ,
  GENERIC_WRITE,
  MOUNT_POINT_REPARSE_DATA_STRUCTURE,
  MOUNT_POINT_REPARSE_GUID_DATA_STRUCTURE,
  READ_CONTROL,
  REQ_GET_DFS_REFERRAL,
  SMB2_0_IOCTL_IS_FSCTL,
  SMB2_DIALECT_002,
  SMB2_DIALECT_21,
  SMB2_DIALECT_30,
  SMB2_DIALECT_302,
  SMB2_DIALECT_311,
  SMB2_IL_IMPERSONATION,
  SMB2_OPLOCK_LEVEL_NONE,
  SRV_SNAPSHOT_ARRAY,
  SYNCHRONIZE,
  parseDfsReferral,
} from '@impacket/smb3';
import * as krb5 from '@impacket/krb5';
import { SMBTransport } from '@impacket/dcerpc';
import { MSRPC_UUID_SRVS, hNetrShareEnum } from '@impacket/dcerpc';

const SMB1_DIALECT = SMB_DIALECT;

export class SessionError extends Error {
  error: number;
  packet: unknown;

  constructor(error = 0, packet: unknown = null) {
    super(`SMB SessionError: code: 0x${error.toString(16)}`);
    this.error = error;
    this.packet = packet;
  }

  getErrorCode(): number {
    return this.error;
  }

  getErrorPacket(): unknown {
    return this.packet;
  }
}

export interface SMBConnectionOptions {
  myName?: string | null;
  sessPort?: number;
  timeout?: number;
  preferredDialect?: number | string | null;
  existingConnection?: SMB | SMB3 | null;
  manualNegotiate?: boolean;
}

type Dialect = string | number;

function isSMB1(conn: SMB | SMB3): conn is SMB {
  return conn instanceof SMB;
}

function isSMB3(conn: SMB | SMB3): conn is SMB3 {
  return conn instanceof SMB3;
}

export class SMBConnection {
  private _SMBConnection: SMB | SMB3;
  private _dialect: Dialect = '';
  private _nmbSession: nmb.NetBIOSTCPSession | null = null;
  private _sessPort: number;
  private _myName: string | null;
  private _remoteHost: string;
  private _remoteName: string;
  private _timeout: number;
  private _preferredDialect: number | string | null;
  private _manualNegotiate: boolean;
  private _doKerberos = false;
  private _kdcHost: string | null = null;
  private _useCache = true;
  private _ntlmFallback = true;

  constructor(remoteName = '', remoteHost = '', options: SMBConnectionOptions = {}) {
    const {
      myName = null,
      sessPort = 445,
      timeout = 60,
      preferredDialect = null,
      existingConnection = null,
      manualNegotiate = false,
    } = options;

    this._SMBConnection = null as unknown as SMB | SMB3;
    this._sessPort = sessPort;
    this._myName = myName;
    this._remoteHost = remoteHost;
    this._remoteName = remoteName;
    this._timeout = timeout;
    this._preferredDialect = preferredDialect;
    this._manualNegotiate = manualNegotiate;

    if (existingConnection) {
      this._SMBConnection = existingConnection;
      const d = this.getDialect();
      this._preferredDialect = typeof d === 'number' ? d : d;
      this._doKerberos = isSMB3(this._SMBConnection) ? this._SMBConnection.getKerberos() : false;
      return;
    }

    this._manualNegotiate = manualNegotiate;
  }

  async negotiateSession(
    preferredDialect?: number | string | null,
    flags1 = FLAGS1_PATHCASELESS | FLAGS1_CANONICALIZED_PATHS,
    flags2 = FLAGS2_EXTENDED_SECURITY | FLAGS2_NT_STATUS | FLAGS2_LONG_NAMES,
    negoData = Buffer.from('\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00', 'latin1'),
  ): Promise<boolean> {
    if (this._sessPort === 445 && this._remoteName === '*SMBSERVER') {
      this._remoteName = this._remoteHost;
    }

    if (this._sessPort === 139) {
      negoData = Buffer.from('\x02NT LM 0.12\x00\x02SMB 2.002\x00', 'latin1');
    }

    const hostType = nmb.TYPE_SERVER;
    const dialect = preferredDialect ?? this._preferredDialect;

    if (dialect == null) {
      const packet = await this.negotiateSessionWildcard(flags1, flags2, negoData);
      if (packet.length > 0 && packet[0] === 0xfe) {
        this._SMBConnection = new SMB3(this._remoteName, this._remoteHost, {
          myName: this._myName ?? undefined,
          hostType,
          sessPort: this._sessPort,
          timeout: this._timeout,
          session: this._nmbSession,
        });
        await this._SMBConnection.negotiateSession(null, packet);
      } else {
        this._SMBConnection = new SMB(this._remoteName, this._remoteHost, {
          myName: this._myName ?? undefined,
          hostType,
          sessPort: this._sessPort,
          timeout: this._timeout,
          session: this._nmbSession,
        });
        await this._SMBConnection.negSession(true, packet);
      }
    } else if (dialect === SMB1_DIALECT) {
      let session: nmb.NetBIOSTCPSession | undefined;
      if (getGlobalProxy()) {
        session = await nmb.NetBIOSTCPSession.withProxy(
          this._myName ?? os.hostname().split('.')[0]!,
          this._remoteName, this._remoteHost, hostType, this._sessPort, this._timeout,
        );
      }
      this._SMBConnection = new SMB(this._remoteName, this._remoteHost, {
        myName: this._myName ?? undefined,
        hostType,
        sessPort: this._sessPort,
        timeout: this._timeout,
        session,
      });
      await this._SMBConnection.negSession();
    } else if (
      dialect === SMB2_DIALECT_002 ||
      dialect === SMB2_DIALECT_21 ||
      dialect === SMB2_DIALECT_30 ||
      dialect === SMB2_DIALECT_302 ||
      dialect === SMB2_DIALECT_311
    ) {
      let session: nmb.NetBIOSTCPSession | undefined;
      if (getGlobalProxy()) {
        session = await nmb.NetBIOSTCPSession.withProxy(
          this._myName ?? os.hostname().split('.')[0]!,
          this._remoteName, this._remoteHost, hostType, this._sessPort, this._timeout,
        );
      }
      this._SMBConnection = new SMB3(this._remoteName, this._remoteHost, {
        myName: this._myName ?? undefined,
        hostType,
        sessPort: this._sessPort,
        timeout: this._timeout,
        preferredDialect: dialect as number,
        session,
      });
      await this._SMBConnection.negotiateSession();
    } else {
      throw new Error(`Unknown dialect ${dialect}`);
    }

    if (isSMB1(this._SMBConnection)) {
      const [, f2] = this._SMBConnection.getFlags();
      if (f2 & FLAGS2_UNICODE) {
        flags2 |= FLAGS2_UNICODE;
      }
      this._SMBConnection.setFlags(flags1, flags2);
    }

    return true;
  }

  private async negotiateSessionWildcard(
    flags1: number,
    flags2: number,
    data: Buffer,
  ): Promise<Buffer> {
    let myName = this._myName;
    if (!myName) {
      myName = os.hostname();
      const i = myName.indexOf('.');
      if (i > -1) myName = myName.slice(0, i);
    }

    const smbp = new smbConsts.NewSMBPacket();
    smbp.set('Flags1', flags1);
    smbp.set('Flags2', flags2 | FLAGS2_UNICODE | FLAGS2_EXTENDED_SECURITY);

    const negSession = new smbConsts.SMBCommand(smbConsts.SMB_COMMAND_NEGOTIATE);
    negSession.set('Data', data);
    smbp.addCommand(negSession);

    if (getGlobalProxy()) {
      this._nmbSession = await nmb.NetBIOSTCPSession.withProxy(
        myName, this._remoteName, this._remoteHost,
        nmb.TYPE_SERVER, this._sessPort, this._timeout,
      );
    } else {
      this._nmbSession = new nmb.NetBIOSTCPSession(
        myName, this._remoteName, this._remoteHost,
        nmb.TYPE_SERVER, this._sessPort, this._timeout,
      );
    }

    await this._nmbSession.sendPacket(smbp.getData());
    const resp = await this._nmbSession.recvPacket(this._timeout);
    return resp.get_trailer();
  }

  getNMBServer(): nmb.NetBIOSTCPSession | null {
    return this._nmbSession;
  }

  getSMBServer(): SMB | SMB3 {
    return this._SMBConnection;
  }

  getDialect(): Dialect {
    return this._SMBConnection.getDialect();
  }

  getServerName(): string {
    return isSMB1(this._SMBConnection)
      ? this._SMBConnection.getServerName()
      : this._SMBConnection.getServerName();
  }

  getClientName(): string {
    return isSMB1(this._SMBConnection)
      ? this._SMBConnection.getClientName()
      : this._SMBConnection.getClientName();
  }

  getRemoteHost(): string {
    return isSMB1(this._SMBConnection)
      ? this._SMBConnection.getRemoteHost()
      : this._SMBConnection.getServerIP();
  }

  getRemoteName(): string {
    return isSMB1(this._SMBConnection)
      ? this._SMBConnection.getRemoteName()
      : this._SMBConnection.getRemoteName();
  }

  setRemoteName(name: string): boolean {
    if (isSMB1(this._SMBConnection)) return this._SMBConnection.setRemoteName(name);
    return this._SMBConnection.setRemoteName(name);
  }

  getServerDomain(): string {
    return isSMB1(this._SMBConnection)
      ? this._SMBConnection.getServerDomain()
      : this._SMBConnection.getServerDomain();
  }

  getServerDNSDomainName(): string {
    return isSMB1(this._SMBConnection)
      ? this._SMBConnection.getServerDnsDomainName()
      : this._SMBConnection.getServerDNSDomainName();
  }

  getServerDNSHostName(): string {
    return isSMB1(this._SMBConnection)
      ? this._SMBConnection.getServerDnsHostName()
      : this._SMBConnection.getServerDNSHostName();
  }

  getServerOS(): string {
    return this._SMBConnection.getServerOS();
  }

  getServerOSMajor(): number | null {
    return this._SMBConnection.getServerOSMajor();
  }

  getServerOSMinor(): number | null {
    return this._SMBConnection.getServerOSMinor();
  }

  getServerOSBuild(): number | null {
    return this._SMBConnection.getServerOSBuild();
  }

  doesSupportNTLMv2(): boolean {
    return this._SMBConnection.doesSupportNTLMv2();
  }

  isLoginRequired(): boolean {
    return this._SMBConnection.isLoginRequired();
  }

  isSigningRequired(): boolean {
    return this._SMBConnection.isSigningRequired();
  }

  getCredentials() {
    return this._SMBConnection.getCredentials();
  }

  getIOCapabilities() {
    return this._SMBConnection.getIOCapabilities();
  }

  async login(
    user: string,
    password: string,
    domain = '',
    lmhash: Buffer | string = '',
    nthash: Buffer | string = '',
    ntlmFallback = true,
  ): Promise<void> {
    this._ntlmFallback = ntlmFallback;
    try {
      if (this.getDialect() === SMB1_DIALECT) {
        await (this._SMBConnection as SMB).login(
          user,
          password,
          domain,
          lmhash,
          nthash,
          ntlmFallback,
        );
      } else {
        await (this._SMBConnection as SMB3).login(user, password, domain, lmhash, nthash);
      }
    } catch (e) {
      if (e instanceof SMBSessionError || e instanceof SMB3SessionError) {
        throw new SessionError((e as SMBSessionError).error, null);
      }
      throw e;
    }
  }

  async kerberosLogin(
    user: string,
    password: string,
    domain = '',
    lmhash: Buffer | string = '',
    nthash: Buffer | string = '',
    aesKey: Buffer | string = '',
    kdcHost: string | null = null,
    TGT: krb5.KerberosV5.TGTResult | null = null,
    TGS: krb5.KerberosV5.TGSResult | null = null,
    useCache = true,
  ): Promise<void> {
    this._doKerberos = true;
    this._kdcHost = kdcHost;
    this._useCache = useCache;

    if (TGT !== null || TGS !== null) {
      this._useCache = false;
    }

    try {
      if (this.getDialect() === SMB1_DIALECT) {
        throw new Error('Kerberos login not yet supported for SMBv1');
      } else {
        await (this._SMBConnection as SMB3).kerberosLogin(
          user,
          password,
          domain,
          lmhash,
          nthash,
          aesKey,
          kdcHost,
          TGT,
          TGS,
        );
      }
    } catch (e) {
      if (e instanceof SMBSessionError || e instanceof SMB3SessionError) {
        throw new SessionError((e as SMBSessionError).error, null);
      }
      throw e;
    }
  }

  isGuestSession(): boolean {
    return this._SMBConnection.isGuestSession();
  }

  async logoff(): Promise<void> {
    try {
      if (isSMB1(this._SMBConnection)) {
        await this._SMBConnection.logoff();
      } else {
        await this._SMBConnection.logoff();
      }
    } catch (e) {
      if (e instanceof SMBSessionError || e instanceof SMB3SessionError) {
        throw new SessionError((e as SMBSessionError).error, null);
      }
      throw e;
    }
  }

  async connectTree(share: string): Promise<number> {
    if (this.getDialect() === SMB1_DIALECT) {
      if (!share.startsWith('\\\\')) {
        share = `\\\\${this.getRemoteHost()}\\${share.split('\\').pop()}`;
      }
    }
    try {
      if (isSMB1(this._SMBConnection)) {
        return await this._SMBConnection.treeConnectAndX(share);
      }
      return await this._SMBConnection.connectTree(share);
    } catch (e) {
      if (e instanceof SMBSessionError || e instanceof SMB3SessionError) {
        throw new SessionError((e as SMBSessionError).error, null);
      }
      throw e;
    }
  }

  async disconnectTree(treeId: number): Promise<void> {
    try {
      if (isSMB1(this._SMBConnection)) {
        await this._SMBConnection.disconnectTree(treeId);
      } else {
        await this._SMBConnection.disconnectTree(treeId);
      }
    } catch (e) {
      if (e instanceof SMBSessionError || e instanceof SMB3SessionError) {
        throw new SessionError((e as SMBSessionError).error, null);
      }
      throw e;
    }
  }

  async createFile(
    treeId: number,
    pathName: string,
    desiredAccess = GENERIC_ALL,
    shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    creationOption = FILE_NON_DIRECTORY_FILE,
    creationDisposition = FILE_OVERWRITE_IF,
    fileAttributes = FILE_ATTRIBUTE_NORMAL,
    impersonationLevel = SMB2_IL_IMPERSONATION,
    securityFlags = 0,
    oplockLevel = SMB2_OPLOCK_LEVEL_NONE,
  ): Promise<number | Buffer> {
    if (this.getDialect() === SMB1_DIALECT) {
      const smb = this._SMBConnection as SMB;
      return await smb.ntCreateAndX(
        treeId,
        pathName,
        undefined,
        undefined,
        shareMode,
        creationDisposition,
        desiredAccess,
      );
    }
    const smb3 = this._SMBConnection as SMB3;
    return await smb3.create(
      treeId,
      pathName,
      desiredAccess,
      shareMode,
      creationOption,
      creationDisposition,
      fileAttributes,
      impersonationLevel,
      securityFlags,
      oplockLevel,
    );
  }

  async openFile(
    treeId: number,
    pathName: string,
    desiredAccess = FILE_READ_DATA | FILE_WRITE_DATA,
    shareMode = FILE_SHARE_READ,
    creationOption = FILE_NON_DIRECTORY_FILE,
    creationDisposition = FILE_OPEN,
    fileAttributes = FILE_ATTRIBUTE_NORMAL,
    impersonationLevel = SMB2_IL_IMPERSONATION,
    securityFlags = 0,
    oplockLevel = SMB2_OPLOCK_LEVEL_NONE,
  ): Promise<number | Buffer> {
    if (this.getDialect() === SMB1_DIALECT) {
      const smb = this._SMBConnection as SMB;
      return await smb.ntCreateAndX(
        treeId,
        pathName,
        undefined,
        undefined,
        shareMode,
        creationDisposition,
        desiredAccess,
      );
    }
    const smb3 = this._SMBConnection as SMB3;
    return await smb3.create(
      treeId,
      pathName,
      desiredAccess,
      shareMode,
      creationOption,
      creationDisposition,
      fileAttributes,
      impersonationLevel,
      securityFlags,
      oplockLevel,
    );
  }

  async writeFile(
    treeId: number,
    fileId: number | Buffer,
    data: Buffer,
    offset = 0,
  ): Promise<number> {
    if (this.getDialect() === SMB1_DIALECT) {
      const smb = this._SMBConnection as SMB;
      return await smb.writeFile(treeId, fileId as number, data, offset);
    }
    const smb3 = this._SMBConnection as SMB3;
    return await smb3.writeFile(treeId, fileId as Buffer, data, BigInt(offset));
  }

  async readFile(
    treeId: number,
    fileId: number | Buffer,
    offset = 0,
    bytesToRead: number | null = null,
    singleCall = true,
  ): Promise<Buffer> {
    let finished = false;
    let data = Buffer.alloc(0);
    const maxReadSize = this._SMBConnection.getIOCapabilities().MaxReadSize;
    const target = bytesToRead ?? maxReadSize;
    let remaining = target;
    let curOffset = offset;

    while (!finished) {
      const toRead = Math.min(remaining, maxReadSize);
      let bytesRead: Buffer;
      try {
        if (this.getDialect() === SMB1_DIALECT) {
          bytesRead = (await (this._SMBConnection as SMB).readAndX(
            treeId,
            fileId as number,
            curOffset,
            toRead,
          )) as Buffer;
        } else {
          bytesRead = await (this._SMBConnection as SMB3).read(
            treeId,
            fileId as Buffer,
            toRead,
            BigInt(curOffset),
          );
        }
      } catch (e: any) {
        if (e instanceof SMBSessionError || e instanceof SMB3SessionError) {
          if (e.error === 0xc0000011) return data;
          throw new SessionError(e.error, null);
        }
        if (e instanceof Error && typeof (e as any).error === 'number') {
          if ((e as any).error === 0xc0000011) return data;
          throw new SessionError((e as any).error, null);
        }
        throw e;
      }

      data = Buffer.concat([data, bytesRead]);
      if (data.length >= target) finished = true;
      else if (bytesRead.length === 0) finished = true;
      else if (singleCall) finished = true;
      else {
        curOffset += bytesRead.length;
        remaining -= bytesRead.length;
      }
    }
    return data;
  }

  async closeFile(treeId: number, fileId: number | Buffer): Promise<boolean | number | undefined> {
    if (this.getDialect() === SMB1_DIALECT) {
      return await (this._SMBConnection as SMB).close(treeId, fileId as number);
    }
    return await (this._SMBConnection as SMB3).close(treeId, fileId as Buffer);
  }

  async deleteFile(shareName: string, pathName: string): Promise<void> {
    if (this.getDialect() === SMB1_DIALECT) {
      await (this._SMBConnection as SMB).remove(shareName, pathName);
    } else {
      const smb3 = this._SMBConnection as SMB3;
      const treeId = await smb3.connectTree(shareName);
      try {
        const fileId = await smb3.create(
          treeId,
          pathName,
          DELETE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
          FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
          FILE_OPEN,
          FILE_ATTRIBUTE_NORMAL,
        );
        await smb3.close(treeId, fileId);
      } finally {
        await smb3.disconnectTree(treeId);
      }
    }
  }

  async queryInfo(
    treeId: number,
    fileId: number | Buffer,
    fileInfoClass?: number,
  ): Promise<Buffer | SMBQueryFileStandardInfo> {
    if (this.getDialect() === SMB1_DIALECT) {
      const smb = this._SMBConnection as SMB;
      if (!fileInfoClass) {
        const res = await smb.queryFileInfo(treeId, fileId as number);
        return new SMBQueryFileStandardInfo(res);
      }
      return await smb.queryFileInfo(treeId, fileId as number, fileInfoClass);
    }
    const smb3 = this._SMBConnection as SMB3;
    if (!fileInfoClass) {
      const res = await smb3.queryInfo(treeId, fileId as Buffer);
      return new SMBQueryFileStandardInfo(res);
    }
    return await smb3.queryInfo(treeId, fileId as Buffer, Buffer.alloc(0), 1, fileInfoClass);
  }

  async setInfo(
    treeId: number,
    fileId: number | Buffer,
    fileInfoClass: number,
    infoData: Buffer,
  ): Promise<boolean | Buffer | undefined> {
    if (this.getDialect() === SMB1_DIALECT) {
      return await (this._SMBConnection as SMB).setFileInfo(
        treeId,
        fileId as number,
        fileInfoClass,
        infoData,
      );
    }
    return await (this._SMBConnection as SMB3).setInfo(
      treeId,
      fileId as Buffer,
      infoData,
      1,
      fileInfoClass,
    );
  }

  async createDirectory(shareName: string, pathName: string): Promise<void> {
    if (this.getDialect() === SMB1_DIALECT) {
      await (this._SMBConnection as SMB).mkdir(shareName, pathName);
    } else {
      throw new Error('createDirectory not yet implemented for SMB3');
    }
  }

  async deleteDirectory(shareName: string, pathName: string): Promise<void> {
    if (this.getDialect() === SMB1_DIALECT) {
      await (this._SMBConnection as SMB).rmdir(shareName, pathName);
    } else {
      throw new Error('deleteDirectory not yet implemented for SMB3');
    }
  }

  async waitNamedPipe(treeId: number, pipeName: string, timeout = 5): Promise<void> {
    if (this.getDialect() === SMB1_DIALECT) {
      await (this._SMBConnection as SMB).waitNamedPipe(treeId, pipeName, timeout);
    } else {
      await (this._SMBConnection as SMB3).waitNamedPipe(treeId, pipeName, timeout);
    }
  }

  async transactNamedPipe(
    treeId: number,
    fileId: number | Buffer,
    data: Buffer,
    waitAnswer = true,
  ): Promise<Buffer | null | undefined> {
    if (this.getDialect() === SMB1_DIALECT) {
      return await (this._SMBConnection as SMB).transactNamedPipe(
        treeId,
        fileId as number,
        data,
        0,
        waitAnswer,
      );
    }
    return await (this._SMBConnection as SMB3).TransactNamedPipe(
      treeId,
      fileId as Buffer,
      data,
      waitAnswer,
    );
  }

  async writeNamedPipe(
    treeId: number,
    fileId: number | Buffer,
    data: Buffer,
    waitAnswer = true,
  ): Promise<void> {
    if (this.getDialect() === SMB1_DIALECT) {
      await (this._SMBConnection as SMB).writeAndX(
        treeId,
        fileId as number,
        data,
        0,
        waitAnswer,
        true,
      );
    } else {
      await this.writeFile(treeId, fileId, data, 0);
    }
  }

  async readNamedPipe(
    treeId: number,
    fileId: number | Buffer,
    bytesToRead?: number,
  ): Promise<Buffer> {
    return this.readFile(treeId, fileId, 0, bytesToRead ?? null, true);
  }

  async listShares(): Promise<unknown[]> {
    const rpctransport = new SMBTransport(
      this.getRemoteName(),
      445,
      '\\srvsvc',
      '',
      '',
      '',
      '',
      '',
      null,
      null,
      null,
      this.getRemoteHost(),
      this,
    );
    const dce = rpctransport.getDceRpc();
    await dce.connect();
    await dce.bind(MSRPC_UUID_SRVS);
    const resp = await hNetrShareEnum(dce, 1);
    const infoStruct = resp.get('InfoStruct') as any;
    const shareInfo = infoStruct.get('ShareInfo') as any;
    const level1 = shareInfo.get('Level1') as any;
    return level1.get('Buffer') as any[];
  }

  async listPath(shareName: string, path: string, password?: string | null): Promise<unknown[]> {
    if (this.getDialect() === SMB1_DIALECT) {
      return await (this._SMBConnection as SMB).listPath(shareName, path, password ?? null);
    }

    // SMB3 implementation using queryDirectory
    const smb3 = this._SMBConnection as SMB3;
    let searchPath = path.replace(/\//g, '\\');
    // Normalize the path
    searchPath = searchPath.replace(/\\+/g, '\\').replace(/^\\/, '');

    // Split into directory and search pattern
    const lastSep = searchPath.lastIndexOf('\\');
    const dirPath = lastSep >= 0 ? searchPath.slice(0, lastSep) : '';
    const searchPattern = lastSep >= 0 ? searchPath.slice(lastSep + 1) : searchPath;

    const treeId = await smb3.connectTree(shareName);
    let fileId: Buffer | null = null;
    try {
      fileId = await smb3.create(
        treeId,
        dirPath,
        FILE_READ_ATTRIBUTES | FILE_READ_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_OPEN,
        0,
      );

      const files: SharedFile[] = [];
      const STATUS_NO_MORE_FILES = 0x80000006;

      // eslint-disable-next-line no-constant-condition
      while (true) {
        let res: Buffer;
        try {
          res = await smb3.queryDirectory(
            treeId,
            fileId,
            searchPattern || '*',
            0,
            FILE_FULL_DIRECTORY_INFORMATION,
            65535,
          );
        } catch (e) {
          if ((e instanceof SMB3SessionError || (e instanceof Error && 'error' in e)) && (e as any).error === STATUS_NO_MORE_FILES) {
            break;
          }
          throw e;
        }

        // Parse FILE_FULL_DIRECTORY_INFORMATION entries from the result buffer
        let offset = 0;
        while (offset < res.length) {
          // Minimum entry size: 68 bytes for the fixed fields
          if (res.length - offset < 68) break;

          const nextEntryOffset = res.readUInt32LE(offset);
          // FileIndex at offset + 4
          const creationTimeLow = res.readUInt32LE(offset + 8);
          const creationTimeHigh = res.readInt32LE(offset + 12);
          const lastAccessTimeLow = res.readUInt32LE(offset + 16);
          const lastAccessTimeHigh = res.readInt32LE(offset + 20);
          const lastWriteTimeLow = res.readUInt32LE(offset + 24);
          const lastWriteTimeHigh = res.readInt32LE(offset + 28);
          // LastChangeTime at offset + 32
          const endOfFileLow = res.readUInt32LE(offset + 40);
          const endOfFileHigh = res.readInt32LE(offset + 44);
          // AllocationSize at offset + 48
          const extFileAttributes = res.readUInt32LE(offset + 56);
          const fileNameLength = res.readUInt32LE(offset + 60);
          // EaSize at offset + 64
          const fileNameStart = offset + 68;
          const fileNameBuf = res.subarray(fileNameStart, fileNameStart + fileNameLength);
          const fileName = fileNameBuf.toString('utf-16le');

          // Convert Windows FILETIME (100ns since 1601-01-01) to JS Date
          const filesize = endOfFileLow + endOfFileHigh * 0x100000000;

          const toDate = (lo: number, hi: number): Date => {
            const ft = BigInt(hi) * 0x100000000n + BigInt(lo >>> 0);
            // FILETIME epoch offset: 11644473600000ms
            const ms = Number(ft / 10000n) - 11644473600000;
            return new Date(ms);
          };

          files.push(new SharedFile(
            fileName,
            fileName,
            filesize,
            extFileAttributes,
            toDate(lastWriteTimeLow, lastWriteTimeHigh),
            toDate(creationTimeLow, creationTimeHigh),
            toDate(lastAccessTimeLow, lastAccessTimeHigh),
          ));

          if (nextEntryOffset === 0) break;
          offset += nextEntryOffset;
        }
      }
      return files;
    } finally {
      if (fileId !== null) {
        await smb3.close(treeId, fileId);
      }
      await smb3.disconnectTree(treeId);
    }
  }

  async rename(shareName: string, oldPath: string, newPath: string): Promise<void> {
    if (this.getDialect() === SMB1_DIALECT) {
      await (this._SMBConnection as SMB).rename(shareName, oldPath, newPath);
    } else {
      throw new Error('rename not yet implemented for SMB3');
    }
  }

  async reconnect(): Promise<boolean> {
    const creds = this.getCredentials();
    await this.negotiateSession(this._preferredDialect);
    if (this._doKerberos) {
      await this.kerberosLogin(
        creds.user,
        creds.password,
        creds.domain,
        creds.lmhash,
        creds.nthash,
        creds.aesKey,
        this._kdcHost,
        creds.tgt as krb5.KerberosV5.TGTResult | null,
        creds.tgs as krb5.KerberosV5.TGSResult | null,
      );
    } else {
      await this.login(
        creds.user,
        creds.password,
        creds.domain,
        creds.lmhash,
        creds.nthash,
        this._ntlmFallback,
      );
    }
    return true;
  }

  setTimeout(timeout: number): void {
    this._timeout = timeout;
    if (isSMB1(this._SMBConnection)) {
      this._SMBConnection.setTimeout(timeout);
    } else {
      this._SMBConnection.setTimeout(timeout);
    }
  }

  getSessionKey(): Buffer {
    if (this.getDialect() === SMB1_DIALECT) {
      return (this._SMBConnection as SMB).getSessionKey();
    }
    return (this._SMBConnection as SMB3).getSessionKey();
  }

  setSessionKey(key: Buffer): void {
    if (this.getDialect() === SMB1_DIALECT) {
      (this._SMBConnection as SMB).setSessionKey(key);
    } else {
      (this._SMBConnection as SMB3).setSessionKey(key);
    }
  }

  setHostnameValidation(validate: boolean, acceptEmpty: boolean, hostname: string): void {
    if (isSMB1(this._SMBConnection)) {
      this._SMBConnection.setHostnameValidation(validate, acceptEmpty, hostname);
    } else {
      this._SMBConnection.setHostnameValidation(validate, acceptEmpty, hostname);
    }
  }

  async close(): Promise<void> {
    try {
      await this.logoff();
    } catch {
      // ignore
    }
    this._SMBConnection.closeSession();
  }

  async getDFSReferral(path: string): Promise<Array<Record<string, unknown>>> {
    if (this.getDialect() === SMB1_DIALECT) {
      throw new SessionError(0xc00000bb);
    }
    const ipcTid = await this.connectTree('IPC$');
    try {
      const request = new REQ_GET_DFS_REFERRAL();
      request.set('MaxReferralLevel', 3);
      request.set(
        'RequestFileName',
        Buffer.concat([Buffer.from(path, 'utf-16le'), Buffer.from([0, 0])]),
      );

      const referralData = await (this._SMBConnection as SMB3).ioctl(
        ipcTid,
        null,
        FSCTL_DFS_GET_REFERRALS,
        SMB2_0_IOCTL_IS_FSCTL,
        request.getData(),
        0,
        4280,
      );
      const [referrals] = parseDfsReferral(referralData);
      return referrals;
    } finally {
      await this.disconnectTree(ipcTid);
    }
  }

  async listSnapshots(tid: number, path: string): Promise<string[]> {
    const dialect = this.getDialect();
    if (
      typeof dialect === 'string' ||
      ![
        SMB2_DIALECT_002,
        SMB2_DIALECT_21,
        SMB2_DIALECT_30,
        SMB2_DIALECT_302,
        SMB2_DIALECT_311,
      ].includes(dialect as number)
    ) {
      throw new SessionError(0xc00000bb);
    }

    const fid = (await this.openFile(
      tid,
      path,
      FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      FILE_SYNCHRONOUS_IO_NONALERT,
      FILE_OPEN,
      0,
    )) as Buffer;
    const smb3 = this._SMBConnection as SMB3;

    let snapshotData: SRV_SNAPSHOT_ARRAY;
    try {
      const raw = await smb3.ioctl(
        tid,
        fid,
        FSCTL_SRV_ENUMERATE_SNAPSHOTS,
        SMB2_0_IOCTL_IS_FSCTL,
        Buffer.alloc(0),
        0,
        16,
      );
      snapshotData = new SRV_SNAPSHOT_ARRAY(raw);
    } catch (e) {
      await this.closeFile(tid, fid);
      throw e;
    }

    if ((snapshotData.get('SnapShotArraySize') as number) >= 52) {
      const raw = await smb3.ioctl(
        tid,
        fid,
        FSCTL_SRV_ENUMERATE_SNAPSHOTS,
        SMB2_0_IOCTL_IS_FSCTL,
        Buffer.alloc(0),
        0,
        (snapshotData.get('SnapShotArraySize') as number) + 12,
      );
      snapshotData = new SRV_SNAPSHOT_ARRAY(raw);
    }

    await this.closeFile(tid, fid);
    const shots = snapshotData.get('SnapShots') as Buffer;
    return shots.toString('utf-16le').split('\x00').filter(Boolean);
  }
}

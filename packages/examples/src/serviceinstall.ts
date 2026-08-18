// Impacket - Collection of TypeScript classes for working with network protocols.
//
// Copyright Fortra, LLC and its affiliated companies
//
// All rights reserved.
//
// This software is provided under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Description:
//   Service Install Helper library used by psexec and smbrelayx.
//   You provide an already established connection and an exefile
//   (or class that mimics a file class) and this will install and
//   execute the service, and then uninstall (install(), uninstall()).
//   It tries to take care as much as possible to leave everything clean.
//
// Author:
//   Alberto Solino (@agsolino)
//   Ported to TypeScript
//

import { Buffer } from 'node:buffer';
import { readFile } from 'node:fs/promises';
import { info, critical, debug } from './logger.js';
import { SMBConnection } from '@impacket/smb-connection';
import {
  SMBTransport,
  MSRPC_UUID_SCMR,
  MSRPC_UUID_SRVS,
  hNetrShareEnum,
  hROpenSCManagerW,
  hROpenServiceW,
  hRCreateServiceW,
  hRStartServiceW,
  hRDeleteService,
  hRControlService,
  hRCloseServiceHandle,
  SERVICE_DEMAND_START,
  SERVICE_CONTROL_STOP,
  SERVICE_WIN32_OWN_PROCESS,
  SERVICE_ALL_ACCESS,
  SERVICE_ERROR_IGNORE,
  STYPE_DISKTREE,
  STYPE_SPECIAL,
  type DCERPC_v5,
  type ScRpcHandle,
} from '@impacket/dcerpc';
import {
  FILE_WRITE_DATA,
  FILE_DIRECTORY_FILE,
} from '@impacket/smb3';

/** Something that can be read like a file -- either a Buffer or a path string. */
export type ExeFileInput = Buffer | string;

function randomString(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(Math.random() * chars.length)]!;
  }
  return result;
}

export class ServiceInstall {
  private connection: SMBConnection;
  private rpcsvc!: DCERPC_v5;
  private _rpctransport!: SMBTransport;
  private _serviceName: string;
  private _binaryServiceName: string;
  private _exeFile: ExeFileInput;
  private _share = '';

  constructor(
    smbObject: SMBConnection,
    exeFile: ExeFileInput,
    serviceName = '',
    binaryServiceName: string | null = null,
  ) {
    this.connection = smbObject;
    this._exeFile = exeFile;
    this._serviceName = serviceName.length > 0 ? serviceName : randomString(4);
    this._binaryServiceName = binaryServiceName ?? randomString(8) + '.exe';
  }

  get serviceName(): string {
    return this._serviceName;
  }

  get binaryServiceName(): string {
    return this._binaryServiceName;
  }

  getShare(): string {
    return this._share;
  }

  async getShares(): Promise<unknown[]> {
    info(`Requesting shares on ${this.connection.getRemoteHost()}...`);
    try {
      this._rpctransport = new SMBTransport(
        this.connection.getRemoteHost(),
        445,
        '\\srvsvc',
        '', '', '', '', '',
        null, null, null,
        this.connection.getRemoteHost(),
        this.connection,
      );
      const dceSrvs = this._rpctransport.getDceRpc();
      await dceSrvs.connect();
      await dceSrvs.bind(MSRPC_UUID_SRVS);
      const resp = await hNetrShareEnum(dceSrvs, 1);
      const infoStruct = (resp as any).get('InfoStruct');
      const shareInfo = infoStruct.get('ShareInfo');
      const level1 = shareInfo.get('Level1');
      return level1.get('Buffer') as unknown[];
    } catch {
      critical(`Error requesting shares on ${this.connection.getRemoteHost()}, aborting...`);
      throw new Error(`Error requesting shares on ${this.connection.getRemoteHost()}`);
    }
  }

  async createService(handle: ScRpcHandle, _share: string, path: string): Promise<ScRpcHandle> {
    info(`Creating service ${this._serviceName} on ${this.connection.getRemoteHost()}...`);

    // First try to open the service in case it exists. If it does, remove it.
    try {
      const resp = await hROpenServiceW(this.rpcsvc, handle, this._serviceName + '\x00');
      // It exists, remove it
      await hRDeleteService(this.rpcsvc, resp.get('lpServiceHandle') as ScRpcHandle);
      await hRCloseServiceHandle(this.rpcsvc, resp.get('lpServiceHandle') as ScRpcHandle);
    } catch (e: unknown) {
      const msg = String(e);
      if (!msg.includes('ERROR_SERVICE_DOES_NOT_EXIST') && !msg.includes('0x424')) {
        throw e;
      }
    }

    // Create the service
    const command = `${path}\\${this._binaryServiceName}`;
    try {
      const resp = await hRCreateServiceW(
        this.rpcsvc,
        handle,
        this._serviceName + '\x00',
        this._serviceName + '\x00',
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        command + '\x00',
      );
      return resp.get('lpServiceHandle') as ScRpcHandle;
    } catch {
      critical(`Error creating service ${this._serviceName} on ${this.connection.getRemoteHost()}`);
      throw new Error(`Error creating service ${this._serviceName}`);
    }
  }

  async openSvcManager(): Promise<ScRpcHandle> {
    info(`Opening SVCManager on ${this.connection.getRemoteHost()}...`);
    this._rpctransport = new SMBTransport(
      this.connection.getRemoteHost(),
      445,
      '\\svcctl',
      '', '', '', '', '',
      null, null, null,
      this.connection.getRemoteHost(),
      this.connection,
    );
    this.rpcsvc = this._rpctransport.getDceRpc();
    await this.rpcsvc.connect();
    await this.rpcsvc.bind(MSRPC_UUID_SCMR);
    try {
      const resp = await hROpenSCManagerW(this.rpcsvc);
      return resp.get('lpScHandle') as ScRpcHandle;
    } catch {
      critical(`Error opening SVCManager on ${this.connection.getRemoteHost()}...`);
      throw new Error('Unable to open SVCManager');
    }
  }

  async copyFile(src: ExeFileInput, tree: string, dst: string): Promise<void> {
    info(`Uploading file ${dst}`);
    let data: Buffer;
    if (typeof src === 'string') {
      data = await readFile(src);
    } else {
      data = src;
    }
    const pathname = dst.replace(/\//g, '\\');
    try {
      const tid = await this.connection.connectTree(tree);
      const fid = await this.connection.createFile(tid, pathname);
      await this.connection.writeFile(tid, fid, data);
      await this.connection.closeFile(tid, fid);
      await this.connection.disconnectTree(tid);
    } catch {
      critical(`Error uploading file ${dst}, aborting...`);
      throw new Error(`Error uploading file ${dst}`);
    }
  }

  async findWritableShare(shares: unknown[]): Promise<string | null> {
    let writeableShare: string | null = null;
    for (const item of shares) {
      const i = item as any;
      const shareType = (typeof i.get === 'function' ? i.get('shi1_type') : i.fields?.['shi1_type']) as number;
      if (shareType === STYPE_DISKTREE || shareType === STYPE_SPECIAL) {
        const rawName = (typeof i.get === 'function' ? i.get('shi1_netname') : i.fields?.['shi1_netname']) as string;
        const share = rawName.endsWith('\x00') ? rawName.slice(0, -1) : rawName;
        let tid = 0;
        try {
          tid = await this.connection.connectTree(share);
          await this.connection.openFile(tid, '\\', FILE_WRITE_DATA, undefined, FILE_DIRECTORY_FILE);
        } catch {
          debug(`share '${share}' is not writable.`);
          continue;
        } finally {
          if (tid !== 0) {
            try { await this.connection.disconnectTree(tid); } catch { /* ignore */ }
          }
        }
        info(`Found writable share ${share}`);
        writeableShare = share;
        break;
      }
    }
    return writeableShare;
  }

  async install(): Promise<boolean> {
    if (this.connection.isGuestSession()) {
      critical('Authenticated as Guest. Aborting');
      await this.connection.logoff();
      return false;
    }

    let fileCopied = false;
    let serviceCreated = false;
    let service!: ScRpcHandle;

    try {
      // Get the shares
      const shares = await this.getShares();
      const share = await this.findWritableShare(shares);
      if (share === null) {
        return false;
      }
      this._share = share;
      await this.copyFile(this._exeFile, this._share, this._binaryServiceName);
      fileCopied = true;

      const svcManager = await this.openSvcManager();
      const serverName = this.connection.getServerName();
      let path: string;
      if (this._share.toLowerCase() === 'admin$') {
        path = '%systemroot%';
      } else {
        if (serverName !== '') {
          path = `\\\\${serverName}\\${this._share}`;
        } else {
          path = `\\\\127.0.0.1\\${this._share}`;
        }
      }
      service = await this.createService(svcManager, this._share, path);
      serviceCreated = true;

      // Start service
      info(`Starting service ${this._serviceName}...`);
      try {
        await hRStartServiceW(this.rpcsvc, service);
      } catch {
        // Expected -- service may exit quickly
      }
      await hRCloseServiceHandle(this.rpcsvc, service);
      await hRCloseServiceHandle(this.rpcsvc, svcManager);
      return true;
    } catch (e: unknown) {
      critical(`Error performing the installation, cleaning up: ${e}`);
      try { await hRControlService(this.rpcsvc, service, SERVICE_CONTROL_STOP); } catch { /* ignore */ }
      if (fileCopied) {
        try { await this.connection.deleteFile(this._share, this._binaryServiceName); } catch { /* ignore */ }
      }
      if (serviceCreated) {
        try { await hRDeleteService(this.rpcsvc, service); } catch { /* ignore */ }
      }
      return false;
    }
  }

  async uninstall(): Promise<void> {
    let service!: ScRpcHandle;
    try {
      const svcManager = await this.openSvcManager();
      const resp = await hROpenServiceW(this.rpcsvc, svcManager, this._serviceName + '\x00');
      service = resp.get('lpServiceHandle') as ScRpcHandle;

      info(`Stopping service ${this._serviceName}...`);
      try {
        await hRControlService(this.rpcsvc, service, SERVICE_CONTROL_STOP);
      } catch {
        // ignore
      }

      info(`Removing service ${this._serviceName}...`);
      await hRDeleteService(this.rpcsvc, service);
      await hRCloseServiceHandle(this.rpcsvc, service);
      await hRCloseServiceHandle(this.rpcsvc, svcManager);

      info(`Removing file ${this._binaryServiceName}...`);
      await this.connection.deleteFile(this._share, this._binaryServiceName);
    } catch {
      critical('Error performing the uninstallation, cleaning up');
      try { await hRControlService(this.rpcsvc, service, SERVICE_CONTROL_STOP); } catch { /* ignore */ }
      try { await this.connection.deleteFile(this._share, this._binaryServiceName); } catch { /* ignore */ }
      try { await hRDeleteService(this.rpcsvc, service); } catch { /* ignore */ }
    }
  }
}

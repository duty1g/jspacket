import { uuidtupToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRPOINTER,
  NDRUniConformantArray,
  NDRUniVaryingArray,
  NULL,
  type NDRField,
} from './ndr';
import {
  WSTR,
  DWORD,
  LPWSTR,
  ULONG,
  LARGE_INTEGER,
  WORD,
  BYTE,
  UUID,
} from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_EVEN6 = uuidtupToBin([
  'F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C',
  '1.0',
]);

class DCERPCSessionError extends DCERPCException {
  toString(): string {
    return `EVEN6 SessionError: code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

function checkNullString(str: string | typeof NULL): string | typeof NULL {
  if (str === NULL) return str;
  if (typeof str !== 'string') return str;
  if (str.length === 0 || str[str.length - 1] !== '\x00') return str + '\x00';
  return str;
}

// Constants

export const EvtQueryChannelName = 0x00000001;
export const EvtQueryFilePath = 0x00000002;
export const EvtQueryTolerateQueryErrors = 0x00001000;
export const EvtReadOldestToNewest = 0x00000100;
export const EvtReadNewestToOldest = 0x00000200;

// Structures

export class handle_t extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['context_handle_attributes', ULONG],
    ['context_handle_uuid', UUID],
  ];

  constructor(data?: Buffer | null, isNDR64: boolean = false) {
    super(data, isNDR64);
    if (!data) {
      this.set('context_handle_uuid', Buffer.alloc(16, 0));
    }
  }

  isNull(): boolean {
    const uuid = this.get('context_handle_uuid') as Buffer;
    return Buffer.isBuffer(uuid) && uuid.equals(Buffer.alloc(16, 0));
  }
}

export const CONTEXT_HANDLE_LOG_HANDLE = handle_t;

export class PCONTEXT_HANDLE_LOG_HANDLE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', handle_t]];
}

export const CONTEXT_HANDLE_LOG_QUERY = handle_t;

export class PCONTEXT_HANDLE_LOG_QUERY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', handle_t]];
}

export class LPPCONTEXT_HANDLE_LOG_QUERY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', PCONTEXT_HANDLE_LOG_QUERY]];
}

export const CONTEXT_HANDLE_OPERATION_CONTROL = handle_t;

export class PCONTEXT_HANDLE_OPERATION_CONTROL extends NDRPOINTER {
  static referent: NDRField[] = [['Data', handle_t]];
}

// 2.2.11 EvtRpcQueryChannelInfo
export class EvtRpcQueryChannelInfoStruct extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Name', LPWSTR],
    ['Status', DWORD],
  ];
}

export class EvtRpcQueryChannelInfoArray extends NDRUniVaryingArray {
  static item = EvtRpcQueryChannelInfoStruct;
}

export class LPEvtRpcQueryChannelInfoArray extends NDRPOINTER {
  static referent: NDRField[] = [['Data', EvtRpcQueryChannelInfoArray]];
}

export class RPC_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Error', DWORD],
    ['SubError', DWORD],
    ['SubErrorParam', DWORD],
  ];
}

export class PRPC_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RPC_INFO]];
}

class WSTR_ARRAY extends NDRUniVaryingArray {
  static item = WSTR;
}

class DWORD_ARRAY extends NDRUniVaryingArray {
  static item = DWORD;
}

class LPDWORD_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DWORD_ARRAY]];
}

class BYTE_ARRAY extends NDRUniVaryingArray {
  static item = 'c';
}

class CBYTE_ARRAY extends NDRUniVaryingArray {
  static item = BYTE;
}

class CDWORD_ARRAY extends NDRUniConformantArray {
  static item = DWORD;
}

class LPBYTE_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', CBYTE_ARRAY]];
}

class ULONG_ARRAY extends NDRUniVaryingArray {
  static item = ULONG;
}

// 2.3.1 EVENT_DESCRIPTOR
export class EVENT_DESCRIPTOR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Id', WORD],
    ['Version', BYTE],
    ['Channel', BYTE],
    ['LevelSeverity', BYTE],
    ['Opcode', BYTE],
    ['Task', WORD],
    ['Keyword', ULONG],
  ];
}

export class BOOKMARK extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['BookmarkSize', DWORD],
    ['HeaderSize', '<L=0x18'],
    ['ChannelSize', DWORD],
    ['CurrentChannel', DWORD],
    ['ReadDirection', DWORD],
    ['RecordIdsOffset', DWORD],
    ['LogRecordNumbers', ULONG_ARRAY],
  ];
}

// 2.2.17 RESULT_SET
export class RESULT_SET extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['TotalSize', DWORD],
    ['HeaderSize', DWORD],
    ['EventOffset', DWORD],
    ['BookmarkOffset', DWORD],
    ['BinXmlSize', DWORD],
    ['EventData', BYTE_ARRAY],
  ];
}

// RPC CALLS

export class EvtRpcRegisterControllableOperationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Handle', handle_t],
    ['Error', DWORD],
  ];
}

export class EvtRpcRegisterControllableOperation extends NDRCALL {
  static opnum = 4;
  static Response = EvtRpcRegisterControllableOperationResponse;
  static structure: NDRField[] = [];
}

export class EvtRpcRegisterLogQueryResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Handle', handle_t],
    ['OpControl', handle_t],
    ['QueryChannelInfoSize', DWORD],
    ['QueryChannelInfo', EvtRpcQueryChannelInfoArray],
    ['Error', RPC_INFO],
  ];
}

export class EvtRpcRegisterLogQuery extends NDRCALL {
  static opnum = 5;
  static Response = EvtRpcRegisterLogQueryResponse;
  static structure: NDRField[] = [
    ['Path', LPWSTR],
    ['Query', WSTR],
    ['Flags', DWORD],
  ];
}

export class EvtRpcClearLogResponse extends NDRCALL {
  static structure: NDRField[] = [['Error', RPC_INFO]];
}

export class EvtRpcClearLog extends NDRCALL {
  static opnum = 6;
  static Response = EvtRpcClearLogResponse;
  static structure: NDRField[] = [
    ['Handle', handle_t],
    ['ChannelPath', WSTR],
    ['BackupPath', WSTR],
    ['Flags', DWORD],
  ];
}

export class EvtRpcExportLogResponse extends NDRCALL {
  static structure: NDRField[] = [['Error', RPC_INFO]];
}

export class EvtRpcExportLog extends NDRCALL {
  static opnum = 7;
  static Response = EvtRpcExportLogResponse;
  static structure: NDRField[] = [
    ['Handle', handle_t],
    ['ChannelPath', WSTR],
    ['Query', WSTR],
    ['BackupPath', WSTR],
    ['Flags', DWORD],
  ];
}

export class EvtRpcQueryNextResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['NumActualRecords', DWORD],
    ['EventDataIndices', DWORD_ARRAY],
    ['EventDataSizes', DWORD_ARRAY],
    ['ResultBufferSize', DWORD],
    ['ResultBuffer', BYTE_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class EvtRpcQueryNext extends NDRCALL {
  static opnum = 11;
  static Response = EvtRpcQueryNextResponse;
  static structure: NDRField[] = [
    ['LogQuery', handle_t],
    ['NumRequestedRecords', DWORD],
    ['TimeOutEnd', DWORD],
    ['Flags', DWORD],
  ];
}

export class EvtRpcQuerySeekResponse extends NDRCALL {
  static structure: NDRField[] = [['Error', RPC_INFO]];
}

export class EvtRpcQuerySeek extends NDRCALL {
  static opnum = 12;
  static Response = EvtRpcQuerySeekResponse;
  static structure: NDRField[] = [
    ['LogQuery', handle_t],
    ['Pos', LARGE_INTEGER],
    ['BookmarkXML', LPWSTR],
    ['Flags', DWORD],
  ];
}

export class EvtRpcCloseResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Handle', PCONTEXT_HANDLE_LOG_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class EvtRpcClose extends NDRCALL {
  static opnum = 13;
  static Response = EvtRpcCloseResponse;
  static structure: NDRField[] = [['Handle', handle_t]];
}

export class EvtRpcOpenLogHandleResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Handle', PCONTEXT_HANDLE_LOG_HANDLE],
    ['Error', RPC_INFO],
  ];
}

export class EvtRpcOpenLogHandle extends NDRCALL {
  static opnum = 17;
  static Response = EvtRpcOpenLogHandleResponse;
  static structure: NDRField[] = [
    ['Channel', WSTR],
    ['Flags', DWORD],
  ];
}

export class EvtRpcGetChannelListResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['NumChannelPaths', DWORD],
    ['ChannelPaths', WSTR_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class EvtRpcGetChannelList extends NDRCALL {
  static opnum = 19;
  static Response = EvtRpcGetChannelListResponse;
  static structure: NDRField[] = [['Flags', DWORD]];
}

const OPNUMS: Record<number, [typeof NDRCALL, typeof NDRCALL]> = {
  4: [EvtRpcRegisterControllableOperation, EvtRpcRegisterControllableOperationResponse],
  5: [EvtRpcRegisterLogQuery, EvtRpcRegisterLogQueryResponse],
  6: [EvtRpcClearLog, EvtRpcClearLogResponse],
  7: [EvtRpcExportLog, EvtRpcExportLogResponse],
  11: [EvtRpcQueryNext, EvtRpcQueryNextResponse],
  12: [EvtRpcQuerySeek, EvtRpcQuerySeekResponse],
  13: [EvtRpcClose, EvtRpcCloseResponse],
  17: [EvtRpcOpenLogHandle, EvtRpcOpenLogHandleResponse],
  19: [EvtRpcGetChannelList, EvtRpcGetChannelListResponse],
};

type DceRequestFn = <T>(
  req: unknown,
  uuid?: unknown,
  checkError?: boolean,
) => Promise<T>;

export async function hEvtRpcRegisterControllableOperation(
  dce: DCERPC_v5,
): Promise<EvtRpcRegisterControllableOperationResponse> {
  const request = new EvtRpcRegisterControllableOperation();
  return (dce as unknown as { request: DceRequestFn }).request<EvtRpcRegisterControllableOperationResponse>(
    request,
  );
}

export async function hEvtRpcRegisterLogQuery(
  dce: DCERPC_v5,
  path: string,
  flags: number,
  query: string = '*\x00',
): Promise<EvtRpcRegisterLogQueryResponse> {
  const request = new EvtRpcRegisterLogQuery();
  request.set('Path', checkNullString(path));
  request.set('Query', checkNullString(query));
  request.set('Flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<EvtRpcRegisterLogQueryResponse>(
    request,
  );
}

export async function hEvtRpcClearLog(
  dce: DCERPC_v5,
  handle: unknown,
  path: string,
  backupPath: string | typeof NULL = NULL,
): Promise<EvtRpcClearLogResponse> {
  const request = new EvtRpcClearLog();
  request.set('Handle', handle);
  request.set('ChannelPath', checkNullString(path));
  request.set('BackupPath', checkNullString(backupPath));
  request.set('Flags', 0);
  return (dce as unknown as { request: DceRequestFn }).request<EvtRpcClearLogResponse>(request);
}

export async function hEvtRpcExportLog(
  dce: DCERPC_v5,
  handle: unknown,
  channelPath: string,
  query: string,
  backupPath: string,
): Promise<EvtRpcExportLogResponse> {
  const request = new EvtRpcExportLog();
  request.set('Handle', handle);
  request.set('ChannelPath', checkNullString(channelPath));
  request.set('Query', checkNullString(query));
  request.set('BackupPath', checkNullString(backupPath));
  request.set('Flags', 0);
  return (dce as unknown as { request: DceRequestFn }).request<EvtRpcExportLogResponse>(request);
}

export async function hEvtRpcQueryNext(
  dce: DCERPC_v5,
  handle: unknown,
  numRequestedRecords: number,
  timeOutEnd: number = 1000,
): Promise<EvtRpcQueryNextResponse> {
  const request = new EvtRpcQueryNext();
  request.set('LogQuery', handle);
  request.set('NumRequestedRecords', numRequestedRecords);
  request.set('TimeOutEnd', timeOutEnd);
  request.set('Flags', 0);
  return (dce as unknown as { request: DceRequestFn }).request<EvtRpcQueryNextResponse>(request);
}

export async function hEvtRpcClose(
  dce: DCERPC_v5,
  handle: unknown,
): Promise<EvtRpcCloseResponse> {
  const request = new EvtRpcClose();
  request.set('Handle', handle);
  return (dce as unknown as { request: DceRequestFn }).request<EvtRpcCloseResponse>(request);
}

export async function hEvtRpcOpenLogHandle(
  dce: DCERPC_v5,
  channel: string,
  flags: number,
): Promise<EvtRpcOpenLogHandleResponse> {
  const request = new EvtRpcOpenLogHandle();
  request.set('Channel', checkNullString(channel));
  request.set('Flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<EvtRpcOpenLogHandleResponse>(
    request,
  );
}

export async function hEvtRpcGetChannelList(
  dce: DCERPC_v5,
): Promise<EvtRpcGetChannelListResponse> {
  const request = new EvtRpcGetChannelList();
  request.set('Flags', 0);
  return (dce as unknown as { request: DceRequestFn }).request<EvtRpcGetChannelListResponse>(
    request,
  );
}

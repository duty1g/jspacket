import { uuidtupToBin } from '@impacket/uuid';
import { Structure, type FieldDescriptor } from '@impacket/structure';
import {
  NDRCALL,
  NDRSTRUCT,
  NDR,
  NDRPOINTER,
  NDRUniConformantArray,
  NULL,
  type NDRField,
} from './ndr';
import {
  ULONG,
  LPWSTR,
  RPC_UNICODE_STRING,
  LPSTR,
  NTSTATUS,
  PRPC_UNICODE_STRING,
  PULONG,
  USHORT,
  PRPC_SID,
  LPBYTE,
} from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_EVEN = uuidtupToBin([
  '82273FDC-E32A-18C3-3F78-827929DC23EA',
  '0.0',
]);

class DCERPCSessionError extends DCERPCException {
  toString(): string {
    return `EVEN SessionError: code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

// 2.2.2 EventType
export const EVENTLOG_SUCCESS = 0x0000;
export const EVENTLOG_ERROR_TYPE = 0x0001;
export const EVENTLOG_WARNING_TYPE = 0x0002;
export const EVENTLOG_INFORMATION_TYPE = 0x0004;
export const EVENTLOG_AUDIT_SUCCESS = 0x0008;
export const EVENTLOG_AUDIT_FAILURE = 0x0010;

export const EVENTLOG_HANDLE_W = LPWSTR;

// 2.2.9 Constants
export const MAX_STRINGS = 0x00000100;
export const MAX_SINGLE_EVENT = 0x0003ffff;
export const MAX_BATCH_BUFF = 0x0007ffff;

// 3.1.4.7 ElfrReadELW flags
export const EVENTLOG_SEQUENTIAL_READ = 0x00000001;
export const EVENTLOG_SEEK_READ = 0x00000002;
export const EVENTLOG_FORWARDS_READ = 0x00000004;
export const EVENTLOG_BACKWARDS_READ = 0x00000008;

// 2.2.7 IELF_HANDLE
export class IELF_HANDLE extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '20s=""']];
  getAlignment(): number {
    return 1;
  }
}

// 2.2.3 EVENTLOGRECORD
export class EVENTLOGRECORD extends Structure {
  static structure: FieldDescriptor[] = [
    ['Length', '<L=0'],
    ['Reserved', '<L=0'],
    ['RecordNumber', '<L=0'],
    ['TimeGenerated', '<L=0'],
    ['TimeWritten', '<L=0'],
    ['EventID', '<L=0'],
    ['EventType', '<H=0'],
    ['NumStrings', '<H=0'],
    ['EventCategory', '<H=0'],
    ['ReservedFlags', '<H=0'],
    ['ClosingRecordNumber', '<L=0'],
    ['StringOffset', '<L=0'],
    ['UserSidLength', '<L=0'],
    ['UserSidOffset', '<L=0'],
    ['DataLength', '<L=0'],
    ['DataOffset', '<L=0'],
    ['SourceName', 'z'],
    ['Computername', 'z'],
    ['UserSidPadding', ':'],
    ['_UserSid', '_-UserSid', 'self["UserSidLength"]'],
    ['UserSid', ':'],
    ['Strings', ':'],
    ['_Data', '_-Data', 'self["DataLength"]'],
    ['Data', ':'],
    ['Padding', ':'],
    ['Length2', '<L=0'],
  ];
}

// 2.2.4 EVENTLOG_FULL_INFORMATION
export class EVENTLOG_FULL_INFORMATION extends NDRSTRUCT {
  static structure: NDRField[] = [['dwFull', ULONG]];
}

// 2.2.8 RPC_CLIENT_ID
export class RPC_CLIENT_ID extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['UniqueProcess', ULONG],
    ['UniqueThread', ULONG],
  ];
}

// 2.2.12 RPC_STRING
class RPC_STRING extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', '<H=0'],
    ['MaximumLength', '<H=0'],
    ['Data', LPSTR],
  ];

  set(key: string, value: unknown): void {
    if (key === 'Data' && !(value instanceof NDR)) {
      if (typeof value === 'string') {
        super.set('Length', value.length);
        super.set('MaximumLength', value.length);
      } else if (Buffer.isBuffer(value)) {
        super.set('Length', value.length);
        super.set('MaximumLength', value.length);
      }
    }
    super.set(key, value);
  }
}

class RPC_UNICODE_STRING_ARRAY extends NDRUniConformantArray {
  static item = RPC_UNICODE_STRING;
}

class PRPC_UNICODE_STRING_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RPC_UNICODE_STRING_ARRAY]];
}

// RPC CALLS

// 3.1.4.9 ElfrClearELFW (Opnum 0)
export class ElfrClearELFWResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', NTSTATUS]];
}

export class ElfrClearELFW extends NDRCALL {
  static opnum = 0;
  static Response = ElfrClearELFWResponse;
  static structure: NDRField[] = [
    ['LogHandle', IELF_HANDLE],
    ['BackupFileName', PRPC_UNICODE_STRING],
  ];
}

// 3.1.4.11 ElfrBackupELFW (Opnum 1)
export class ElfrBackupELFWResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', NTSTATUS]];
}

export class ElfrBackupELFW extends NDRCALL {
  static opnum = 1;
  static Response = ElfrBackupELFWResponse;
  static structure: NDRField[] = [
    ['LogHandle', IELF_HANDLE],
    ['BackupFileName', RPC_UNICODE_STRING],
  ];
}

// 3.1.4.21 ElfrCloseEL (Opnum 2)
export class ElfrCloseELResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['LogHandle', IELF_HANDLE],
    ['ErrorCode', NTSTATUS],
  ];
}

export class ElfrCloseEL extends NDRCALL {
  static opnum = 2;
  static Response = ElfrCloseELResponse;
  static structure: NDRField[] = [['LogHandle', IELF_HANDLE]];
}

// 3.1.4.18 ElfrNumberOfRecords (Opnum 4)
export class ElfrNumberOfRecordsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['NumberOfRecords', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class ElfrNumberOfRecords extends NDRCALL {
  static opnum = 4;
  static Response = ElfrNumberOfRecordsResponse;
  static structure: NDRField[] = [['LogHandle', IELF_HANDLE]];
}

// 3.1.4.19 ElfrOldestRecord (Opnum 5)
export class ElfrOldestRecordResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['OldestRecordNumber', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class ElfrOldestRecord extends NDRCALL {
  static opnum = 5;
  static Response = ElfrOldestRecordResponse;
  static structure: NDRField[] = [['LogHandle', IELF_HANDLE]];
}

// 3.1.4.3 ElfrOpenELW (Opnum 7)
export class ElfrOpenELWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['LogHandle', IELF_HANDLE],
    ['ErrorCode', NTSTATUS],
  ];
}

export class ElfrOpenELW extends NDRCALL {
  static opnum = 7;
  static Response = ElfrOpenELWResponse;
  static structure: NDRField[] = [
    ['UNCServerName', LPWSTR],
    ['ModuleName', RPC_UNICODE_STRING],
    ['RegModuleName', RPC_UNICODE_STRING],
    ['MajorVersion', ULONG],
    ['MinorVersion', ULONG],
  ];
}

// 3.1.4.5 ElfrRegisterEventSourceW (Opnum 8)
export class ElfrRegisterEventSourceWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['LogHandle', IELF_HANDLE],
    ['ErrorCode', NTSTATUS],
  ];
}

export class ElfrRegisterEventSourceW extends NDRCALL {
  static opnum = 8;
  static Response = ElfrRegisterEventSourceWResponse;
  static structure: NDRField[] = [
    ['UNCServerName', LPWSTR],
    ['ModuleName', RPC_UNICODE_STRING],
    ['RegModuleName', RPC_UNICODE_STRING],
    ['MajorVersion', ULONG],
    ['MinorVersion', ULONG],
  ];
}

// 3.1.4.1 ElfrOpenBELW (Opnum 9)
export class ElfrOpenBELWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['LogHandle', IELF_HANDLE],
    ['ErrorCode', NTSTATUS],
  ];
}

export class ElfrOpenBELW extends NDRCALL {
  static opnum = 9;
  static Response = ElfrOpenBELWResponse;
  static structure: NDRField[] = [
    ['UNCServerName', LPWSTR],
    ['BackupFileName', RPC_UNICODE_STRING],
    ['MajorVersion', ULONG],
    ['MinorVersion', ULONG],
  ];
}

// 3.1.4.7 ElfrReadELW (Opnum 10)
export class ElfrReadELWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Buffer', NDRUniConformantArray],
    ['NumberOfBytesRead', ULONG],
    ['MinNumberOfBytesNeeded', ULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class ElfrReadELW extends NDRCALL {
  static opnum = 10;
  static Response = ElfrReadELWResponse;
  static structure: NDRField[] = [
    ['LogHandle', IELF_HANDLE],
    ['ReadFlags', ULONG],
    ['RecordOffset', ULONG],
    ['NumberOfBytesToRead', ULONG],
  ];
}

// 3.1.4.13 ElfrReportEventW (Opnum 11)
export class ElfrReportEventWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['RecordNumber', PULONG],
    ['TimeWritten', PULONG],
    ['ErrorCode', NTSTATUS],
  ];
}

export class ElfrReportEventW extends NDRCALL {
  static opnum = 11;
  static Response = ElfrReportEventWResponse;
  static structure: NDRField[] = [
    ['LogHandle', IELF_HANDLE],
    ['Time', ULONG],
    ['EventType', USHORT],
    ['EventCategory', USHORT],
    ['EventID', ULONG],
    ['NumStrings', USHORT],
    ['DataSize', ULONG],
    ['ComputerName', RPC_UNICODE_STRING],
    ['UserSID', PRPC_SID],
    ['Strings', PRPC_UNICODE_STRING_ARRAY],
    ['Data', LPBYTE],
    ['Flags', USHORT],
    ['RecordNumber', PULONG],
    ['TimeWritten', PULONG],
  ];
}

const OPNUMS: Record<number, [typeof NDRCALL, typeof NDRCALL]> = {
  0: [ElfrClearELFW, ElfrClearELFWResponse],
  1: [ElfrBackupELFW, ElfrBackupELFWResponse],
  2: [ElfrCloseEL, ElfrCloseELResponse],
  4: [ElfrNumberOfRecords, ElfrNumberOfRecordsResponse],
  5: [ElfrOldestRecord, ElfrOldestRecordResponse],
  7: [ElfrOpenELW, ElfrOpenELWResponse],
  8: [ElfrRegisterEventSourceW, ElfrRegisterEventSourceWResponse],
  9: [ElfrOpenBELW, ElfrOpenBELWResponse],
  10: [ElfrReadELW, ElfrReadELWResponse],
  11: [ElfrReportEventW, ElfrReportEventWResponse],
};

type DceRequestFn = <T>(
  req: unknown,
  uuid?: unknown,
  checkError?: boolean,
) => Promise<T>;

export async function hElfrOpenBELW(
  dce: DCERPC_v5,
  backupFileName: unknown | typeof NULL = NULL,
): Promise<ElfrOpenBELWResponse> {
  const request = new ElfrOpenBELW();
  request.set('UNCServerName', NULL);
  request.set('BackupFileName', backupFileName);
  request.set('MajorVersion', 1);
  request.set('MinorVersion', 1);
  return (dce as unknown as { request: DceRequestFn }).request<ElfrOpenBELWResponse>(request);
}

export async function hElfrOpenELW(
  dce: DCERPC_v5,
  moduleName: unknown | typeof NULL = NULL,
  regModuleName: unknown | typeof NULL = NULL,
): Promise<ElfrOpenELWResponse> {
  const request = new ElfrOpenELW();
  request.set('UNCServerName', NULL);
  request.set('ModuleName', moduleName);
  request.set('RegModuleName', regModuleName);
  request.set('MajorVersion', 1);
  request.set('MinorVersion', 1);
  return (dce as unknown as { request: DceRequestFn }).request<ElfrOpenELWResponse>(request);
}

export async function hElfrCloseEL(
  dce: DCERPC_v5,
  logHandle: unknown,
): Promise<ElfrCloseELResponse> {
  const request = new ElfrCloseEL();
  request.set('LogHandle', logHandle);
  return (dce as unknown as { request: DceRequestFn }).request<ElfrCloseELResponse>(request);
}

export async function hElfrRegisterEventSourceW(
  dce: DCERPC_v5,
  moduleName: unknown | typeof NULL = NULL,
  regModuleName: unknown | typeof NULL = NULL,
): Promise<ElfrRegisterEventSourceWResponse> {
  const request = new ElfrRegisterEventSourceW();
  request.set('UNCServerName', NULL);
  request.set('ModuleName', moduleName);
  request.set('RegModuleName', regModuleName);
  request.set('MajorVersion', 1);
  request.set('MinorVersion', 1);
  return (dce as unknown as { request: DceRequestFn }).request<ElfrRegisterEventSourceWResponse>(request);
}

export async function hElfrReadELW(
  dce: DCERPC_v5,
  logHandle: unknown = '',
  readFlags: number = EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ,
  recordOffset: number = 0,
  numberOfBytesToRead: number = MAX_BATCH_BUFF,
): Promise<ElfrReadELWResponse> {
  const request = new ElfrReadELW();
  request.set('LogHandle', logHandle);
  request.set('ReadFlags', readFlags);
  request.set('RecordOffset', recordOffset);
  request.set('NumberOfBytesToRead', numberOfBytesToRead);
  return (dce as unknown as { request: DceRequestFn }).request<ElfrReadELWResponse>(request);
}

export async function hElfrClearELFW(
  dce: DCERPC_v5,
  logHandle: unknown = '',
  backupFileName: unknown | typeof NULL = NULL,
): Promise<ElfrClearELFWResponse> {
  const request = new ElfrClearELFW();
  request.set('LogHandle', logHandle);
  request.set('BackupFileName', backupFileName);
  return (dce as unknown as { request: DceRequestFn }).request<ElfrClearELFWResponse>(request);
}

export async function hElfrBackupELFW(
  dce: DCERPC_v5,
  logHandle: unknown = '',
  backupFileName: unknown | typeof NULL = NULL,
): Promise<ElfrBackupELFWResponse> {
  const request = new ElfrBackupELFW();
  request.set('LogHandle', logHandle);
  request.set('BackupFileName', backupFileName);
  return (dce as unknown as { request: DceRequestFn }).request<ElfrBackupELFWResponse>(request);
}

export async function hElfrNumberOfRecords(
  dce: DCERPC_v5,
  logHandle: unknown,
): Promise<ElfrNumberOfRecordsResponse> {
  const request = new ElfrNumberOfRecords();
  request.set('LogHandle', logHandle);
  return (dce as unknown as { request: DceRequestFn }).request<ElfrNumberOfRecordsResponse>(request);
}

export async function hElfrOldestRecordNumber(
  dce: DCERPC_v5,
  logHandle: unknown,
): Promise<ElfrOldestRecordResponse> {
  const request = new ElfrOldestRecord();
  request.set('LogHandle', logHandle);
  return (dce as unknown as { request: DceRequestFn }).request<ElfrOldestRecordResponse>(request);
}

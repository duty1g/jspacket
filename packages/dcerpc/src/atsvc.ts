import { uuidtupToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRPOINTER,
  NDRUniConformantArray,
  NULL,
  type NDRField,
} from './ndr';
import { DWORD, ULONG, UCHAR, LPWSTR, LPDWORD } from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_ATSVC = uuidtupToBin([
  '1FF70682-0A51-30E8-076D-740BE8CEE98B',
  '1.0',
]);

class DCERPCSessionError extends DCERPCException {
  toString(): string {
    return `ATSVC SessionError: code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

// 2.3.1 Constant Values
export const ATSVC_HANDLE = LPWSTR;
const CNLEN = 15;
const DNLEN = CNLEN;
const UNLEN = 256;
const MAX_BUFFER_SIZE = DNLEN + UNLEN + 1 + 1;

// 2.3.7 Flags
const TASK_FLAG_INTERACTIVE = 0x1;
const TASK_FLAG_DELETE_WHEN_DONE = 0x2;
const TASK_FLAG_DISABLED = 0x4;
const TASK_FLAG_START_ONLY_IF_IDLE = 0x10;
const TASK_FLAG_KILL_ON_IDLE_END = 0x20;
const TASK_FLAG_DONT_START_IF_ON_BATTERIES = 0x40;
const TASK_FLAG_KILL_IF_GOING_ON_BATTERIES = 0x80;
const TASK_FLAG_RUN_ONLY_IF_DOCKED = 0x100;
const TASK_FLAG_HIDDEN = 0x200;
const TASK_FLAG_RUN_IF_CONNECTED_TO_INTERNET = 0x400;
const TASK_FLAG_RESTART_ON_IDLE_RESUME = 0x800;
const TASK_FLAG_SYSTEM_REQUIRED = 0x1000;
const TASK_FLAG_RUN_ONLY_IF_LOGGED_ON = 0x2000;

// 2.3.4 AT_INFO
export class AT_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['JobTime', DWORD],
    ['DaysOfMonth', DWORD],
    ['DaysOfWeek', UCHAR],
    ['Flags', UCHAR],
    ['Command', LPWSTR],
  ];
}

export class LPAT_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', AT_INFO]];
}

// 2.3.6 AT_ENUM
export class AT_ENUM extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['JobId', DWORD],
    ['JobTime', DWORD],
    ['DaysOfMonth', DWORD],
    ['DaysOfWeek', UCHAR],
    ['Flags', UCHAR],
    ['Command', LPWSTR],
  ];
}

export class AT_ENUM_ARRAY extends NDRUniConformantArray {
  static item = AT_ENUM;
}

export class LPAT_ENUM_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', AT_ENUM_ARRAY]];
}

// 2.3.5 AT_ENUM_CONTAINER
export class AT_ENUM_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPAT_ENUM_ARRAY],
  ];
}

// 3.2.5.2.1 NetrJobAdd (Opnum 0)
export class NetrJobAddResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pJobId', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class NetrJobAdd extends NDRCALL {
  static opnum = 0;
  static Response = NetrJobAddResponse;
  static structure: NDRField[] = [
    ['ServerName', ATSVC_HANDLE],
    ['pAtInfo', AT_INFO],
  ];
}

// 3.2.5.2.2 NetrJobDel (Opnum 1)
export class NetrJobDelResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrJobDel extends NDRCALL {
  static opnum = 1;
  static Response = NetrJobDelResponse;
  static structure: NDRField[] = [
    ['ServerName', ATSVC_HANDLE],
    ['MinJobId', DWORD],
    ['MaxJobId', DWORD],
  ];
}

// 3.2.5.2.3 NetrJobEnum (Opnum 2)
export class NetrJobEnumResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pEnumContainer', AT_ENUM_CONTAINER],
    ['pTotalEntries', DWORD],
    ['pResumeHandle', LPDWORD],
    ['ErrorCode', ULONG],
  ];
}

export class NetrJobEnum extends NDRCALL {
  static opnum = 2;
  static Response = NetrJobEnumResponse;
  static structure: NDRField[] = [
    ['ServerName', ATSVC_HANDLE],
    ['pEnumContainer', AT_ENUM_CONTAINER],
    ['PreferedMaximumLength', DWORD],
    ['pResumeHandle', LPDWORD],
  ];
}

// 3.2.5.2.4 NetrJobGetInfo (Opnum 3)
export class NetrJobGetInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppAtInfo', LPAT_INFO],
    ['ErrorCode', ULONG],
  ];
}

export class NetrJobGetInfo extends NDRCALL {
  static opnum = 3;
  static Response = NetrJobGetInfoResponse;
  static structure: NDRField[] = [
    ['ServerName', ATSVC_HANDLE],
    ['JobId', DWORD],
  ];
}

const OPNUMS: Record<number, [typeof NDRCALL, typeof NDRCALL]> = {
  0: [NetrJobAdd, NetrJobAddResponse],
  1: [NetrJobDel, NetrJobDelResponse],
  2: [NetrJobEnum, NetrJobEnumResponse],
  3: [NetrJobGetInfo, NetrJobGetInfoResponse],
};

type DceRequestFn = <T>(
  req: unknown,
  uuid?: unknown,
  checkError?: boolean,
) => Promise<T>;

export async function hNetrJobAdd(
  dce: DCERPC_v5,
  serverName: string | typeof NULL = NULL,
  atInfo: AT_INFO | typeof NULL = NULL,
): Promise<NetrJobAddResponse> {
  const request = new NetrJobAdd();
  request.set('ServerName', serverName);
  request.set('pAtInfo', atInfo);
  return (dce as unknown as { request: DceRequestFn }).request<NetrJobAddResponse>(
    request,
  );
}

export async function hNetrJobDel(
  dce: DCERPC_v5,
  serverName: string | typeof NULL = NULL,
  minJobId: number = 0,
  maxJobId: number = 0,
): Promise<NetrJobDelResponse> {
  const request = new NetrJobDel();
  request.set('ServerName', serverName);
  request.set('MinJobId', minJobId);
  request.set('MaxJobId', maxJobId);
  return (dce as unknown as { request: DceRequestFn }).request<NetrJobDelResponse>(
    request,
  );
}

export async function hNetrJobEnum(
  dce: DCERPC_v5,
  serverName: string | typeof NULL = NULL,
  pEnumContainer: typeof NULL = NULL,
  preferedMaximumLength: number = 0xffffffff,
): Promise<NetrJobEnumResponse> {
  const request = new NetrJobEnum();
  request.set('ServerName', serverName);
  (request.fields['pEnumContainer'] as AT_ENUM_CONTAINER).set(
    'Buffer',
    pEnumContainer,
  );
  request.set('PreferedMaximumLength', preferedMaximumLength);
  return (dce as unknown as { request: DceRequestFn }).request<NetrJobEnumResponse>(
    request,
  );
}

export async function hNetrJobGetInfo(
  dce: DCERPC_v5,
  serverName: string | typeof NULL = NULL,
  jobId: number = 0,
): Promise<NetrJobGetInfoResponse> {
  const request = new NetrJobGetInfo();
  request.set('ServerName', serverName);
  request.set('JobId', jobId);
  return (dce as unknown as { request: DceRequestFn }).request<NetrJobGetInfoResponse>(
    request,
  );
}

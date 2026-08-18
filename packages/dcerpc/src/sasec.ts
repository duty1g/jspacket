import { uuidtupToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRUniConformantArray,
  NULL,
  type NDRField,
} from './ndr';
import { DWORD, ULONG, LPWSTR, WSTR } from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_SASEC = uuidtupToBin([
  '378E52B0-C0A9-11CF-822D-00AA0051E40F',
  '1.0',
]);

class DCERPCSessionError extends DCERPCException {
  toString(): string {
    return `SASEC SessionError: code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

export const SASEC_HANDLE = WSTR;
export const PSASEC_HANDLE = LPWSTR;

const MAX_BUFFER_SIZE = 273;
const TASK_FLAG_RUN_ONLY_IF_LOGGED_ON = 0x40000;

class WORD_ARRAY extends NDRUniConformantArray {
  static item = '<H';
}

// 3.2.5.3.4 SASetAccountInformation (Opnum 0)
export class SASetAccountInformationResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SASetAccountInformation extends NDRCALL {
  static opnum = 0;
  static Response = SASetAccountInformationResponse;
  static structure: NDRField[] = [
    ['Handle', LPWSTR],
    ['pwszJobName', WSTR],
    ['pwszAccount', WSTR],
    ['pwszPassword', LPWSTR],
    ['dwJobFlags', DWORD],
  ];
}

// 3.2.5.3.5 SASetNSAccountInformation (Opnum 1)
export class SASetNSAccountInformationResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class SASetNSAccountInformation extends NDRCALL {
  static opnum = 1;
  static Response = SASetNSAccountInformationResponse;
  static structure: NDRField[] = [
    ['Handle', LPWSTR],
    ['pwszAccount', LPWSTR],
    ['pwszPassword', LPWSTR],
  ];
}

// 3.2.5.3.6 SAGetNSAccountInformation (Opnum 2)
export class SAGetNSAccountInformationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['wszBuffer', WORD_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class SAGetNSAccountInformation extends NDRCALL {
  static opnum = 2;
  static Response = SAGetNSAccountInformationResponse;
  static structure: NDRField[] = [
    ['Handle', LPWSTR],
    ['ccBufferSize', DWORD],
    ['wszBuffer', WORD_ARRAY],
  ];
}

// 3.2.5.3.7 SAGetAccountInformation (Opnum 3)
export class SAGetAccountInformationResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['wszBuffer', WORD_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class SAGetAccountInformation extends NDRCALL {
  static opnum = 3;
  static Response = SAGetAccountInformationResponse;
  static structure: NDRField[] = [
    ['Handle', LPWSTR],
    ['pwszJobName', WSTR],
    ['ccBufferSize', DWORD],
    ['wszBuffer', WORD_ARRAY],
  ];
}

const OPNUMS: Record<number, [typeof NDRCALL, typeof NDRCALL]> = {
  0: [SASetAccountInformation, SASetAccountInformationResponse],
  1: [SASetNSAccountInformation, SASetNSAccountInformationResponse],
  2: [SAGetNSAccountInformation, SAGetNSAccountInformationResponse],
  3: [SAGetAccountInformation, SAGetAccountInformationResponse],
};

function checkNullString(str: string | typeof NULL): string | typeof NULL {
  if (str === NULL) return str;
  if (typeof str !== 'string') return str;
  if (str.length === 0 || str[str.length - 1] !== '\x00') return str + '\x00';
  return str;
}

type DceRequestFn = <T>(
  req: unknown,
  uuid?: unknown,
  checkError?: boolean,
) => Promise<T>;

export async function hSASetAccountInformation(
  dce: DCERPC_v5,
  handle: string,
  pwszJobName: string,
  pwszAccount: string,
  pwszPassword: string | typeof NULL,
  dwJobFlags: number = 0,
): Promise<SASetAccountInformationResponse> {
  const request = new SASetAccountInformation();
  request.set('Handle', handle);
  request.set('pwszJobName', checkNullString(pwszJobName));
  request.set('pwszAccount', checkNullString(pwszAccount));
  request.set('pwszPassword', checkNullString(pwszPassword));
  request.set('dwJobFlags', dwJobFlags);
  return (dce as unknown as { request: DceRequestFn }).request<SASetAccountInformationResponse>(
    request,
  );
}

export async function hSASetNSAccountInformation(
  dce: DCERPC_v5,
  handle: string,
  pwszAccount: string | typeof NULL,
  pwszPassword: string | typeof NULL,
): Promise<SASetNSAccountInformationResponse> {
  const request = new SASetNSAccountInformation();
  request.set('Handle', handle);
  request.set('pwszAccount', checkNullString(pwszAccount));
  request.set('pwszPassword', checkNullString(pwszPassword));
  return (dce as unknown as { request: DceRequestFn }).request<SASetNSAccountInformationResponse>(
    request,
  );
}

export async function hSAGetNSAccountInformation(
  dce: DCERPC_v5,
  handle: string,
  ccBufferSize: number = MAX_BUFFER_SIZE,
): Promise<SAGetNSAccountInformationResponse> {
  const request = new SAGetNSAccountInformation();
  request.set('Handle', handle);
  request.set('ccBufferSize', ccBufferSize);
  request.set('wszBuffer', new Array(ccBufferSize).fill(0));
  return (dce as unknown as { request: DceRequestFn }).request<SAGetNSAccountInformationResponse>(
    request,
  );
}

export async function hSAGetAccountInformation(
  dce: DCERPC_v5,
  handle: string,
  pwszJobName: string,
  ccBufferSize: number = MAX_BUFFER_SIZE,
): Promise<SAGetAccountInformationResponse> {
  const request = new SAGetAccountInformation();
  request.set('Handle', handle);
  request.set('pwszJobName', checkNullString(pwszJobName));
  request.set('ccBufferSize', ccBufferSize);
  request.set('wszBuffer', new Array(ccBufferSize).fill(0));
  return (dce as unknown as { request: DceRequestFn }).request<SAGetAccountInformationResponse>(
    request,
  );
}

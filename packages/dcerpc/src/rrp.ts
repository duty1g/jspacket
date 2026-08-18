import { Buffer } from 'node:buffer';
import { structPack, structUnpack } from '@impacket/structure';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRPOINTER,
  NDRUniConformantVaryingArray,
  NDRUniConformantArray,
  NDRField,
  NULL,
} from './ndr';
import {
  DWORD,
  UUID,
  ULONG,
  LPULONG,
  BOOLEAN,
  SECURITY_INFORMATION,
  PFILETIME,
  RPC_UNICODE_STRING,
  FILETIME,
  MAXIMUM_ALLOWED,
  OWNER_SECURITY_INFORMATION,
  PWCHAR,
  PRPC_UNICODE_STRING,
} from './dtypes';
import { DCERPCException } from './rpcrt';
import { uuidtupToBin } from '@impacket/uuid';

export const MSRPC_UUID_RRP = uuidtupToBin(['338CD001-2244-31F1-AAAA-900038001003', '1.0'])!;

export class RRP_DCERPCSessionError extends DCERPCException {}

export const PREGISTRY_SERVER_NAME = PWCHAR;
export const error_status_t = ULONG;
export const RRP_UNICODE_STRING = RPC_UNICODE_STRING;
export const PRRP_UNICODE_STRING = PRPC_UNICODE_STRING;
export const REGSAM = ULONG;

export const KEY_QUERY_VALUE = 0x00000001;
export const KEY_SET_VALUE = 0x00000002;
export const KEY_CREATE_SUB_KEY = 0x00000004;
export const KEY_ENUMERATE_SUB_KEYS = 0x00000008;
export const KEY_CREATE_LINK = 0x00000020;
export const KEY_WOW64_64KEY = 0x00000100;
export const KEY_WOW64_32KEY = 0x00000200;
export const KEY_READ = 0x00020019;

export const REG_BINARY = 3;
export const REG_DWORD = 4;
export const REG_DWORD_LITTLE_ENDIAN = 4;
export const REG_DWORD_BIG_ENDIAN = 5;
export const REG_EXPAND_SZ = 2;
export const REG_LINK = 6;
export const REG_MULTI_SZ = 7;
export const REG_NONE = 0;
export const REG_QWORD = 11;
export const REG_QWORD_LITTLE_ENDIAN = 11;
export const REG_SZ = 1;

export const REG_OPTION_BACKUP_RESTORE = 0x00000004;
export const REG_OPTION_OPEN_LINK = 0x00000008;

export const REG_CREATED_NEW_KEY = 0x00000001;
export const REG_OPENED_EXISTING_KEY = 0x00000002;

export const REG_WHOLE_HIVE_VOLATILE = 0x00000001;
export const REG_REFRESH_HIVE = 0x00000002;
export const REG_NO_LAZY_FLUSH = 0x00000004;
export const REG_FORCE_RESTORE = 0x00000008;

export const ERROR_MORE_DATA = 0xea;

export class RPC_HKEY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['context_handle_attributes', ULONG],
    ['context_handle_uuid', UUID],
  ];

  constructor(data?: Buffer | null, isNDR64 = false) {
    super(data, isNDR64);
    this.set('context_handle_uuid', Buffer.alloc(16, 0));
  }

  isNull(): boolean {
    return (this.get('context_handle_uuid') as Buffer).equals(Buffer.alloc(16, 0));
  }
}

export class RVALENT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ve_valuename', PRRP_UNICODE_STRING],
    ['ve_valuelen', DWORD],
    ['ve_valueptr', DWORD],
    ['ve_type', DWORD],
  ];
}

export class RVALENT_ARRAY extends NDRUniConformantVaryingArray {
  static item = RVALENT;
}

export class RRP_BYTE_ARRAY extends NDRUniConformantVaryingArray {}

export class RRP_PBYTE_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RRP_BYTE_ARRAY]];
}

export class RPC_SECURITY_DESCRIPTOR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['lpSecurityDescriptor', RRP_PBYTE_ARRAY],
    ['cbInSecurityDescriptor', DWORD],
    ['cbOutSecurityDescriptor', DWORD],
  ];
}

export class RPC_SECURITY_ATTRIBUTES extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['nLength', DWORD],
    ['RpcSecurityDescriptor', RPC_SECURITY_DESCRIPTOR],
    ['bInheritHandle', BOOLEAN],
  ];
}

export class PRPC_SECURITY_ATTRIBUTES extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RPC_SECURITY_ATTRIBUTES]];
}

// RPC CALLS

// Opnum 0
export class OpenClassesRootResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phKey', RPC_HKEY],
    ['ErrorCode', error_status_t],
  ];
}

export class OpenClassesRoot extends NDRCALL {
  static opnum = 0;
  static Response = OpenClassesRootResponse;
  static structure: NDRField[] = [
    ['ServerName', PREGISTRY_SERVER_NAME],
    ['samDesired', REGSAM],
  ];
}

// Opnum 1
export class OpenCurrentUserResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phKey', RPC_HKEY],
    ['ErrorCode', error_status_t],
  ];
}

export class OpenCurrentUser extends NDRCALL {
  static opnum = 1;
  static Response = OpenCurrentUserResponse;
  static structure: NDRField[] = [
    ['ServerName', PREGISTRY_SERVER_NAME],
    ['samDesired', REGSAM],
  ];
}

// Opnum 2
export class OpenLocalMachineResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phKey', RPC_HKEY],
    ['ErrorCode', error_status_t],
  ];
}

export class OpenLocalMachine extends NDRCALL {
  static opnum = 2;
  static Response = OpenLocalMachineResponse;
  static structure: NDRField[] = [
    ['ServerName', PREGISTRY_SERVER_NAME],
    ['samDesired', REGSAM],
  ];
}

// Opnum 3
export class OpenPerformanceDataResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phKey', RPC_HKEY],
    ['ErrorCode', error_status_t],
  ];
}

export class OpenPerformanceData extends NDRCALL {
  static opnum = 3;
  static Response = OpenPerformanceDataResponse;
  static structure: NDRField[] = [
    ['ServerName', PREGISTRY_SERVER_NAME],
    ['samDesired', REGSAM],
  ];
}

// Opnum 4
export class OpenUsersResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phKey', RPC_HKEY],
    ['ErrorCode', error_status_t],
  ];
}

export class OpenUsers extends NDRCALL {
  static opnum = 4;
  static Response = OpenUsersResponse;
  static structure: NDRField[] = [
    ['ServerName', PREGISTRY_SERVER_NAME],
    ['samDesired', REGSAM],
  ];
}

// Opnum 5
export class BaseRegCloseKeyResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['ErrorCode', error_status_t],
  ];
}

export class BaseRegCloseKey extends NDRCALL {
  static opnum = 5;
  static Response = BaseRegCloseKeyResponse;
  static structure: NDRField[] = [['hKey', RPC_HKEY]];
}

// Opnum 6
export class BaseRegCreateKeyResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phkResult', RPC_HKEY],
    ['lpdwDisposition', LPULONG],
    ['ErrorCode', error_status_t],
  ];
}

export class BaseRegCreateKey extends NDRCALL {
  static opnum = 6;
  static Response = BaseRegCreateKeyResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['lpSubKey', RRP_UNICODE_STRING],
    ['lpClass', RRP_UNICODE_STRING],
    ['dwOptions', DWORD],
    ['samDesired', REGSAM],
    ['lpSecurityAttributes', PRPC_SECURITY_ATTRIBUTES],
    ['lpdwDisposition', LPULONG],
  ];
}

// Opnum 7
export class BaseRegDeleteKeyResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class BaseRegDeleteKey extends NDRCALL {
  static opnum = 7;
  static Response = BaseRegDeleteKeyResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['lpSubKey', RRP_UNICODE_STRING],
  ];
}

// Opnum 8
export class BaseRegDeleteValueResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class BaseRegDeleteValue extends NDRCALL {
  static opnum = 8;
  static Response = BaseRegDeleteValueResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['lpValueName', RRP_UNICODE_STRING],
  ];
}

// Opnum 9
export class BaseRegEnumKeyResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpNameOut', RRP_UNICODE_STRING],
    ['lplpClassOut', PRRP_UNICODE_STRING],
    ['lpftLastWriteTime', PFILETIME],
    ['ErrorCode', error_status_t],
  ];
}

export class BaseRegEnumKey extends NDRCALL {
  static opnum = 9;
  static Response = BaseRegEnumKeyResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['dwIndex', DWORD],
    ['lpNameIn', RRP_UNICODE_STRING],
    ['lpClassIn', PRRP_UNICODE_STRING],
    ['lpftLastWriteTime', PFILETIME],
  ];
}

// Opnum 10
export class BaseRegEnumValueResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpValueNameOut', RRP_UNICODE_STRING],
    ['lpType', LPULONG],
    ['lpData', RRP_PBYTE_ARRAY],
    ['lpcbData', LPULONG],
    ['lpcbLen', LPULONG],
    ['ErrorCode', error_status_t],
  ];
}

export class BaseRegEnumValue extends NDRCALL {
  static opnum = 10;
  static Response = BaseRegEnumValueResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['dwIndex', DWORD],
    ['lpValueNameIn', RRP_UNICODE_STRING],
    ['lpType', LPULONG],
    ['lpData', RRP_PBYTE_ARRAY],
    ['lpcbData', LPULONG],
    ['lpcbLen', LPULONG],
  ];
}

// Opnum 11
export class BaseRegFlushKeyResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class BaseRegFlushKey extends NDRCALL {
  static opnum = 11;
  static Response = BaseRegFlushKeyResponse;
  static structure: NDRField[] = [['hKey', RPC_HKEY]];
}

// Opnum 12
export class BaseRegGetKeySecurityResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pRpcSecurityDescriptorOut', RPC_SECURITY_DESCRIPTOR],
    ['ErrorCode', error_status_t],
  ];
}

export class BaseRegGetKeySecurity extends NDRCALL {
  static opnum = 12;
  static Response = BaseRegGetKeySecurityResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['SecurityInformation', SECURITY_INFORMATION],
    ['pRpcSecurityDescriptorIn', RPC_SECURITY_DESCRIPTOR],
  ];
}

// Opnum 13
export class BaseRegLoadKeyResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class BaseRegLoadKey extends NDRCALL {
  static opnum = 13;
  static Response = BaseRegLoadKeyResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['lpSubKey', RRP_UNICODE_STRING],
    ['lpFile', RRP_UNICODE_STRING],
  ];
}

// Opnum 15
export class BaseRegOpenKeyResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phkResult', RPC_HKEY],
    ['ErrorCode', error_status_t],
  ];
}

export class BaseRegOpenKey extends NDRCALL {
  static opnum = 15;
  static Response = BaseRegOpenKeyResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['lpSubKey', RRP_UNICODE_STRING],
    ['dwOptions', DWORD],
    ['samDesired', REGSAM],
  ];
}

// Opnum 16
export class BaseRegQueryInfoKeyResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpClassOut', RPC_UNICODE_STRING],
    ['lpcSubKeys', DWORD],
    ['lpcbMaxSubKeyLen', DWORD],
    ['lpcbMaxClassLen', DWORD],
    ['lpcValues', DWORD],
    ['lpcbMaxValueNameLen', DWORD],
    ['lpcbMaxValueLen', DWORD],
    ['lpcbSecurityDescriptor', DWORD],
    ['lpftLastWriteTime', FILETIME],
    ['ErrorCode', error_status_t],
  ];
}

export class BaseRegQueryInfoKey extends NDRCALL {
  static opnum = 16;
  static Response = BaseRegQueryInfoKeyResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['lpClassIn', RRP_UNICODE_STRING],
  ];
}

// Opnum 17
export class BaseRegQueryValueResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpType', LPULONG],
    ['lpData', RRP_PBYTE_ARRAY],
    ['lpcbData', LPULONG],
    ['lpcbLen', LPULONG],
    ['ErrorCode', error_status_t],
  ];
}

export class BaseRegQueryValue extends NDRCALL {
  static opnum = 17;
  static Response = BaseRegQueryValueResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['lpValueName', RRP_UNICODE_STRING],
    ['lpType', LPULONG],
    ['lpData', RRP_PBYTE_ARRAY],
    ['lpcbData', LPULONG],
    ['lpcbLen', LPULONG],
  ];
}

// Opnum 18
export class BaseRegReplaceKeyResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class BaseRegReplaceKey extends NDRCALL {
  static opnum = 18;
  static Response = BaseRegReplaceKeyResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['lpSubKey', RRP_UNICODE_STRING],
    ['lpNewFile', RRP_UNICODE_STRING],
    ['lpOldFile', RRP_UNICODE_STRING],
  ];
}

// Opnum 19
export class BaseRegRestoreKeyResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class BaseRegRestoreKey extends NDRCALL {
  static opnum = 19;
  static Response = BaseRegRestoreKeyResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['lpFile', RRP_UNICODE_STRING],
    ['Flags', DWORD],
  ];
}

// Opnum 20
export class BaseRegSaveKeyResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class BaseRegSaveKey extends NDRCALL {
  static opnum = 20;
  static Response = BaseRegSaveKeyResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['lpFile', RRP_UNICODE_STRING],
    ['pSecurityAttributes', PRPC_SECURITY_ATTRIBUTES],
  ];
}

// Opnum 21
export class BaseRegSetKeySecurityResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class BaseRegSetKeySecurity extends NDRCALL {
  static opnum = 21;
  static Response = BaseRegSetKeySecurityResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['SecurityInformation', SECURITY_INFORMATION],
    ['pRpcSecurityDescriptor', RPC_SECURITY_DESCRIPTOR],
  ];
}

// Opnum 22
export class BaseRegSetValueResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class BaseRegSetValue extends NDRCALL {
  static opnum = 22;
  static Response = BaseRegSetValueResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['lpValueName', RRP_UNICODE_STRING],
    ['dwType', DWORD],
    ['lpData', NDRUniConformantArray],
    ['cbData', DWORD],
  ];
}

// Opnum 23
export class BaseRegUnLoadKeyResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class BaseRegUnLoadKey extends NDRCALL {
  static opnum = 23;
  static Response = BaseRegUnLoadKeyResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['lpSubKey', RRP_UNICODE_STRING],
  ];
}

// Opnum 26
export class BaseRegGetVersionResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpdwVersion', DWORD],
    ['ErrorCode', error_status_t],
  ];
}

export class BaseRegGetVersion extends NDRCALL {
  static opnum = 26;
  static Response = BaseRegGetVersionResponse;
  static structure: NDRField[] = [['hKey', RPC_HKEY]];
}

// Opnum 27
export class OpenCurrentConfigResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phKey', RPC_HKEY],
    ['ErrorCode', error_status_t],
  ];
}

export class OpenCurrentConfig extends NDRCALL {
  static opnum = 27;
  static Response = OpenCurrentConfigResponse;
  static structure: NDRField[] = [
    ['ServerName', PREGISTRY_SERVER_NAME],
    ['samDesired', REGSAM],
  ];
}

// Opnum 29
export class BaseRegQueryMultipleValuesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['val_listOut', RVALENT_ARRAY],
    ['lpvalueBuf', RRP_PBYTE_ARRAY],
    ['ldwTotsize', DWORD],
    ['ErrorCode', error_status_t],
  ];
}

export class BaseRegQueryMultipleValues extends NDRCALL {
  static opnum = 29;
  static Response = BaseRegQueryMultipleValuesResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['val_listIn', RVALENT_ARRAY],
    ['num_vals', DWORD],
    ['lpvalueBuf', RRP_PBYTE_ARRAY],
    ['ldwTotsize', DWORD],
  ];
}

// Opnum 31
export class BaseRegSaveKeyExResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class BaseRegSaveKeyEx extends NDRCALL {
  static opnum = 31;
  static Response = BaseRegSaveKeyExResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['lpFile', RRP_UNICODE_STRING],
    ['pSecurityAttributes', PRPC_SECURITY_ATTRIBUTES],
    ['Flags', DWORD],
  ];
}

// Opnum 32
export class OpenPerformanceTextResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phKey', RPC_HKEY],
    ['ErrorCode', error_status_t],
  ];
}

export class OpenPerformanceText extends NDRCALL {
  static opnum = 32;
  static Response = OpenPerformanceTextResponse;
  static structure: NDRField[] = [
    ['ServerName', PREGISTRY_SERVER_NAME],
    ['samDesired', REGSAM],
  ];
}

// Opnum 33
export class OpenPerformanceNlsTextResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phKey', RPC_HKEY],
    ['ErrorCode', error_status_t],
  ];
}

export class OpenPerformanceNlsText extends NDRCALL {
  static opnum = 33;
  static Response = OpenPerformanceNlsTextResponse;
  static structure: NDRField[] = [
    ['ServerName', PREGISTRY_SERVER_NAME],
    ['samDesired', REGSAM],
  ];
}

// Opnum 34
export class BaseRegQueryMultipleValues2Response extends NDRCALL {
  static structure: NDRField[] = [
    ['val_listOut', RVALENT_ARRAY],
    ['lpvalueBuf', RRP_PBYTE_ARRAY],
    ['ldwRequiredSize', DWORD],
    ['ErrorCode', error_status_t],
  ];
}

export class BaseRegQueryMultipleValues2 extends NDRCALL {
  static opnum = 34;
  static Response = BaseRegQueryMultipleValues2Response;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['val_listIn', RVALENT_ARRAY],
    ['num_vals', DWORD],
    ['lpvalueBuf', RRP_PBYTE_ARRAY],
    ['ldwTotsize', DWORD],
  ];
}

// Opnum 35
export class BaseRegDeleteKeyExResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', error_status_t]];
}

export class BaseRegDeleteKeyEx extends NDRCALL {
  static opnum = 35;
  static Response = BaseRegDeleteKeyExResponse;
  static structure: NDRField[] = [
    ['hKey', RPC_HKEY],
    ['lpSubKey', RRP_UNICODE_STRING],
    ['AccessMask', REGSAM],
    ['Reserved', DWORD],
  ];
}

export const RRP_OPNUMS: Record<number, [new (data?: Buffer | null, isNDR64?: boolean) => NDRCALL, new (data?: Buffer | null, isNDR64?: boolean) => NDRCALL]> = {
  0: [OpenClassesRoot, OpenClassesRootResponse] as const,
  1: [OpenCurrentUser, OpenCurrentUserResponse] as const,
  2: [OpenLocalMachine, OpenLocalMachineResponse] as const,
  3: [OpenPerformanceData, OpenPerformanceDataResponse] as const,
  4: [OpenUsers, OpenUsersResponse] as const,
  5: [BaseRegCloseKey, BaseRegCloseKeyResponse] as const,
  6: [BaseRegCreateKey, BaseRegCreateKeyResponse] as const,
  7: [BaseRegDeleteKey, BaseRegDeleteKeyResponse] as const,
  8: [BaseRegDeleteValue, BaseRegDeleteValueResponse] as const,
  9: [BaseRegEnumKey, BaseRegEnumKeyResponse] as const,
  10: [BaseRegEnumValue, BaseRegEnumValueResponse] as const,
  11: [BaseRegFlushKey, BaseRegFlushKeyResponse] as const,
  12: [BaseRegGetKeySecurity, BaseRegGetKeySecurityResponse] as const,
  13: [BaseRegLoadKey, BaseRegLoadKeyResponse] as const,
  15: [BaseRegOpenKey, BaseRegOpenKeyResponse] as const,
  16: [BaseRegQueryInfoKey, BaseRegQueryInfoKeyResponse] as const,
  17: [BaseRegQueryValue, BaseRegQueryValueResponse] as const,
  18: [BaseRegReplaceKey, BaseRegReplaceKeyResponse] as const,
  19: [BaseRegRestoreKey, BaseRegRestoreKeyResponse] as const,
  20: [BaseRegSaveKey, BaseRegSaveKeyResponse] as const,
  21: [BaseRegSetKeySecurity, BaseRegSetKeySecurityResponse] as const,
  22: [BaseRegSetValue, BaseRegSetValueResponse] as const,
  23: [BaseRegUnLoadKey, BaseRegUnLoadKeyResponse] as const,
  26: [BaseRegGetVersion, BaseRegGetVersionResponse] as const,
  27: [OpenCurrentConfig, OpenCurrentConfigResponse] as const,
  29: [BaseRegQueryMultipleValues, BaseRegQueryMultipleValuesResponse] as const,
  31: [BaseRegSaveKeyEx, BaseRegSaveKeyExResponse] as const,
  32: [OpenPerformanceText, OpenPerformanceTextResponse] as const,
  33: [OpenPerformanceNlsText, OpenPerformanceNlsTextResponse] as const,
  34: [BaseRegQueryMultipleValues2, BaseRegQueryMultipleValues2Response] as const,
  35: [BaseRegDeleteKeyEx, BaseRegDeleteKeyExResponse] as const,
};

// HELPER FUNCTIONS

type DceRpc = { request<T>(req: unknown): Promise<T> };

export function rrpCheckNullString(str: any): any {
  if (str === NULL || (str && str.constructor && str.constructor.name === 'NDRPOINTERNULL')) return str;
  if (typeof str !== 'string') return str;
  if (str === '\x00') return str;
  if (str.endsWith('\x00')) return str;
  return str + '\x00';
}

export function packValue(valueType: number, value: number | string | Buffer): Buffer {
  if (valueType === REG_DWORD) return structPack('<L', value as number);
  if (valueType === REG_DWORD_BIG_ENDIAN) return structPack('>L', value as number);
  if (valueType === REG_EXPAND_SZ) return Buffer.from(rrpCheckNullString(value as string), 'utf16le');
  if (valueType === REG_MULTI_SZ) {
    let v = rrpCheckNullString(value as string);
    if (!v.endsWith('\x00')) v += '\x00';
    return Buffer.from(v, 'utf16le');
  }
  if (valueType === REG_QWORD) return structPack('<Q', BigInt(value as number));
  if (valueType === REG_QWORD_LITTLE_ENDIAN) return structPack('>Q', BigInt(value as number));
  if (valueType === REG_SZ) return Buffer.from(rrpCheckNullString(value as string), 'utf16le');
  return value as Buffer;
}

export function unpackValue(valueType: number, value: Buffer): number | bigint | string | Buffer {
  if (valueType === REG_DWORD) return structUnpack('<L', value) as number;
  if (valueType === REG_DWORD_BIG_ENDIAN) return structUnpack('>L', value) as number;
  if (valueType === REG_EXPAND_SZ) return value.toString('utf16le');
  if (valueType === REG_MULTI_SZ) return value.toString('utf16le');
  if (valueType === REG_QWORD) return structUnpack('<Q', value) as bigint;
  if (valueType === REG_QWORD_LITTLE_ENDIAN) return structUnpack('>Q', value) as bigint;
  if (valueType === REG_SZ) return value.toString('utf16le');
  return value;
}

export async function hOpenClassesRoot(dce: DceRpc, samDesired = MAXIMUM_ALLOWED): Promise<any> {
  const request = new OpenClassesRoot();
  request.set('ServerName', NULL);
  request.set('samDesired', samDesired);
  return dce.request(request);
}

export async function hOpenCurrentUser(dce: DceRpc, samDesired = MAXIMUM_ALLOWED): Promise<any> {
  const request = new OpenCurrentUser();
  request.set('ServerName', NULL);
  request.set('samDesired', samDesired);
  return dce.request(request);
}

export async function hOpenLocalMachine(dce: DceRpc, samDesired = MAXIMUM_ALLOWED): Promise<any> {
  const request = new OpenLocalMachine();
  request.set('ServerName', NULL);
  request.set('samDesired', samDesired);
  return dce.request(request);
}

export async function hOpenPerformanceData(dce: DceRpc, samDesired = MAXIMUM_ALLOWED): Promise<any> {
  const request = new OpenPerformanceData();
  request.set('ServerName', NULL);
  request.set('samDesired', samDesired);
  return dce.request(request);
}

export async function hOpenUsers(dce: DceRpc, samDesired = MAXIMUM_ALLOWED): Promise<any> {
  const request = new OpenUsers();
  request.set('ServerName', NULL);
  request.set('samDesired', samDesired);
  return dce.request(request);
}

export async function hBaseRegCloseKey(dce: DceRpc, hKey: any): Promise<any> {
  const request = new BaseRegCloseKey();
  request.set('hKey', hKey);
  return dce.request(request);
}

export async function hBaseRegCreateKey(dce: DceRpc, hKey: any, lpSubKey: string, lpClass: any = NULL, dwOptions = 0x00000001, samDesired = MAXIMUM_ALLOWED, lpSecurityAttributes: any = NULL, lpdwDisposition = REG_CREATED_NEW_KEY): Promise<any> {
  const request = new BaseRegCreateKey();
  request.set('hKey', hKey);
  request.set('lpSubKey', rrpCheckNullString(lpSubKey));
  request.set('lpClass', rrpCheckNullString(lpClass));
  request.set('dwOptions', dwOptions);
  request.set('samDesired', samDesired);
  if (lpSecurityAttributes === NULL) {
    request.set('lpSecurityAttributes', NULL);
  } else {
    request.set('lpSecurityAttributes', lpSecurityAttributes);
  }
  request.set('lpdwDisposition', lpdwDisposition);
  return dce.request(request);
}

export async function hBaseRegDeleteKey(dce: DceRpc, hKey: any, lpSubKey: string): Promise<any> {
  const request = new BaseRegDeleteKey();
  request.set('hKey', hKey);
  request.set('lpSubKey', rrpCheckNullString(lpSubKey));
  return dce.request(request);
}

export async function hBaseRegEnumKey(dce: DceRpc, hKey: any, dwIndex: number, lpftLastWriteTime: any = NULL): Promise<any> {
  const request = new BaseRegEnumKey();
  request.set('hKey', hKey);
  request.set('dwIndex', dwIndex);
  (request.fields['lpNameIn'] as any).set('MaximumLength', 1024);
  (request.fields['lpNameIn'] as any).fields['Data'].fields['Data'].set('MaximumCount', 1024 / 2);
  request.set('lpClassIn', ' '.repeat(64));
  request.set('lpftLastWriteTime', lpftLastWriteTime);
  return dce.request(request);
}

export async function hBaseRegEnumValue(dce: DceRpc, hKey: any, dwIndex: number, dataLen = 256): Promise<any> {
  let retries = 1;
  while (true) {
    try {
      const request = new BaseRegEnumValue();
      request.set('hKey', hKey);
      request.set('dwIndex', dwIndex);
      (request.fields['lpValueNameIn'] as any).set('MaximumLength', dataLen * 2);
      (request.fields['lpValueNameIn'] as any).fields['Data'].fields['Data'].set('MaximumCount', dataLen);
      request.set('lpData', Buffer.alloc(dataLen, 0x20));
      request.set('lpcbData', dataLen);
      request.set('lpcbLen', dataLen);
      return await dce.request(request);
    } catch (e) {
      if (retries > 1) throw e;
      if (e instanceof RRP_DCERPCSessionError && (e as any).error_code === ERROR_MORE_DATA) {
        retries++;
        const cbObj = (e as any).packet.fields['lpcbData']?.fields?.['Data'];
        const cbVal = (typeof cbObj === 'object' && cbObj?.fields?.['Data'] != null) ? cbObj.fields['Data'] : cbObj;
        dataLen = cbVal ?? dataLen;
        continue;
      }
      throw e;
    }
  }
}

export async function hBaseRegFlushKey(dce: DceRpc, hKey: any): Promise<any> {
  const request = new BaseRegFlushKey();
  request.set('hKey', hKey);
  return dce.request(request);
}

export async function hBaseRegGetKeySecurity(dce: DceRpc, hKey: any, securityInformation = OWNER_SECURITY_INFORMATION): Promise<any> {
  const request = new BaseRegGetKeySecurity();
  request.set('hKey', hKey);
  request.set('SecurityInformation', securityInformation);
  (request.fields['pRpcSecurityDescriptorIn'] as any).set('lpSecurityDescriptor', NULL);
  (request.fields['pRpcSecurityDescriptorIn'] as any).set('cbInSecurityDescriptor', 1024);
  return dce.request(request);
}

export async function hBaseRegLoadKey(dce: DceRpc, hKey: any, lpSubKey: string, lpFile: string): Promise<any> {
  const request = new BaseRegLoadKey();
  request.set('hKey', hKey);
  request.set('lpSubKey', rrpCheckNullString(lpSubKey));
  request.set('lpFile', rrpCheckNullString(lpFile));
  return dce.request(request);
}

export async function hBaseRegUnLoadKey(dce: DceRpc, hKey: any, lpSubKey: string): Promise<any> {
  const request = new BaseRegUnLoadKey();
  request.set('hKey', hKey);
  request.set('lpSubKey', rrpCheckNullString(lpSubKey));
  return dce.request(request);
}

export async function hBaseRegOpenKey(dce: DceRpc, hKey: any, lpSubKey: string, dwOptions = 0x00000001, samDesired = MAXIMUM_ALLOWED): Promise<any> {
  const request = new BaseRegOpenKey();
  request.set('hKey', hKey);
  request.set('lpSubKey', rrpCheckNullString(lpSubKey));
  request.set('dwOptions', dwOptions);
  request.set('samDesired', samDesired);
  return dce.request(request);
}

export async function hBaseRegQueryInfoKey(dce: DceRpc, hKey: any): Promise<any> {
  const request = new BaseRegQueryInfoKey();
  request.set('hKey', hKey);
  (request.fields['lpClassIn'] as any).set('MaximumLength', 1024);
  (request.fields['lpClassIn'] as any).fields['Data'].fields['Data'].set('MaximumCount', 1024 / 2);
  return dce.request(request);
}

export async function hBaseRegQueryValue(dce: DceRpc, hKey: any, lpValueName: string, dataLen = 512): Promise<[number, any]> {
  let retries = 1;
  while (true) {
    try {
      const request = new BaseRegQueryValue();
      request.set('hKey', hKey);
      request.set('lpValueName', rrpCheckNullString(lpValueName));
      request.set('lpData', Buffer.alloc(dataLen, 0x20));
      request.set('lpcbData', dataLen);
      request.set('lpcbLen', dataLen);
      const resp: any = await dce.request(request);
      const lpTypeObj = (resp.fields['lpType'] as any).fields['Data'];
      const lpType = (typeof lpTypeObj === 'object' && lpTypeObj?.fields?.['Data'] != null) ? lpTypeObj.fields['Data'] as number : lpTypeObj as number;
      const lpDataOuter = resp.fields['lpData'].fields['Data'];
      const lpData = (typeof lpDataOuter === 'object' && lpDataOuter?.fields?.['Data'] != null) ? lpDataOuter.fields['Data'] : lpDataOuter;
      const dataBuf = Array.isArray(lpData) ? Buffer.from(lpData as number[]) : (lpData as Buffer);
      return [lpType, unpackValue(lpType, dataBuf)];
    } catch (e) {
      if (retries > 1) throw e;
      if (e instanceof RRP_DCERPCSessionError && (e as any).error_code === ERROR_MORE_DATA) {
        retries++;
        const cbObj = (e as any).packet.fields['lpcbData']?.fields?.['Data'];
        const cbVal = (typeof cbObj === 'object' && cbObj?.fields?.['Data'] != null) ? cbObj.fields['Data'] : cbObj;
        dataLen = cbVal ?? dataLen;
        continue;
      }
      throw e;
    }
  }
}

export async function hBaseRegReplaceKey(dce: DceRpc, hKey: any, lpSubKey: string, lpNewFile: string, lpOldFile: string): Promise<any> {
  const request = new BaseRegReplaceKey();
  request.set('hKey', hKey);
  request.set('lpSubKey', rrpCheckNullString(lpSubKey));
  request.set('lpNewFile', rrpCheckNullString(lpNewFile));
  request.set('lpOldFile', rrpCheckNullString(lpOldFile));
  return dce.request(request);
}

export async function hBaseRegRestoreKey(dce: DceRpc, hKey: any, lpFile: string, flags = REG_REFRESH_HIVE): Promise<any> {
  const request = new BaseRegRestoreKey();
  request.set('hKey', hKey);
  request.set('lpFile', rrpCheckNullString(lpFile));
  request.set('Flags', flags);
  return dce.request(request);
}

export async function hBaseRegSaveKey(dce: DceRpc, hKey: any, lpFile: string, pSecurityAttributes: any = NULL): Promise<any> {
  const request = new BaseRegSaveKey();
  request.set('hKey', hKey);
  request.set('lpFile', rrpCheckNullString(lpFile));
  request.set('pSecurityAttributes', pSecurityAttributes);
  return dce.request(request);
}

export async function hBaseRegSetValue(dce: DceRpc, hKey: any, lpValueName: string, dwType: number, lpData: any): Promise<any> {
  const request = new BaseRegSetValue();
  request.set('hKey', hKey);
  request.set('lpValueName', rrpCheckNullString(lpValueName));
  request.set('dwType', dwType);
  const packed = packValue(dwType, lpData);
  request.set('lpData', Array.from(packed));
  request.set('cbData', packed.length);
  return dce.request(request);
}

export async function hBaseRegGetVersion(dce: DceRpc, hKey: any): Promise<any> {
  const request = new BaseRegGetVersion();
  request.set('hKey', hKey);
  return dce.request(request);
}

export async function hOpenCurrentConfig(dce: DceRpc, samDesired = MAXIMUM_ALLOWED): Promise<any> {
  const request = new OpenCurrentConfig();
  request.set('ServerName', NULL);
  request.set('samDesired', samDesired);
  return dce.request(request);
}

export async function hBaseRegQueryMultipleValues(dce: DceRpc, hKey: any, val_listIn: Array<{ ValueName: string; ValueType: number }>): Promise<Array<{ ValueName: string; ValueData: any }>> {
  const request = new BaseRegQueryMultipleValues();
  request.set('hKey', hKey);
  for (const item of val_listIn) {
    const itemn = new RVALENT();
    itemn.set('ve_valuename', rrpCheckNullString(item.ValueName));
    itemn.set('ve_valuelen', rrpCheckNullString(item.ValueName).length);
    itemn.set('ve_valueptr', NULL);
    itemn.set('ve_type', item.ValueType);
    (request.fields['val_listIn'] as any).fields['Data'].push(itemn);
  }
  request.set('num_vals', val_listIn.length);
  request.set('lpvalueBuf', Array.from(Buffer.alloc(128, 0x20)));
  request.set('ldwTotsize', 128);
  const resp: any = await dce.request(request);
  const retVal: Array<{ ValueName: string; ValueData: any }> = [];
  const valListOut = resp.fields['val_listOut'].fields['Data'] as any[];
  const lpvalueBuf = resp.fields['lpvalueBuf'].fields['Data'];
  const bufData = Array.isArray(lpvalueBuf) ? Buffer.from(lpvalueBuf as number[]) : (lpvalueBuf as Buffer);
  for (const item of valListOut) {
    const ve_valuename = item.fields['ve_valuename'];
    const ve_valuelen = item.fields['ve_valuelen'].fields['Data'] as number;
    const ve_valueptr = item.fields['ve_valueptr'].fields['Data'] as number;
    const ve_type = item.fields['ve_type'].fields['Data'] as number;
    const name = ve_valuename.fields['Data'];
    const nameStr = name?.fields?.['Data'] ?? name ?? '';
    retVal.push({
      ValueName: nameStr as string,
      ValueData: unpackValue(ve_type, bufData.subarray(ve_valueptr, ve_valueptr + ve_valuelen)),
    });
  }
  return retVal;
}

export async function hBaseRegSaveKeyEx(dce: DceRpc, hKey: any, lpFile: string, pSecurityAttributes: any = NULL, flags = 1): Promise<any> {
  const request = new BaseRegSaveKeyEx();
  request.set('hKey', hKey);
  request.set('lpFile', rrpCheckNullString(lpFile));
  request.set('pSecurityAttributes', pSecurityAttributes);
  request.set('Flags', flags);
  return dce.request(request);
}

export async function hOpenPerformanceText(dce: DceRpc, samDesired = MAXIMUM_ALLOWED): Promise<any> {
  const request = new OpenPerformanceText();
  request.set('ServerName', NULL);
  request.set('samDesired', samDesired);
  return dce.request(request);
}

export async function hOpenPerformanceNlsText(dce: DceRpc, samDesired = MAXIMUM_ALLOWED): Promise<any> {
  const request = new OpenPerformanceNlsText();
  request.set('ServerName', NULL);
  request.set('samDesired', samDesired);
  return dce.request(request);
}

export async function hBaseRegDeleteValue(dce: DceRpc, hKey: any, lpValueName: string): Promise<any> {
  const request = new BaseRegDeleteValue();
  request.set('hKey', hKey);
  request.set('lpValueName', rrpCheckNullString(lpValueName));
  return dce.request(request);
}
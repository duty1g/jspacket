import { uuidtupToBin, stringToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRUNION,
  NDRPOINTER,
  NDRUniConformantArray,
  NULL,
  type NDRField,
} from './ndr';
import { ULONGLONG, UINT, USHORT, LPWSTR, DWORD, ULONG } from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_PAR = uuidtupToBin([
  '76F03F96-CDFD-44FC-A22C-64950A001209',
  '1.0',
]);
export const MSRPC_UUID_WINSPOOL = stringToBin(
  '9940CA8E-512F-4C58-88A9-61098D6896BD',
);

class DCERPCSessionError extends DCERPCException {
  toString(): string {
    return `PAR SessionError: code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

const STRING_HANDLE = LPWSTR;
class PSTRING_HANDLE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', STRING_HANDLE]];
}

const JOB_ACCESS_ADMINISTER = 0x00000010;
const JOB_ACCESS_READ = 0x00000020;
const JOB_EXECUTE = 0x00020010;
const JOB_READ = 0x00020020;
const JOB_WRITE = 0x00020010;
const JOB_ALL_ACCESS = 0x000f0030;
const PRINTER_ACCESS_ADMINISTER = 0x00000004;
const PRINTER_ACCESS_USE = 0x00000008;
const PRINTER_ACCESS_MANAGE_LIMITED = 0x00000040;
const PRINTER_ALL_ACCESS = 0x000f000c;
const PRINTER_EXECUTE = 0x00020008;
const PRINTER_READ = 0x00020008;
const PRINTER_WRITE = 0x00020008;
const SERVER_ACCESS_ADMINISTER = 0x00000001;
const SERVER_ACCESS_ENUMERATE = 0x00000002;
const SERVER_ALL_ACCESS = 0x000f0003;
const SERVER_EXECUTE = 0x00020002;
const SERVER_READ = 0x00020002;
const SERVER_WRITE = 0x00020003;
const SPECIFIC_RIGHTS_ALL = 0x0000ffff;
const STANDARD_RIGHTS_ALL = 0x001f0000;
const STANDARD_RIGHTS_EXECUTE = 0x00020000;
const STANDARD_RIGHTS_READ = 0x00020000;
const STANDARD_RIGHTS_REQUIRED = 0x000f0000;
const STANDARD_RIGHTS_WRITE = 0x00020000;
const SYNCHRONIZE = 0x00100000;
const DELETE = 0x00010000;
const READ_CONTROL = 0x00020000;
const WRITE_DAC = 0x00040000;
const WRITE_OWNER = 0x00080000;
const GENERIC_READ = 0x80000000;
const GENERIC_WRITE = 0x40000000;
const GENERIC_EXECUTE = 0x20000000;
const GENERIC_ALL = 0x10000000;

export const PAR_PRINTER_CHANGE_SET_PRINTER = 0x00000002;
export const PAR_PRINTER_CHANGE_DELETE_PRINTER = 0x00000004;
export const PAR_PRINTER_CHANGE_PRINTER = 0x000000ff;
export const PAR_PRINTER_CHANGE_ADD_JOB = 0x00000100;
export const PAR_PRINTER_CHANGE_SET_JOB = 0x00000200;
export const PAR_PRINTER_CHANGE_DELETE_JOB = 0x00000400;
export const PAR_PRINTER_CHANGE_WRITE_JOB = 0x00000800;
export const PAR_PRINTER_CHANGE_JOB = 0x0000ff00;
export const PAR_PRINTER_CHANGE_SET_PRINTER_DRIVER = 0x20000000;
export const PAR_PRINTER_CHANGE_TIMEOUT = 0x80000000;
export const PAR_PRINTER_CHANGE_ALL = 0x7777ffff;
export const PAR_PRINTER_CHANGE_ALL_2 = 0x7f77ffff;

export const PAR_PRINTER_ENUM_LOCAL = 0x00000002;
export const PAR_PRINTER_ENUM_CONNECTIONS = 0x00000004;
export const PAR_PRINTER_ENUM_NAME = 0x00000008;
export const PAR_PRINTER_ENUM_REMOTE = 0x00000010;
export const PAR_PRINTER_ENUM_SHARED = 0x00000020;
export const PAR_PRINTER_ENUM_NETWORK = 0x00000040;

export const PAR_PRINTER_NOTIFY_CATEGORY_2D = 0x00000000;
export const PAR_PRINTER_NOTIFY_CATEGORY_ALL = 0x00010000;
export const PAR_PRINTER_NOTIFY_CATEGORY_3D = 0x00020000;

export const PAR_APD_STRICT_UPGRADE = 0x00000001;
export const PAR_APD_STRICT_DOWNGRADE = 0x00000002;
export const PAR_APD_COPY_ALL_FILES = 0x00000004;
export const PAR_APD_COPY_NEW_FILES = 0x00000008;
export const PAR_APD_COPY_FROM_DIRECTORY = 0x00000010;
export const PAR_APD_COPY_TO_ALL_SPOOLERS = 0x00002000;
export const PAR_APD_INSTALL_WARNED_DRIVER = 0x00008000;
export const PAR_APD_RETURN_BLOCKING_STATUS_CODE = 0x00010000;

class PRINTER_HANDLE extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '20s=b""']];
  getAlignment(): number {
    return 4;
  }
}

class BYTE_ARRAY extends NDRUniConformantArray {
  static item = 'c';
}

class PBYTE_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', BYTE_ARRAY]];
}

class DEVMODE_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cbBuf', DWORD],
    ['pDevMode', PBYTE_ARRAY],
  ];
}

class SPLCLIENT_INFO_1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['dwSize', DWORD],
    ['pMachineName', LPWSTR],
    ['pUserName', LPWSTR],
    ['dwBuildNum', DWORD],
    ['dwMajorVersion', DWORD],
    ['dwMinorVersion', DWORD],
    ['wProcessorArchitecture', USHORT],
  ];
}

class PSPLCLIENT_INFO_1 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SPLCLIENT_INFO_1]];
}

class SPLCLIENT_INFO_2 extends NDRSTRUCT {
  static structure: NDRField[] = [['notUsed', ULONGLONG]];
}

class PSPLCLIENT_INFO_2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SPLCLIENT_INFO_2]];
}

class SPLCLIENT_INFO_3 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cbSize', UINT],
    ['dwFlags', DWORD],
    ['dwFlags2', DWORD],
    ['pMachineName', LPWSTR],
    ['pUserName', LPWSTR],
    ['dwBuildNum', DWORD],
    ['dwMajorVersion', DWORD],
    ['dwMinorVersion', DWORD],
    ['wProcessorArchitecture', USHORT],
    ['hSplPrinter', ULONGLONG],
  ];
}

class PSPLCLIENT_INFO_3 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SPLCLIENT_INFO_3]];
}

class DRIVER_INFO_1 extends NDRSTRUCT {
  static structure: NDRField[] = [['pName', STRING_HANDLE]];
}

class PDRIVER_INFO_1 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DRIVER_INFO_1]];
}

class DRIVER_INFO_2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cVersion', DWORD],
    ['pName', LPWSTR],
    ['pEnvironment', LPWSTR],
    ['pDriverPath', LPWSTR],
    ['pDataFile', LPWSTR],
    ['pConfigFile', LPWSTR],
  ];
}

class PDRIVER_INFO_2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DRIVER_INFO_2]];
}

class DRIVER_INFO_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Record<number, NDRField> = {
    1: ['pNotUsed', PDRIVER_INFO_1],
    2: ['Level2', PDRIVER_INFO_2],
  };
}

class DRIVER_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', DWORD],
    ['DriverInfo', DRIVER_INFO_UNION],
  ];
}

class CLIENT_INFO_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Record<number, NDRField> = {
    1: ['pClientInfo1', PSPLCLIENT_INFO_1],
    2: ['pNotUsed1', PSPLCLIENT_INFO_2],
    3: ['pNotUsed2', PSPLCLIENT_INFO_3],
  };
}

class SPLCLIENT_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', DWORD],
    ['ClientInfo', CLIENT_INFO_UNION],
  ];
}

class USHORT_ARRAY extends NDRUniConformantArray {
  static item = '<H';
}

class PUSHORT_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', USHORT_ARRAY]];
}

class RpcAsync_V2_NOTIFY_OPTIONS_TYPE extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Type', USHORT],
    ['Reserved0', USHORT],
    ['Reserved1', DWORD],
    ['Reserved2', DWORD],
    ['Count', DWORD],
    ['pFields', PUSHORT_ARRAY],
  ];
}

class PRPC_V2_NOTIFY_OPTIONS_TYPE_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RpcAsync_V2_NOTIFY_OPTIONS_TYPE]];
}

class RpcAsync_V2_NOTIFY_OPTIONS extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Version', DWORD],
    ['Reserved', DWORD],
    ['Count', DWORD],
    ['pTypes', PRPC_V2_NOTIFY_OPTIONS_TYPE_ARRAY],
  ];
}

class PRPC_V2_NOTIFY_OPTIONS extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RpcAsync_V2_NOTIFY_OPTIONS]];
}

// 3.1.4.1.21 RpcAsyncEnumPrinters (Opnum 38)
export class RpcAsyncEnumPrintersResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pPrinterEnum', PBYTE_ARRAY],
    ['pcbNeeded', DWORD],
    ['pcReturned', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class RpcAsyncEnumPrinters extends NDRCALL {
  static opnum = 38;
  static Response = RpcAsyncEnumPrintersResponse;
  static structure: NDRField[] = [
    ['Flags', DWORD],
    ['Name', STRING_HANDLE],
    ['Level', DWORD],
    ['pPrinterEnum', PBYTE_ARRAY],
    ['cbBuf', DWORD],
  ];
}

// 3.1.4.1.1 RpcAsyncOpenPrinter (Opnum 0)
export class RpcAsyncOpenPrinterResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pHandle', PRINTER_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class RpcAsyncOpenPrinter extends NDRCALL {
  static opnum = 0;
  static Response = RpcAsyncOpenPrinterResponse;
  static structure: NDRField[] = [
    ['pPrinterName', STRING_HANDLE],
    ['pDatatype', LPWSTR],
    ['pDevModeContainer', DEVMODE_CONTAINER],
    ['AccessRequired', DWORD],
    ['pClientInfo', SPLCLIENT_CONTAINER],
  ];
}

// 3.1.4.1.10 RpcAsyncClosePrinter (Opnum 20)
export class RpcAsyncClosePrinterResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phPrinter', PRINTER_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class RpcAsyncClosePrinter extends NDRCALL {
  static opnum = 20;
  static Response = RpcAsyncClosePrinterResponse;
  static structure: NDRField[] = [['phPrinter', PRINTER_HANDLE]];
}

// 3.1.4.2.3 RpcAsyncEnumPrinterDrivers (Opnum 40)
export class RpcAsyncEnumPrinterDriversResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pDrivers', PBYTE_ARRAY],
    ['pcbNeeded', DWORD],
    ['pcReturned', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class RpcAsyncEnumPrinterDrivers extends NDRCALL {
  static opnum = 40;
  static Response = RpcAsyncEnumPrinterDriversResponse;
  static structure: NDRField[] = [
    ['pName', STRING_HANDLE],
    ['pEnvironment', LPWSTR],
    ['Level', DWORD],
    ['pDrivers', PBYTE_ARRAY],
    ['cbBuf', DWORD],
  ];
}

// 3.1.4.2.4 RpcAsyncGetPrinterDriverDirectory (Opnum 41)
export class RpcAsyncGetPrinterDriverDirectoryResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pDriverDirectory', PBYTE_ARRAY],
    ['pcbNeeded', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class RpcAsyncGetPrinterDriverDirectory extends NDRCALL {
  static opnum = 41;
  static Response = RpcAsyncGetPrinterDriverDirectoryResponse;
  static structure: NDRField[] = [
    ['pName', STRING_HANDLE],
    ['pEnvironment', LPWSTR],
    ['Level', DWORD],
    ['pDriverDirectory', PBYTE_ARRAY],
    ['cbBuf', DWORD],
  ];
}

// 3.1.4.2.2 RpcAsyncAddPrinterDriver (Opnum 39)
export class RpcAsyncAddPrinterDriverResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcAsyncAddPrinterDriver extends NDRCALL {
  static opnum = 39;
  static Response = RpcAsyncAddPrinterDriverResponse;
  static structure: NDRField[] = [
    ['pName', STRING_HANDLE],
    ['pDriverContainer', DRIVER_CONTAINER],
    ['dwFileCopyFlags', DWORD],
  ];
}

const OPNUMS: Record<number, [typeof NDRCALL, typeof NDRCALL]> = {
  0: [RpcAsyncOpenPrinter, RpcAsyncOpenPrinterResponse],
  20: [RpcAsyncClosePrinter, RpcAsyncClosePrinterResponse],
  38: [RpcAsyncEnumPrinters, RpcAsyncEnumPrintersResponse],
  39: [RpcAsyncAddPrinterDriver, RpcAsyncAddPrinterDriverResponse],
  40: [RpcAsyncEnumPrinterDrivers, RpcAsyncEnumPrinterDriversResponse],
  41: [RpcAsyncGetPrinterDriverDirectory, RpcAsyncGetPrinterDriverDirectoryResponse],
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

export async function hRpcAsyncClosePrinter(
  dce: DCERPC_v5,
  phPrinter: unknown,
): Promise<RpcAsyncClosePrinterResponse> {
  const request = new RpcAsyncClosePrinter();
  request.set('phPrinter', phPrinter);
  return (dce as unknown as { request: DceRequestFn }).request<RpcAsyncClosePrinterResponse>(
    request,
    MSRPC_UUID_WINSPOOL,
  );
}

export async function hRpcAsyncOpenPrinter(
  dce: DCERPC_v5,
  printerName: string,
  pDatatype: string | typeof NULL = NULL,
  pDevModeContainer: unknown | typeof NULL = NULL,
  accessRequired: number = SERVER_READ,
  pClientInfo: unknown,
): Promise<RpcAsyncOpenPrinterResponse> {
  const request = new RpcAsyncOpenPrinter();
  request.set('pPrinterName', checkNullString(printerName));
  request.set('pDatatype', pDatatype);
  if (pDevModeContainer === NULL) {
    (request.fields['pDevModeContainer'] as DEVMODE_CONTAINER).set('pDevMode', NULL);
  } else {
    request.set('pDevModeContainer', pDevModeContainer);
  }
  request.set('AccessRequired', accessRequired);
  request.set('pClientInfo', pClientInfo);
  return (dce as unknown as { request: DceRequestFn }).request<RpcAsyncOpenPrinterResponse>(
    request,
    MSRPC_UUID_WINSPOOL,
  );
}

export async function hRpcAsyncEnumPrinters(
  dce: DCERPC_v5,
  flags: number,
  name: string | typeof NULL = NULL,
  level: number = 1,
): Promise<RpcAsyncEnumPrintersResponse> {
  const request = new RpcAsyncEnumPrinters();
  request.set('Flags', flags);
  request.set('Name', name);
  request.set('pPrinterEnum', NULL);
  request.set('Level', level);
  let bytesNeeded = 0;
  try {
    await (dce as unknown as { request: DceRequestFn }).request(request, MSRPC_UUID_WINSPOOL);
  } catch (e) {
    if (String(e).indexOf('ERROR_INSUFFICIENT_BUFFER') < 0) throw e;
    const pkt = (e as DCERPCException).getPacket() as { get(k: string): unknown } | null;
    bytesNeeded = (pkt?.get('pcbNeeded') as number) ?? 0;
  }

  const request2 = new RpcAsyncEnumPrinters();
  request2.set('Flags', flags);
  request2.set('Name', name);
  request2.set('Level', level);
  request2.set('cbBuf', bytesNeeded);
  request2.set('pPrinterEnum', Buffer.alloc(bytesNeeded, 0x61));
  return (dce as unknown as { request: DceRequestFn }).request<RpcAsyncEnumPrintersResponse>(
    request2,
    MSRPC_UUID_WINSPOOL,
  );
}

export async function hRpcAsyncAddPrinterDriver(
  dce: DCERPC_v5,
  pName: string,
  pDriverContainer: unknown,
  dwFileCopyFlags: number,
): Promise<RpcAsyncAddPrinterDriverResponse> {
  const request = new RpcAsyncAddPrinterDriver();
  request.set('pName', checkNullString(pName));
  request.set('pDriverContainer', pDriverContainer);
  request.set('dwFileCopyFlags', dwFileCopyFlags);
  return (dce as unknown as { request: DceRequestFn }).request<RpcAsyncAddPrinterDriverResponse>(
    request,
    MSRPC_UUID_WINSPOOL,
  );
}

export async function hRpcAsyncEnumPrinterDrivers(
  dce: DCERPC_v5,
  pName: string,
  pEnvironment: string,
  level: number,
): Promise<RpcAsyncEnumPrinterDriversResponse> {
  const request = new RpcAsyncEnumPrinterDrivers();
  request.set('pName', checkNullString(pName));
  request.set('pEnvironment', pEnvironment);
  request.set('Level', level);
  request.set('pDrivers', NULL);
  request.set('cbBuf', 0);
  let bytesNeeded = 0;
  try {
    await (dce as unknown as { request: DceRequestFn }).request(request, MSRPC_UUID_WINSPOOL);
  } catch (e) {
    if (String(e).indexOf('ERROR_INSUFFICIENT_BUFFER') < 0) throw e;
    const pkt = (e as DCERPCException).getPacket() as { get(k: string): unknown } | null;
    bytesNeeded = (pkt?.get('pcbNeeded') as number) ?? 0;
  }

  const request2 = new RpcAsyncEnumPrinterDrivers();
  request2.set('pName', checkNullString(pName));
  request2.set('pEnvironment', pEnvironment);
  request2.set('Level', level);
  request2.set('pDrivers', Buffer.alloc(bytesNeeded, 0x61));
  request2.set('cbBuf', bytesNeeded);
  return (dce as unknown as { request: DceRequestFn }).request<RpcAsyncEnumPrinterDriversResponse>(
    request2,
    MSRPC_UUID_WINSPOOL,
  );
}

export async function hRpcAsyncGetPrinterDriverDirectory(
  dce: DCERPC_v5,
  pName: string,
  pEnvironment: string,
  level: number,
): Promise<RpcAsyncGetPrinterDriverDirectoryResponse> {
  const request = new RpcAsyncGetPrinterDriverDirectory();
  request.set('pName', checkNullString(pName));
  request.set('pEnvironment', pEnvironment);
  request.set('Level', level);
  request.set('pDriverDirectory', NULL);
  request.set('cbBuf', 0);
  let bytesNeeded = 0;
  try {
    await (dce as unknown as { request: DceRequestFn }).request(request, MSRPC_UUID_WINSPOOL);
  } catch (e) {
    if (String(e).indexOf('ERROR_INSUFFICIENT_BUFFER') < 0) throw e;
    const pkt = (e as DCERPCException).getPacket() as { get(k: string): unknown } | null;
    bytesNeeded = (pkt?.get('pcbNeeded') as number) ?? 0;
  }

  const request2 = new RpcAsyncGetPrinterDriverDirectory();
  request2.set('pName', checkNullString(pName));
  request2.set('pEnvironment', pEnvironment);
  request2.set('Level', level);
  request2.set('pDriverDirectory', Buffer.alloc(bytesNeeded, 0x61));
  request2.set('cbBuf', bytesNeeded);
  return (dce as unknown as { request: DceRequestFn }).request<RpcAsyncGetPrinterDriverDirectoryResponse>(
    request2,
    MSRPC_UUID_WINSPOOL,
  );
}

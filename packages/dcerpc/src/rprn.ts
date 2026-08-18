import { uuidtupToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRUNION,
  NDRPOINTER,
  NDRUniConformantArray,
  NULL,
  type NDRField,
} from './ndr';
import {
  DWORD,
  ULONG,
  USHORT,
  LPWSTR,
  ULONGLONG,
  UINT,
} from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_RPRN = uuidtupToBin([
  '12345678-1234-ABCD-EF00-0123456789AB',
  '1.0',
]);

class DCERPCSessionError extends DCERPCException {
  toString(): string {
    return `RPRN SessionError: code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

// 2.2.1.1.7 STRING_HANDLE
export const STRING_HANDLE = LPWSTR;

export class PSTRING_HANDLE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', STRING_HANDLE]];
}

// 2.2.3.1 Access Values
export const JOB_ACCESS_ADMINISTER = 0x00000010;
export const JOB_ACCESS_READ = 0x00000020;
export const JOB_EXECUTE = 0x00020010;
export const JOB_READ = 0x00020020;
export const JOB_WRITE = 0x00020010;
export const JOB_ALL_ACCESS = 0x000f0030;
export const PRINTER_ACCESS_ADMINISTER = 0x00000004;
export const PRINTER_ACCESS_USE = 0x00000008;
export const PRINTER_ACCESS_MANAGE_LIMITED = 0x00000040;
export const PRINTER_ALL_ACCESS = 0x000f000c;
export const PRINTER_EXECUTE = 0x00020008;
export const PRINTER_READ = 0x00020008;
export const PRINTER_WRITE = 0x00020008;
export const SERVER_ACCESS_ADMINISTER = 0x00000001;
export const SERVER_ACCESS_ENUMERATE = 0x00000002;
export const SERVER_ALL_ACCESS = 0x000f0003;
export const SERVER_EXECUTE = 0x00020002;
export const SERVER_READ = 0x00020002;
export const SERVER_WRITE = 0x00020003;
export const SPECIFIC_RIGHTS_ALL = 0x0000ffff;
export const STANDARD_RIGHTS_ALL = 0x001f0000;
export const STANDARD_RIGHTS_EXECUTE = 0x00020000;
export const STANDARD_RIGHTS_READ = 0x00020000;
export const STANDARD_RIGHTS_REQUIRED = 0x000f0000;
export const STANDARD_RIGHTS_WRITE = 0x00020000;
const SYNCHRONIZE = 0x00100000;
const DELETE = 0x00010000;
const READ_CONTROL = 0x00020000;
const WRITE_DAC = 0x00040000;
const WRITE_OWNER = 0x00080000;
const GENERIC_READ = 0x80000000;
const GENERIC_WRITE = 0x40000000;
const GENERIC_EXECUTE = 0x20000000;
const GENERIC_ALL = 0x10000000;

// 2.2.3.6.1 Printer Change Flags for Use with a Printer Handle
export const PRINTER_CHANGE_SET_PRINTER = 0x00000002;
export const PRINTER_CHANGE_DELETE_PRINTER = 0x00000004;
export const PRINTER_CHANGE_PRINTER = 0x000000ff;
export const PRINTER_CHANGE_ADD_JOB = 0x00000100;
export const PRINTER_CHANGE_SET_JOB = 0x00000200;
export const PRINTER_CHANGE_DELETE_JOB = 0x00000400;
export const PRINTER_CHANGE_WRITE_JOB = 0x00000800;
export const PRINTER_CHANGE_JOB = 0x0000ff00;
export const PRINTER_CHANGE_SET_PRINTER_DRIVER = 0x20000000;
export const PRINTER_CHANGE_TIMEOUT = 0x80000000;
export const PRINTER_CHANGE_ALL = 0x7777ffff;
export const PRINTER_CHANGE_ALL_2 = 0x7f77ffff;

// 2.2.3.6.2 Printer Change Flags for Use with a Server Handle
export const PRINTER_CHANGE_ADD_PRINTER_DRIVER = 0x10000000;
export const PRINTER_CHANGE_DELETE_PRINTER_DRIVER = 0x40000000;
export const PRINTER_CHANGE_PRINTER_DRIVER = 0x70000000;
export const PRINTER_CHANGE_ADD_FORM = 0x00010000;
export const PRINTER_CHANGE_DELETE_FORM = 0x00040000;
export const PRINTER_CHANGE_SET_FORM = 0x00020000;
export const PRINTER_CHANGE_FORM = 0x00070000;
export const PRINTER_CHANGE_ADD_PORT = 0x00100000;
export const PRINTER_CHANGE_CONFIGURE_PORT = 0x00200000;
export const PRINTER_CHANGE_DELETE_PORT = 0x00400000;
export const PRINTER_CHANGE_PORT = 0x00700000;
export const PRINTER_CHANGE_ADD_PRINT_PROCESSOR = 0x01000000;
export const PRINTER_CHANGE_DELETE_PRINT_PROCESSOR = 0x04000000;
export const PRINTER_CHANGE_PRINT_PROCESSOR = 0x07000000;
export const PRINTER_CHANGE_ADD_PRINTER = 0x00000001;
export const PRINTER_CHANGE_FAILED_CONNECTION_PRINTER = 0x00000008;
export const PRINTER_CHANGE_SERVER = 0x08000000;

// 2.2.3.7 Printer Enumeration Flags
export const PRINTER_ENUM_LOCAL = 0x00000002;
export const PRINTER_ENUM_CONNECTIONS = 0x00000004;
export const PRINTER_ENUM_NAME = 0x00000008;
export const PRINTER_ENUM_REMOTE = 0x00000010;
export const PRINTER_ENUM_SHARED = 0x00000020;
export const PRINTER_ENUM_NETWORK = 0x00000040;
export const PRINTER_ENUM_EXPAND = 0x00004000;
export const PRINTER_ENUM_CONTAINER = 0x00008000;
export const PRINTER_ENUM_ICON1 = 0x00010000;
export const PRINTER_ENUM_ICON2 = 0x00020000;
export const PRINTER_ENUM_ICON3 = 0x00040000;
export const PRINTER_ENUM_ICON8 = 0x00800000;
export const PRINTER_ENUM_HIDE = 0x01000000;

// 2.2.3.8 Printer Notification Values
export const PRINTER_NOTIFY_CATEGORY_2D = 0x00000000;
export const PRINTER_NOTIFY_CATEGORY_ALL = 0x00010000;
export const PRINTER_NOTIFY_CATEGORY_3D = 0x00020000;

// 3.1.4.4.8 RpcAddPrinterDriverEx Values
export const APD_STRICT_UPGRADE = 0x00000001;
export const APD_STRICT_DOWNGRADE = 0x00000002;
export const APD_COPY_ALL_FILES = 0x00000004;
export const APD_COPY_NEW_FILES = 0x00000008;
export const APD_COPY_FROM_DIRECTORY = 0x00000010;
export const APD_DONT_COPY_FILES_TO_CLUSTER = 0x00001000;
export const APD_COPY_TO_ALL_SPOOLERS = 0x00002000;
export const APD_INSTALL_WARNED_DRIVER = 0x00008000;
export const APD_RETURN_BLOCKING_STATUS_CODE = 0x00010000;

// 2.2.1.1.4 PRINTER_HANDLE
export class PRINTER_HANDLE extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '20s=b""']];
  getAlignment(): number {
    if (this._isNDR64 === true) {
      return 8;
    }
    return 4;
  }
}

// 2.2.1.2.1 DEVMODE_CONTAINER
class BYTE_ARRAY extends NDRUniConformantArray {
  static item = 'c';
}

class PBYTE_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', BYTE_ARRAY]];
}

export class DEVMODE_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cbBuf', DWORD],
    ['pDevMode', PBYTE_ARRAY],
  ];
}

// 2.2.1.11.1 SPLCLIENT_INFO_1
export class SPLCLIENT_INFO_1 extends NDRSTRUCT {
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

export class PSPLCLIENT_INFO_1 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SPLCLIENT_INFO_1]];
}

// 2.2.1.11.2 SPLCLIENT_INFO_2
export class SPLCLIENT_INFO_2 extends NDRSTRUCT {
  static structure: NDRField[] = [['notUsed', ULONGLONG]];
}

export class PSPLCLIENT_INFO_2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SPLCLIENT_INFO_2]];
}

// 2.2.1.11.3 SPLCLIENT_INFO_3
export class SPLCLIENT_INFO_3 extends NDRSTRUCT {
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

export class PSPLCLIENT_INFO_3 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SPLCLIENT_INFO_3]];
}

// 2.2.1.5.1 DRIVER_INFO_1
export class DRIVER_INFO_1 extends NDRSTRUCT {
  static structure: NDRField[] = [['pName', STRING_HANDLE]];
}

export class PDRIVER_INFO_1 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DRIVER_INFO_1]];
}

// 2.2.1.5.2 DRIVER_INFO_2
export class DRIVER_INFO_2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cVersion', DWORD],
    ['pName', LPWSTR],
    ['pEnvironment', LPWSTR],
    ['pDriverPath', LPWSTR],
    ['pDataFile', LPWSTR],
    ['pConfigFile', LPWSTR],
  ];
}

export class PDRIVER_INFO_2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DRIVER_INFO_2]];
}

// 2.2.1.2.3 DRIVER_CONTAINER
export class DRIVER_INFO_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Record<number, NDRField> = {
    1: ['pNotUsed', PDRIVER_INFO_1],
    2: ['Level2', PDRIVER_INFO_2],
  };
}

export class DRIVER_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', DWORD],
    ['DriverInfo', DRIVER_INFO_UNION],
  ];
}

// 2.2.1.2.14 SPLCLIENT_CONTAINER
export class CLIENT_INFO_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', ULONG]];
  static union: Record<number, NDRField> = {
    1: ['pClientInfo1', PSPLCLIENT_INFO_1],
    2: ['pNotUsed1', PSPLCLIENT_INFO_2],
    3: ['pNotUsed2', PSPLCLIENT_INFO_3],
  };
}

export class SPLCLIENT_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', DWORD],
    ['ClientInfo', CLIENT_INFO_UNION],
  ];
}

// 2.2.1.13.2 RPC_V2_NOTIFY_OPTIONS_TYPE
class USHORT_ARRAY extends NDRUniConformantArray {
  static item = '<H';
}

class PUSHORT_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', USHORT_ARRAY]];
}

export class RPC_V2_NOTIFY_OPTIONS_TYPE extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Type', USHORT],
    ['Reserved0', USHORT],
    ['Reserved1', DWORD],
    ['Reserved2', DWORD],
    ['Count', DWORD],
    ['pFields', PUSHORT_ARRAY],
  ];
}

export class PRPC_V2_NOTIFY_OPTIONS_TYPE_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', RPC_V2_NOTIFY_OPTIONS_TYPE],
  ];
}

// 2.2.1.13.1 RPC_V2_NOTIFY_OPTIONS
export class RPC_V2_NOTIFY_OPTIONS extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Version', DWORD],
    ['Reserved', DWORD],
    ['Count', DWORD],
    ['pTypes', PRPC_V2_NOTIFY_OPTIONS_TYPE_ARRAY],
  ];
}

export class PRPC_V2_NOTIFY_OPTIONS extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RPC_V2_NOTIFY_OPTIONS]];
}

// 3.1.4.2.1 RpcEnumPrinters (Opnum 0)
export class RpcEnumPrintersResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pPrinterEnum', PBYTE_ARRAY],
    ['pcbNeeded', DWORD],
    ['pcReturned', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class RpcEnumPrinters extends NDRCALL {
  static opnum = 0;
  static Response = RpcEnumPrintersResponse;
  static structure: NDRField[] = [
    ['Flags', DWORD],
    ['Name', STRING_HANDLE],
    ['Level', DWORD],
    ['pPrinterEnum', PBYTE_ARRAY],
    ['cbBuf', DWORD],
  ];
}

// 3.1.4.2.2 RpcOpenPrinter (Opnum 1)
export class RpcOpenPrinterResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pHandle', PRINTER_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class RpcOpenPrinter extends NDRCALL {
  static opnum = 1;
  static Response = RpcOpenPrinterResponse;
  static structure: NDRField[] = [
    ['pPrinterName', STRING_HANDLE],
    ['pDatatype', LPWSTR],
    ['pDevModeContainer', DEVMODE_CONTAINER],
    ['AccessRequired', DWORD],
  ];
}

// 3.1.4.4.2 RpcEnumPrinterDrivers (Opnum 10)
export class RpcEnumPrinterDriversResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pDrivers', PBYTE_ARRAY],
    ['pcbNeeded', DWORD],
    ['pcReturned', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class RpcEnumPrinterDrivers extends NDRCALL {
  static opnum = 10;
  static Response = RpcEnumPrinterDriversResponse;
  static structure: NDRField[] = [
    ['pName', STRING_HANDLE],
    ['pEnvironment', LPWSTR],
    ['Level', DWORD],
    ['pDrivers', PBYTE_ARRAY],
    ['cbBuf', DWORD],
  ];
}

// 3.1.4.4.4 RpcGetPrinterDriverDirectory (Opnum 12)
export class RpcGetPrinterDriverDirectoryResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pDriverDirectory', PBYTE_ARRAY],
    ['pcbNeeded', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class RpcGetPrinterDriverDirectory extends NDRCALL {
  static opnum = 12;
  static Response = RpcGetPrinterDriverDirectoryResponse;
  static structure: NDRField[] = [
    ['pName', STRING_HANDLE],
    ['pEnvironment', LPWSTR],
    ['Level', DWORD],
    ['pDriverDirectory', PBYTE_ARRAY],
    ['cbBuf', DWORD],
  ];
}

// 3.1.4.2.9 RpcClosePrinter (Opnum 29)
export class RpcClosePrinterResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phPrinter', PRINTER_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class RpcClosePrinter extends NDRCALL {
  static opnum = 29;
  static Response = RpcClosePrinterResponse;
  static structure: NDRField[] = [['phPrinter', PRINTER_HANDLE]];
}

// 3.1.4.10.4 RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)
export class RpcRemoteFindFirstPrinterChangeNotificationExResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcRemoteFindFirstPrinterChangeNotificationEx extends NDRCALL {
  static opnum = 65;
  static Response = RpcRemoteFindFirstPrinterChangeNotificationExResponse;
  static structure: NDRField[] = [
    ['hPrinter', PRINTER_HANDLE],
    ['fdwFlags', DWORD],
    ['fdwOptions', DWORD],
    ['pszLocalMachine', LPWSTR],
    ['dwPrinterLocal', DWORD],
    ['pOptions', PRPC_V2_NOTIFY_OPTIONS],
  ];
}

// 3.1.4.2.14 RpcOpenPrinterEx (Opnum 69)
export class RpcOpenPrinterExResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pHandle', PRINTER_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class RpcOpenPrinterEx extends NDRCALL {
  static opnum = 69;
  static Response = RpcOpenPrinterExResponse;
  static structure: NDRField[] = [
    ['pPrinterName', STRING_HANDLE],
    ['pDatatype', LPWSTR],
    ['pDevModeContainer', DEVMODE_CONTAINER],
    ['AccessRequired', DWORD],
    ['pClientInfo', SPLCLIENT_CONTAINER],
  ];
}

// 3.1.4.4.8 RpcAddPrinterDriverEx (Opnum 89)
export class RpcAddPrinterDriverExResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class RpcAddPrinterDriverEx extends NDRCALL {
  static opnum = 89;
  static Response = RpcAddPrinterDriverExResponse;
  static structure: NDRField[] = [
    ['pName', STRING_HANDLE],
    ['pDriverContainer', DRIVER_CONTAINER],
    ['dwFileCopyFlags', DWORD],
  ];
}

// OPNUMs and their corresponding structures
const OPNUMS: Record<
  number,
  [typeof NDRCALL, typeof NDRCALL]
> = {
  0: [RpcEnumPrinters, RpcEnumPrintersResponse],
  1: [RpcOpenPrinter, RpcOpenPrinterResponse],
  10: [RpcEnumPrinterDrivers, RpcEnumPrinterDriversResponse],
  12: [RpcGetPrinterDriverDirectory, RpcGetPrinterDriverDirectoryResponse],
  29: [RpcClosePrinter, RpcClosePrinterResponse],
  65: [
    RpcRemoteFindFirstPrinterChangeNotificationEx,
    RpcRemoteFindFirstPrinterChangeNotificationExResponse,
  ],
  69: [RpcOpenPrinterEx, RpcOpenPrinterExResponse],
  89: [RpcAddPrinterDriverEx, RpcAddPrinterDriverExResponse],
};

type DceRequestFn = <T>(
  req: unknown,
  uuid?: unknown,
  checkError?: boolean,
) => Promise<T>;

function checkNullString(str: string | typeof NULL): string | typeof NULL {
  if (str === NULL) return str;
  if (typeof str !== 'string') return str;
  if (str.length === 0 || str[str.length - 1] !== '\x00') return str + '\x00';
  return str;
}

export async function hRpcOpenPrinter(
  dce: DCERPC_v5,
  printerName: string,
  pDatatype: string | typeof NULL = NULL,
  pDevModeContainer: DEVMODE_CONTAINER | typeof NULL = NULL,
  accessRequired: number = SERVER_READ,
): Promise<RpcOpenPrinterResponse> {
  const request = new RpcOpenPrinter();
  request.set('pPrinterName', checkNullString(printerName));
  request.set('pDatatype', pDatatype);
  if (pDevModeContainer === NULL) {
    (request.fields['pDevModeContainer'] as DEVMODE_CONTAINER).set(
      'pDevMode',
      NULL,
    );
  } else {
    request.set('pDevModeContainer', pDevModeContainer);
  }
  request.set('AccessRequired', accessRequired);
  return (dce as unknown as { request: DceRequestFn }).request<RpcOpenPrinterResponse>(
    request,
  );
}

export async function hRpcClosePrinter(
  dce: DCERPC_v5,
  phPrinter: PRINTER_HANDLE,
): Promise<RpcClosePrinterResponse> {
  const request = new RpcClosePrinter();
  request.set('phPrinter', phPrinter);
  return (dce as unknown as { request: DceRequestFn }).request<RpcClosePrinterResponse>(
    request,
  );
}

export async function hRpcOpenPrinterEx(
  dce: DCERPC_v5,
  printerName: string,
  pDatatype: string | typeof NULL = NULL,
  pDevModeContainer: DEVMODE_CONTAINER | typeof NULL = NULL,
  accessRequired: number = SERVER_READ,
  pClientInfo: SPLCLIENT_CONTAINER,
): Promise<RpcOpenPrinterExResponse> {
  const request = new RpcOpenPrinterEx();
  request.set('pPrinterName', checkNullString(printerName));
  request.set('pDatatype', pDatatype);
  if (pDevModeContainer === NULL) {
    (request.fields['pDevModeContainer'] as DEVMODE_CONTAINER).set(
      'pDevMode',
      NULL,
    );
  } else {
    request.set('pDevModeContainer', pDevModeContainer);
  }
  request.set('AccessRequired', accessRequired);
  request.set('pClientInfo', pClientInfo);
  return (dce as unknown as { request: DceRequestFn }).request<RpcOpenPrinterExResponse>(
    request,
  );
}

export async function hRpcRemoteFindFirstPrinterChangeNotificationEx(
  dce: DCERPC_v5,
  hPrinter: PRINTER_HANDLE,
  fdwFlags: number,
  fdwOptions: number = 0,
  pszLocalMachine: string,
  dwPrinterLocal: number = 0,
  pOptions: RPC_V2_NOTIFY_OPTIONS | typeof NULL = NULL,
): Promise<RpcRemoteFindFirstPrinterChangeNotificationExResponse> {
  const request = new RpcRemoteFindFirstPrinterChangeNotificationEx();
  request.set('hPrinter', hPrinter);
  request.set('fdwFlags', fdwFlags);
  request.set('fdwOptions', fdwOptions);
  request.set('dwPrinterLocal', dwPrinterLocal);
  request.set('pszLocalMachine', checkNullString(pszLocalMachine));
  request.set('pOptions', pOptions);
  return (dce as unknown as { request: DceRequestFn }).request<RpcRemoteFindFirstPrinterChangeNotificationExResponse>(
    request,
  );
}

export async function hRpcEnumPrinters(
  dce: DCERPC_v5,
  flags: number,
  name: string | typeof NULL = NULL,
  level: number = 1,
): Promise<RpcEnumPrintersResponse> {
  const request1 = new RpcEnumPrinters();
  request1.set('Flags', flags);
  request1.set('Name', name);
  request1.set('pPrinterEnum', NULL);
  request1.set('Level', level);
  request1.set('cbBuf', 0);

  let bytesNeeded = 0;
  try {
    await (dce as unknown as { request: DceRequestFn }).request(request1);
  } catch (e: unknown) {
    if (
      e instanceof DCERPCException &&
      String(e).includes('ERROR_INSUFFICIENT_BUFFER')
    ) {
      const pkt = (e as DCERPCException).getPacket() as { get(k: string): unknown } | null;
      bytesNeeded = (pkt?.get('pcbNeeded') as number) ?? 0;
    } else {
      throw e;
    }
  }

  const request2 = new RpcEnumPrinters();
  request2.set('Flags', flags);
  request2.set('Name', name);
  request2.set('Level', level);
  request2.set('cbBuf', bytesNeeded);
  request2.set('pPrinterEnum', Buffer.alloc(bytesNeeded, 0x61));
  return (dce as unknown as { request: DceRequestFn }).request<RpcEnumPrintersResponse>(
    request2,
  );
}

export async function hRpcAddPrinterDriverEx(
  dce: DCERPC_v5,
  pName: string,
  pDriverContainer: DRIVER_CONTAINER,
  dwFileCopyFlags: number,
): Promise<RpcAddPrinterDriverExResponse> {
  const request = new RpcAddPrinterDriverEx();
  request.set('pName', checkNullString(pName));
  request.set('pDriverContainer', pDriverContainer);
  request.set('dwFileCopyFlags', dwFileCopyFlags);
  return (dce as unknown as { request: DceRequestFn }).request<RpcAddPrinterDriverExResponse>(
    request,
  );
}

export async function hRpcEnumPrinterDrivers(
  dce: DCERPC_v5,
  pName: string,
  pEnvironment: string,
  level: number,
): Promise<RpcEnumPrinterDriversResponse> {
  const request1 = new RpcEnumPrinterDrivers();
  request1.set('pName', checkNullString(pName));
  request1.set('pEnvironment', pEnvironment);
  request1.set('Level', level);
  request1.set('pDrivers', NULL);
  request1.set('cbBuf', 0);

  let bytesNeeded = 0;
  try {
    await (dce as unknown as { request: DceRequestFn }).request(request1);
  } catch (e: unknown) {
    if (
      e instanceof DCERPCException &&
      String(e).includes('ERROR_INSUFFICIENT_BUFFER')
    ) {
      const pkt = (e as DCERPCException).getPacket() as { get(k: string): unknown } | null;
      bytesNeeded = (pkt?.get('pcbNeeded') as number) ?? 0;
    } else {
      throw e;
    }
  }

  const request2 = new RpcEnumPrinterDrivers();
  request2.set('pName', checkNullString(pName));
  request2.set('pEnvironment', pEnvironment);
  request2.set('Level', level);
  request2.set('pDrivers', Buffer.alloc(bytesNeeded, 0x61));
  request2.set('cbBuf', bytesNeeded);
  return (dce as unknown as { request: DceRequestFn }).request<RpcEnumPrinterDriversResponse>(
    request2,
  );
}

export async function hRpcGetPrinterDriverDirectory(
  dce: DCERPC_v5,
  pName: string,
  pEnvironment: string,
  level: number,
): Promise<RpcGetPrinterDriverDirectoryResponse> {
  const request1 = new RpcGetPrinterDriverDirectory();
  request1.set('pName', checkNullString(pName));
  request1.set('pEnvironment', pEnvironment);
  request1.set('Level', level);
  request1.set('pDriverDirectory', NULL);
  request1.set('cbBuf', 0);

  let bytesNeeded = 0;
  try {
    await (dce as unknown as { request: DceRequestFn }).request(request1);
  } catch (e: unknown) {
    if (
      e instanceof DCERPCException &&
      String(e).includes('ERROR_INSUFFICIENT_BUFFER')
    ) {
      const pkt = (e as DCERPCException).getPacket() as { get(k: string): unknown } | null;
      bytesNeeded = (pkt?.get('pcbNeeded') as number) ?? 0;
    } else {
      throw e;
    }
  }

  const request2 = new RpcGetPrinterDriverDirectory();
  request2.set('pName', checkNullString(pName));
  request2.set('pEnvironment', pEnvironment);
  request2.set('Level', level);
  request2.set('pDriverDirectory', Buffer.alloc(bytesNeeded, 0x61));
  request2.set('cbBuf', bytesNeeded);
  return (dce as unknown as { request: DceRequestFn }).request<RpcGetPrinterDriverDirectoryResponse>(
    request2,
  );
}

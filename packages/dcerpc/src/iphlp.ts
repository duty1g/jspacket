import { uuidtupToBin, stringToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRUniConformantArray,
  NULL,
  type NDRField,
} from './ndr';
import { BYTE, ULONG, WSTR, GUID } from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_IPHLP_IP_TRANSITION = uuidtupToBin([
  '552d076a-cb29-4e44-8b6a-d15e59e2c0af',
  '1.0',
]);

export const MSRPC_UUID_IPHLP_TEREDO = uuidtupToBin([
  'ecbdb051-f208-46b9-8c8b-648d9d3f3944',
  '1.0',
]);

export const MSRPC_UUID_IPHLP_TEREDO_CONSUMER = uuidtupToBin([
  '1fff8faa-ec23-4e3f-a8ce-4b2f8707e636',
  '1.0',
]);

class DCERPCSessionError extends DCERPCException {
  toString(): string {
    return `IPHLP SessionError: code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

// Notification types
export const NOTIFICATION_ISATAP_CONFIGURATION_CHANGE = 0;
export const NOTIFICATION_PROCESS6TO4_CONFIGURATION_CHANGE = 1;
export const NOTIFICATION_TEREDO_CONFIGURATION_CHANGE = 2;
export const NOTIFICATION_IP_TLS_CONFIGURATION_CHANGE = 3;
export const NOTIFICATION_PORT_CONFIGURATION_CHANGE = 4;
export const NOTIFICATION_DNS64_CONFIGURATION_CHANGE = 5;
export const NOTIFICATION_DA_SITE_MGR_LOCAL_CONFIGURATION_CHANGE_EX = 6;

class BYTE_ARRAY extends NDRUniConformantArray {
  static item = 'c';
}

// Opnum 0
export class IpTransitionProtocolApplyConfigChangesResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class IpTransitionProtocolApplyConfigChanges extends NDRCALL {
  static opnum = 0;
  static Response = IpTransitionProtocolApplyConfigChangesResponse;
  static structure: NDRField[] = [['NotificationNum', BYTE]];
}

// Opnum 1
export class IpTransitionProtocolApplyConfigChangesExResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class IpTransitionProtocolApplyConfigChangesEx extends NDRCALL {
  static opnum = 1;
  static Response = IpTransitionProtocolApplyConfigChangesExResponse;
  static structure: NDRField[] = [
    ['NotificationNum', BYTE],
    ['DataLength', ULONG],
    ['Data', BYTE_ARRAY],
  ];
}

// Opnum 2
export class IpTransitionCreatev6Inv4TunnelResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class IpTransitionCreatev6Inv4Tunnel extends NDRCALL {
  static opnum = 2;
  static Response = IpTransitionCreatev6Inv4TunnelResponse;
  static structure: NDRField[] = [
    ['LocalAddress', "4s=''"],
    ['RemoteAddress', "4s=''"],
    ['InterfaceName', WSTR],
  ];
}

// Opnum 3
export class IpTransitionDeletev6Inv4TunnelResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class IpTransitionDeletev6Inv4Tunnel extends NDRCALL {
  static opnum = 3;
  static Response = IpTransitionDeletev6Inv4TunnelResponse;
  static structure: NDRField[] = [['TunnelGuid', GUID]];
}

const OPNUMS: Record<number, [typeof NDRCALL, typeof NDRCALL]> = {
  0: [IpTransitionProtocolApplyConfigChanges, IpTransitionProtocolApplyConfigChangesResponse],
  1: [IpTransitionProtocolApplyConfigChangesEx, IpTransitionProtocolApplyConfigChangesExResponse],
  2: [IpTransitionCreatev6Inv4Tunnel, IpTransitionCreatev6Inv4TunnelResponse],
  3: [IpTransitionDeletev6Inv4Tunnel, IpTransitionDeletev6Inv4TunnelResponse],
};

function checkNullString(str: string | typeof NULL): string | typeof NULL {
  if (str === NULL) return str;
  if (typeof str !== 'string') return str;
  if (str.length === 0 || str[str.length - 1] !== '\x00') return str + '\x00';
  return str;
}

function inetAton(address: string): Buffer {
  return Buffer.from(address.split('.').map(p => parseInt(p, 10)));
}

type DceRequestFn = <T>(
  req: unknown,
  uuid?: unknown,
  checkError?: boolean,
) => Promise<T>;

export async function hIpTransitionProtocolApplyConfigChanges(
  dce: DCERPC_v5,
  notificationNum: number,
): Promise<IpTransitionProtocolApplyConfigChangesResponse> {
  const request = new IpTransitionProtocolApplyConfigChanges();
  request.set('NotificationNum', notificationNum);
  return (dce as unknown as { request: DceRequestFn }).request<IpTransitionProtocolApplyConfigChangesResponse>(
    request,
  );
}

export async function hIpTransitionProtocolApplyConfigChangesEx(
  dce: DCERPC_v5,
  notificationNum: number,
  notificationData: Buffer,
): Promise<IpTransitionProtocolApplyConfigChangesExResponse> {
  const request = new IpTransitionProtocolApplyConfigChangesEx();
  request.set('NotificationNum', notificationNum);
  request.set('DataLength', notificationData.length);
  request.set('Data', notificationData);
  return (dce as unknown as { request: DceRequestFn }).request<IpTransitionProtocolApplyConfigChangesExResponse>(
    request,
  );
}

export async function hIpTransitionCreatev6Inv4Tunnel(
  dce: DCERPC_v5,
  localAddress: string,
  remoteAddress: string,
  interfaceName: string,
): Promise<IpTransitionCreatev6Inv4TunnelResponse> {
  const request = new IpTransitionCreatev6Inv4Tunnel();
  request.set('LocalAddress', inetAton(localAddress));
  request.set('RemoteAddress', inetAton(remoteAddress));
  request.set('InterfaceName', checkNullString(interfaceName));
  const wstrField = request.fields['InterfaceName'] as { fields: Record<string, unknown> };
  wstrField.fields['MaximumCount'] = 256;
  return (dce as unknown as { request: DceRequestFn }).request<IpTransitionCreatev6Inv4TunnelResponse>(
    request,
  );
}

export async function hIpTransitionDeletev6Inv4Tunnel(
  dce: DCERPC_v5,
  tunnelGuid: string,
): Promise<IpTransitionDeletev6Inv4TunnelResponse> {
  const request = new IpTransitionDeletev6Inv4Tunnel();
  request.set('TunnelGuid', stringToBin(tunnelGuid));
  return (dce as unknown as { request: DceRequestFn }).request<IpTransitionDeletev6Inv4TunnelResponse>(
    request,
  );
}

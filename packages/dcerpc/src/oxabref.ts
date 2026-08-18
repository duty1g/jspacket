import { uuidtupToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRPOINTER,
  NULL,
  type NDRField,
} from './ndr';
import { ULONG, STR } from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_OXABREF = uuidtupToBin([
  '1544F5E0-613C-11D1-93DF-00C04FD7BD09',
  '1.0',
]);

class DCERPCSessionError extends DCERPCException {
  toString(): string {
    return `OXABREF SessionError: code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

class PUCHAR_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', STR]];
}

class PPUCHAR_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', PUCHAR_ARRAY]];
}

// 3.1.4.1 RfrGetNewDSA (opnum 0)
export class RfrGetNewDSAResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppszUnused', PPUCHAR_ARRAY],
    ['ppszServer', PPUCHAR_ARRAY],
  ];
}

export class RfrGetNewDSA extends NDRCALL {
  static opnum = 0;
  static Response = RfrGetNewDSAResponse;
  static structure: NDRField[] = [
    ['ulFlags', ULONG],
    ['pUserDN', STR],
    ['ppszUnused', PPUCHAR_ARRAY],
    ['ppszServer', PPUCHAR_ARRAY],
  ];
}

// 3.1.4.2 RfrGetFQDNFromServerDN (opnum 1)
export class RfrGetFQDNFromServerDNResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppszServerFQDN', PUCHAR_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class RfrGetFQDNFromServerDN extends NDRCALL {
  static opnum = 1;
  static Response = RfrGetFQDNFromServerDNResponse;
  static structure: NDRField[] = [
    ['ulFlags', ULONG],
    ['cbMailboxServerDN', ULONG],
    ['szMailboxServerDN', STR],
  ];
}

const OPNUMS: Record<number, [typeof NDRCALL, typeof NDRCALL]> = {
  0: [RfrGetNewDSA, RfrGetNewDSAResponse],
  1: [RfrGetFQDNFromServerDN, RfrGetFQDNFromServerDNResponse],
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

export async function hRfrGetNewDSA(
  dce: DCERPC_v5,
  pUserDN: string = '',
): Promise<RfrGetNewDSAResponse> {
  const request = new RfrGetNewDSA();
  request.set('ulFlags', 0);
  request.set('pUserDN', checkNullString(pUserDN));
  request.set('ppszUnused', NULL);
  request.set('ppszServer', '\x00');
  return (dce as unknown as { request: DceRequestFn }).request<RfrGetNewDSAResponse>(
    request,
  );
}

export async function hRfrGetFQDNFromServerDN(
  dce: DCERPC_v5,
  szMailboxServerDN: string,
): Promise<RfrGetFQDNFromServerDNResponse> {
  const dn = checkNullString(szMailboxServerDN) as string;
  const request = new RfrGetFQDNFromServerDN();
  request.set('ulFlags', 0);
  request.set('szMailboxServerDN', dn);
  request.set('cbMailboxServerDN', dn.length);
  return (dce as unknown as { request: DceRequestFn }).request<RfrGetFQDNFromServerDNResponse>(
    request,
  );
}

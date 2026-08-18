import { Buffer } from 'node:buffer';
import { uuidtupToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRPOINTER,
  NDRUniConformantArray,
  NDRUniConformantVaryingArray,
  type NDRField,
} from './ndr';
import { PRPC_IF_ID } from './epm';
import { ULONG, DWORD_ARRAY, ULONGLONG } from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_MGMT = uuidtupToBin(['afa8bd80-7d8a-11c9-bef4-08002b102989', '1.0'])!;

class MGMTSessionError extends DCERPCException {
  constructor(errorString?: string | null, errorCode?: number | null, packet?: unknown) {
    super(errorString, errorCode, packet);
    if (packet) {
      this.error_code = (packet as { get: (k: string) => unknown }).get('status') as number;
    }
  }

  toString(): string {
    const key = this.error_code;
    if (key != null) {
      return `MGMT SessionError: code: 0x${key.toString(16)}`;
    }
    return `MGMT SessionError: unknown error code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

export class RpcIfIdPTArray extends NDRUniConformantArray {
  static item = PRPC_IF_ID;
}

export class RpcIfIdVectorT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['count', ULONG],
    ['if_id', RpcIfIdPTArray],
  ];
  static structure64: NDRField[] = [
    ['count', ULONGLONG],
    ['if_id', RpcIfIdPTArray],
  ];
}

export class RpcIfIdVectorPT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RpcIfIdVectorT]];
}

const MGMTErrorStatus = ULONG;

export class InqIfIdsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['if_id_vector', RpcIfIdVectorPT],
    ['status', MGMTErrorStatus],
  ];
}

export class InqIfIds extends NDRCALL {
  static opnum = 0;
  static structure: NDRField[] = [];
  static Response = InqIfIdsResponse;
}

export class InqStatsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['count', ULONG],
    ['statistics', DWORD_ARRAY],
    ['status', MGMTErrorStatus],
  ];
}

export class InqStats extends NDRCALL {
  static opnum = 1;
  static structure: NDRField[] = [['count', ULONG]];
  static Response = InqStatsResponse;
}

export class IsServerListeningResponse extends NDRCALL {
  static structure: NDRField[] = [['status', MGMTErrorStatus]];
}

export class IsServerListening extends NDRCALL {
  static opnum = 2;
  static structure: NDRField[] = [];
  static Response = IsServerListeningResponse;
}

export class StopServerListeningResponse extends NDRCALL {
  static structure: NDRField[] = [['status', MGMTErrorStatus]];
}

export class StopServerListening extends NDRCALL {
  static opnum = 3;
  static structure: NDRField[] = [];
  static Response = StopServerListeningResponse;
}

export class InqPrincNameResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['princ_name', NDRUniConformantVaryingArray],
    ['status', MGMTErrorStatus],
  ];
}

export class InqPrincName extends NDRCALL {
  static opnum = 4;
  static structure: NDRField[] = [
    ['authn_proto', ULONG],
    ['princ_name_size', ULONG],
  ];
  static Response = InqPrincNameResponse;
}

const OPNUMS = {
  0: [InqIfIds, InqIfIdsResponse] as const,
  1: [InqStats, InqStatsResponse] as const,
  2: [IsServerListening, IsServerListeningResponse] as const,
  3: [StopServerListening, StopServerListeningResponse] as const,
  4: [InqPrincName, InqPrincNameResponse] as const,
};

type DceRequestFn = <T>(req: unknown, uuid?: unknown, checkError?: boolean) => Promise<T>;

export async function hinqIfIds(dce: DCERPC_v5) {
  const request = new InqIfIds();
  return (dce as unknown as { request: DceRequestFn }).request<InqIfIdsResponse>(request);
}

export async function hinqStats(dce: DCERPC_v5, count = 4) {
  const request = new InqStats();
  request.set('count', count);
  return (dce as unknown as { request: DceRequestFn }).request<InqStatsResponse>(request);
}

export async function hisServerListening(dce: DCERPC_v5) {
  const request = new IsServerListening();
  return (dce as unknown as { request: DceRequestFn }).request<IsServerListeningResponse>(request, null, false);
}

export async function hstopServerListening(dce: DCERPC_v5) {
  const request = new StopServerListening();
  return (dce as unknown as { request: DceRequestFn }).request<StopServerListeningResponse>(request);
}

export async function hinqPrincName(dce: DCERPC_v5, authnProto = 0, princNameSize = 1) {
  const request = new InqPrincName();
  request.set('authn_proto', authnProto);
  request.set('princ_name_size', princNameSize);
  return (dce as unknown as { request: DceRequestFn }).request<InqPrincNameResponse>(request, null, false);
}

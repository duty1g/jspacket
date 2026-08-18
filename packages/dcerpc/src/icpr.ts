import { uuidtupToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRSTRUCT,
  NULL,
  type NDRField,
} from './ndr';
import { DWORD, ULONG, LPWSTR, PBYTE } from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_ICPR = uuidtupToBin([
  '91ae6020-9e3c-11cf-8d7c-00aa00c091be',
  '0.0',
]);

class DCERPCSessionError extends DCERPCException {
  toString(): string {
    const code = (this.error_code ?? 0) & 0xffffffff;
    return `ICPR SessionError: code: 0x${code.toString(16)}`;
  }
}

function checkNullString(str: string | typeof NULL): string | typeof NULL {
  if (str === NULL) return str;
  if (typeof str !== 'string') return str;
  if (str.length === 0 || str[str.length - 1] !== '\x00') return str + '\x00';
  return str;
}

export function translateErrorCode(errorCode: number): string {
  const code = errorCode & 0xffffffff;
  return `unknown error code: 0x${code.toString(16)}`;
}

// [MS-WCCE] 2.2.2.2
export class CERTTRANSBLOB extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cb', ULONG],
    ['pb', PBYTE],
  ];
}

export class CertServerRequestResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pdwRequestId', DWORD],
    ['pdwDisposition', ULONG],
    ['pctbCert', CERTTRANSBLOB],
    ['pctbEncodedCert', CERTTRANSBLOB],
    ['pctbDispositionMessage', CERTTRANSBLOB],
  ];
}

export class CertServerRequest extends NDRCALL {
  static opnum = 0;
  static Response = CertServerRequestResponse;
  static structure: NDRField[] = [
    ['dwFlags', DWORD],
    ['pwszAuthority', LPWSTR],
    ['pdwRequestId', DWORD],
    ['pctbAttribs', CERTTRANSBLOB],
    ['pctbRequest', CERTTRANSBLOB],
  ];
}

const OPNUMS: Record<number, [typeof NDRCALL, typeof NDRCALL]> = {
  0: [CertServerRequest, CertServerRequestResponse],
};

type DceRequestFn = <T>(
  req: unknown,
  uuid?: unknown,
  checkError?: boolean,
) => Promise<T>;

export async function hCertServerRequest(
  dce: DCERPC_v5,
  csr: Buffer,
  attributes: string[],
  requestId: number = 0,
  ca: string = '',
): Promise<CertServerRequestResponse> {
  const attribs = Buffer.from(
    (checkNullString(attributes.join('\n')) as string),
    'utf16le',
  );
  const pctbAttribs = new CERTTRANSBLOB();
  pctbAttribs.set('cb', attribs.length);
  pctbAttribs.set('pb', attribs);

  const pctbRequest = new CERTTRANSBLOB();
  pctbRequest.set('cb', csr.length);
  pctbRequest.set('pb', csr);

  const request = new CertServerRequest();
  request.set('dwFlags', 0);
  request.set('pwszAuthority', checkNullString(ca));
  request.set('pdwRequestId', requestId);
  request.set('pctbAttribs', pctbAttribs);
  request.set('pctbRequest', pctbRequest);

  return (dce as unknown as { request: DceRequestFn }).request<CertServerRequestResponse>(
    request,
  );
}

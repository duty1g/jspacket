import { uuidtupToBin, stringToBin } from '@impacket/uuid';
import { Structure, type FieldDescriptor } from '@impacket/structure';
import {
  NDRCALL,
  NDRPOINTER,
  NDRUniConformantArray,
  NULL,
  type NDRField,
} from './ndr';
import { DWORD, NTSTATUS, GUID } from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_BKRP = uuidtupToBin([
  '3dde7c30-165d-11d1-ab8f-00805f14db40',
  '1.0',
]);

class DCERPCSessionError extends DCERPCException {
  toString(): string {
    return `BKRP SessionError: code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

export const BACKUPKEY_BACKUP_GUID = stringToBin(
  '7F752B10-178E-11D1-AB8F-00805F14DB40',
);
export const BACKUPKEY_RESTORE_GUID_WIN2K = stringToBin(
  '7FE94D50-178E-11D1-AB8F-00805F14DB40',
);
export const BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID = stringToBin(
  '018FF48A-EABA-40C6-8F6D-72370240E967',
);
export const BACKUPKEY_RESTORE_GUID = stringToBin(
  '47270C64-2FC7-499B-AC5B-0E37CDCE899A',
);

class BYTE_ARRAY extends NDRUniConformantArray {
  static item = 'c';
}

class PBYTE_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', BYTE_ARRAY]];
}

export class Rc4EncryptedPayload extends Structure {
  static structure: FieldDescriptor[] = [
    ['R3', '32s=""'],
    ['MAC', '20s=""'],
    ['SID', ':'],
    ['Secret', ':'],
  ];
}

export class WRAPPED_SECRET extends Structure {
  static structure: FieldDescriptor[] = [
    ['SIGNATURE', '<L=1'],
    ['Payload_Length', '<L=0'],
    ['Ciphertext_Length', '<L=0'],
    ['GUID_of_Wrapping_Key', '16s=""'],
    ['R2', '68s=""'],
    ['_Rc4EncryptedPayload', '_-Rc4EncryptedPayload', 'self["Payload_Length"]'],
    ['Rc4EncryptedPayload', ':'],
  ];
}

// 3.1.4.1 BackuprKey (Opnum 0)
export class BackuprKeyResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppDataOut', PBYTE_ARRAY],
    ['pcbDataOut', DWORD],
    ['ErrorCode', NTSTATUS],
  ];
}

export class BackuprKey extends NDRCALL {
  static opnum = 0;
  static Response = BackuprKeyResponse;
  static structure: NDRField[] = [
    ['pguidActionAgent', GUID],
    ['pDataIn', BYTE_ARRAY],
    ['cbDataIn', DWORD],
    ['dwParam', DWORD],
  ];
}

const OPNUMS: Record<number, [typeof NDRCALL, typeof NDRCALL]> = {
  0: [BackuprKey, BackuprKeyResponse],
};

type DceRequestFn = <T>(
  req: unknown,
  uuid?: unknown,
  checkError?: boolean,
) => Promise<T>;

export async function hBackuprKey(
  dce: DCERPC_v5,
  pguidActionAgent: Buffer,
  pDataIn: Buffer | typeof NULL,
  dwParam: number = 0,
): Promise<BackuprKeyResponse> {
  const request = new BackuprKey();
  request.set('pguidActionAgent', pguidActionAgent);
  request.set('pDataIn', pDataIn);
  if (pDataIn === NULL) {
    request.set('cbDataIn', 0);
  } else {
    request.set('cbDataIn', (pDataIn as Buffer).length);
  }
  request.set('dwParam', dwParam);
  return (dce as unknown as { request: DceRequestFn }).request<BackuprKeyResponse>(
    request,
  );
}

import { randomBytes } from 'crypto';
import { uuidtupToBin } from '@impacket/uuid';
import { Structure, type FieldDescriptor } from '@impacket/structure';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRPOINTER,
  NDRUniConformantArray,
  type NDRField,
} from './ndr';
import { DWORD, ULONG } from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_MIMIKATZ = uuidtupToBin([
  '17FC11E9-C258-4B8D-8D07-2F4125156244',
  '1.0',
]);

class DCERPCSessionError extends DCERPCException {
  toString(): string {
    return `Mimikatz SessionError: code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

// Constants
export const CALG_DH_EPHEM = 0x0000aa02;
export const TPUBLICKEYBLOB = 0x6;
export const CUR_BLOB_VERSION = 0x2;
export const ALG_ID = DWORD;
export const CALG_RC4 = 0x6801;

// Structures
export class PUBLICKEYSTRUC extends Structure {
  static structure: FieldDescriptor[] = [
    ['bType', 'B=0'],
    ['bVersion', 'B=0'],
    ['reserved', '<H=0'],
    ['aiKeyAlg', '<L=0'],
  ];

  constructor(data?: Buffer | null, alignment?: number) {
    super(data, alignment);
    if (!data) {
      this.set('bType', TPUBLICKEYBLOB);
      this.set('bVersion', CUR_BLOB_VERSION);
      this.set('aiKeyAlg', CALG_DH_EPHEM);
    }
  }
}

export class DHPUBKEY extends Structure {
  static structure: FieldDescriptor[] = [
    ['magic', '<L=0'],
    ['bitlen', '<L=0'],
  ];

  constructor(data?: Buffer | null, alignment?: number) {
    super(data, alignment);
    if (!data) {
      this.set('magic', 0x31484400);
      this.set('bitlen', 1024);
    }
  }
}

export class PUBLICKEYBLOB extends Structure {
  static structure: FieldDescriptor[] = [
    ['publickeystruc', ':', PUBLICKEYSTRUC],
    ['dhpubkey', ':', DHPUBKEY],
    ['yLen', '_-y', '128'],
    ['y', ':'],
  ];

  constructor(data?: Buffer | null, alignment?: number) {
    super(data, alignment);
    if (!data) {
      this.set('publickeystruc', new PUBLICKEYSTRUC().getData());
      this.set('dhpubkey', new DHPUBKEY().getData());
    }
  }
}

export class MIMI_HANDLE extends NDRSTRUCT {
  static structure: NDRField[] = [['Data', '20s=""']];

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

export class MIMI_PUBLICKEY extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sessionType', DWORD],
    ['cbPublicKey', DWORD],
    ['pbPublicKey', PBYTE_ARRAY],
  ];
}

export class PMIMI_PUBLICKEY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', MIMI_PUBLICKEY]];
}

// RPC Calls
export class MimiBindResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['serverPublicKey', MIMI_PUBLICKEY],
    ['phMimi', MIMI_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class MimiBind extends NDRCALL {
  static opnum = 0;
  static Response = MimiBindResponse;
  static structure: NDRField[] = [['clientPublicKey', MIMI_PUBLICKEY]];
}

export class MimiUnbindResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['phMimi', MIMI_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class MimiUnbind extends NDRCALL {
  static opnum = 1;
  static Response = MimiUnbindResponse;
  static structure: NDRField[] = [['phMimi', MIMI_HANDLE]];
}

export class MimiCommandResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['szEncResult', DWORD],
    ['encResult', PBYTE_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class MimiCommand extends NDRCALL {
  static opnum = 2;
  static Response = MimiCommandResponse;
  static structure: NDRField[] = [
    ['phMimi', MIMI_HANDLE],
    ['szEncCommand', DWORD],
    ['encCommand', PBYTE_ARRAY],
  ];
}

const OPNUMS: Record<number, [typeof NDRCALL, typeof NDRCALL]> = {
  0: [MimiBind, MimiBindResponse],
  1: [MimiUnbind, MimiUnbindResponse],
  2: [MimiCommand, MimiCommandResponse],
};

// Diffie-Hellman key exchange helper
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod;
    }
    exp = exp / 2n;
    base = (base * base) % mod;
  }
  return result;
}

function bigintToBuffer(n: bigint): Buffer {
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

export class MimiDiffeH {
  G = 2n;
  P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFFn;
  privateKey: bigint;
  publicKey: bigint = 0n;
  sharedSecret: bigint = 0n;

  constructor() {
    const bytes = randomBytes(128);
    this.privateKey = BigInt('0x' + bytes.toString('hex'));
  }

  genPublicKey(): Buffer {
    this.publicKey = modPow(this.G, this.privateKey, this.P);
    return bigintToBuffer(this.publicKey);
  }

  getSharedSecret(serverPublicKey: Buffer): Buffer {
    const pubKey = BigInt('0x' + serverPublicKey.toString('hex'));
    this.sharedSecret = modPow(pubKey, this.privateKey, this.P);
    return bigintToBuffer(this.sharedSecret);
  }
}

type DceRequestFn = <T>(
  req: unknown,
  uuid?: unknown,
  checkError?: boolean,
) => Promise<T>;

export async function hMimiBind(
  dce: DCERPC_v5,
  clientPublicKey: MIMI_PUBLICKEY,
): Promise<MimiBindResponse> {
  const request = new MimiBind();
  request.set('clientPublicKey', clientPublicKey);
  return (dce as unknown as { request: DceRequestFn }).request<MimiBindResponse>(
    request,
  );
}

export async function hMimiCommand(
  dce: DCERPC_v5,
  phMimi: MIMI_HANDLE,
  encCommand: Buffer,
): Promise<MimiCommandResponse> {
  const request = new MimiCommand();
  request.set('phMimi', phMimi);
  request.set('szEncCommand', encCommand.length);
  request.set('encCommand', [...encCommand]);
  return (dce as unknown as { request: DceRequestFn }).request<MimiCommandResponse>(
    request,
  );
}

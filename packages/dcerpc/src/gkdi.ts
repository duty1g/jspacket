import { uuidtupToBin } from '@impacket/uuid';
import { Structure, type FieldDescriptor } from '@impacket/structure';
import {
  NDRCALL,
  NDRPOINTER,
  NDRUniConformantArray,
  NULL,
  type NDRField,
} from './ndr';
import { ULONG, PGUID, LONG, NTSTATUS } from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_GKDI = uuidtupToBin([
  'B9785960-524F-11DF-8B6D-83DCDED72085',
  '1.0',
]);

class DCERPCSessionError extends DCERPCException {
  toString(): string {
    return `GKDI SessionError: code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

// 2.2.1 KDF Parameters
export class KDFParameter extends Structure {
  static structure: FieldDescriptor[] = [
    ['Unknown1', '<L=0'],
    ['Unknown2', '<L=0'],
    ['HashLen', '<L=0'],
    ['Unknown3', '<L=0'],
    ['_HashName', '_-HashName', 'self["HashLen"]'],
    ['HashName', ':'],
  ];
}

// 2.2.2 FFC DH Parameters
export class FFCDHParameter extends Structure {
  static structure: FieldDescriptor[] = [
    ['Length', '<L=0'],
    ['Magic', '<4s=0'],
    ['KeyLength', '<L=0'],
    ['_FieldOrder', '_-FieldOrder', 'self["KeyLength"]'],
    ['FieldOrder', ':'],
    ['_Generator', '_-Generator', 'self["KeyLength"]'],
    ['Generator', ':'],
  ];
}

// 2.2.3.1 FFC DH Key
export class FFCDHKey extends Structure {
  static structure: FieldDescriptor[] = [
    ['Magic', '<4s=0'],
    ['KeyLength', '<L=0'],
    ['_FieldOrder', '_-FieldOrder', 'self["KeyLength"]'],
    ['FieldOrder', ':'],
    ['_Generator', '_-Generator', 'self["KeyLength"]'],
    ['Generator', ':'],
    ['_PubKey', '_-PubKey', 'self["KeyLength"]'],
    ['PubKey', ':'],
  ];
}

// 2.2.3.2 ECDH Key
export class ECDHKey extends Structure {
  static structure: FieldDescriptor[] = [
    ['Magic', '<4s=0'],
    ['KeyLength', '<L=0'],
    ['_XCoordinate', '_-XCoordinate', 'self["KeyLength"]'],
    ['XCoordinate', ':'],
    ['_YCoordinate', '_-YCoordinate', 'self["KeyLength"]'],
    ['YCoordinate', ':'],
  ];
}

// 2.2.4 Group Key Envelope
export class GroupKeyEnvelope extends Structure {
  static structure: FieldDescriptor[] = [
    ['Version', '<L=0'],
    ['Magic', '<L=0'],
    ['Flags', '<L=0'],
    ['L0Index', '<L=0'],
    ['L1Index', '<L=0'],
    ['L2Index', '<L=0'],
    ['RootKeyId', '16s=b'],
    ['KdfAlgoLength', '<L=0'],
    ['KdfParaLength', '<L=0'],
    ['SecAlgoLength', '<L=0'],
    ['SecParaLength', '<L=0'],
    ['PrivKeyLength', '<L=0'],
    ['PubKeyLength', '<L=0'],
    ['L1KeyLength', '<L=0'],
    ['L2KeyLength', '<L=0'],
    ['DomainLength', '<L=0'],
    ['ForestLength', '<L=0'],
    ['_KdfAlgo', '_-KdfAlgo', 'self["KdfAlgoLength"]'],
    ['KdfAlgo', ':'],
    ['_KdfPara', '_-KdfPara', 'self["KdfParaLength"]'],
    ['KdfPara', ':', KDFParameter],
    ['_SecAlgo', '_-SecAlgo', 'self["SecAlgoLength"]'],
    ['SecAlgo', ':'],
    ['_SecPara', '_-SecPara', 'self["SecParaLength"]'],
    ['SecPara', ':'],
    ['_Domain', '_-Domain', 'self["DomainLength"]'],
    ['Domain', ':'],
    ['_Forest', '_-Forest', 'self["ForestLength"]'],
    ['Forest', ':'],
    ['_L1Key', '_-L1Key', 'self["L1KeyLength"]'],
    ['L1Key', ':'],
    ['_L2Key', '_-L2Key', 'self["L2KeyLength"]'],
    ['L2Key', ':'],
  ];
}

class BYTE_ARRAY extends NDRUniConformantArray {
  static item = 'c';
}

class PBYTE_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', BYTE_ARRAY]];
}

// 3.1.4.1 GetKey (Opnum 0)
export class GkdiRpcGetKeyResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pcbOut', ULONG],
    ['pbbOut', PBYTE_ARRAY],
    ['ErrorCode', NTSTATUS],
  ];
}

export class GkdiRpcGetKey extends NDRCALL {
  static opnum = 0;
  static Response = GkdiRpcGetKeyResponse;
  static structure: NDRField[] = [
    ['cbTargetSD', ULONG],
    ['pbTargetSD', BYTE_ARRAY],
    ['pRootKeyID', PGUID],
    ['L0KeyID', LONG],
    ['L1KeyID', LONG],
    ['L2KeyID', LONG],
  ];
}

const OPNUMS: Record<number, [typeof NDRCALL, typeof NDRCALL]> = {
  0: [GkdiRpcGetKey, GkdiRpcGetKeyResponse],
};

type DceRequestFn = <T>(
  req: unknown,
  uuid?: unknown,
  checkError?: boolean,
) => Promise<T>;

export async function GkdiGetKey(
  dce: DCERPC_v5,
  targetSd: { getData(): Buffer },
  l0: number = -1,
  l1: number = -1,
  l2: number = -1,
  rootKeyId: typeof NULL | Buffer = NULL,
): Promise<GkdiRpcGetKeyResponse> {
  const request = new GkdiRpcGetKey();
  const sdData = targetSd.getData();
  request.set('cbTargetSD', sdData.length);
  request.set('pbTargetSD', sdData);
  request.set('pRootKeyID', rootKeyId);
  request.set('L0KeyID', l0);
  request.set('L1KeyID', l1);
  request.set('L2KeyID', l2);
  return (dce as unknown as { request: DceRequestFn }).request<GkdiRpcGetKeyResponse>(
    request,
  );
}

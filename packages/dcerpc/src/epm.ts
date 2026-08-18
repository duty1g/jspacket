import { Buffer } from 'node:buffer';
import { Structure, type FieldDescriptor, structUnpack, structPack } from '@impacket/structure';
import { uuidtupToBin, binToString } from '@impacket/uuid';
import {
  NDR,
  NDRCALL,
  NDRSTRUCT,
  NDRPOINTER,
  NDRUniConformantVaryingArray,
  NDRUniVaryingArray,
  NDRUniConformantArray,
  NULL,
  type NDRField,
} from './ndr';
import { UUID, LPBYTE, PUUID, ULONG, USHORT } from './dtypes';
import { DCERPCException, DCERPC_v5, type IDCERPCTransport } from './rpcrt';
import { DCERPCTransportFactory, TCPTransport } from './transport';

export const MSRPC_UUID_PORTMAP = uuidtupToBin(['E1AF8308-5D1F-11C9-91A4-08002B14A0FA', '3.0'])!;

export class DCERPCSessionError extends DCERPCException {
  static errorMessages: Record<number, string> = {};

  constructor(errorString?: string | null, errorCode?: number | null, packet?: unknown) {
    super(errorString, errorCode, packet);
    if (packet) {
      this.error_code = (packet as { get: (k: string) => unknown }).get('status') as number;
    }
  }
}

export const RPC_C_EP_ALL_ELTS = 0x0;
export const RPC_C_EP_MATCH_BY_IF = 0x1;
export const RPC_C_EP_MATH_BY_OBJ = 0x2;
export const RPC_C_EP_MATH_BY_BOTH = 0x1;
export const RPC_C_VERS_ALL = 0x1;
export const RPC_C_VERS_COMPATIBLE = 0x2;
export const RPC_C_VERS_EXACT = 0x3;
export const RPC_C_VERS_MARJOR_ONLY = 0x4;
export const RPC_C_VERS_UPTO = 0x5;

export const FLOOR_UUID_IDENTIFIER = 0x0d;
export const FLOOR_RPCV5_IDENTIFIER = 0x0b;
export const FLOOR_MSNP_IDENTIFIER = 0x0c;
export const FLOOR_NBNP_IDENTIFIER = 0x0f;
export const FLOOR_MSNB_IDENTIFIER = 0x11;
export const FLOOR_TCPPORT_IDENTIFIER = 0x07;
export const FLOOR_UDPPORT_IDENTIFIER = 0x08;
export const FLOOR_LRPC_IDENTIFIER = 0x10;
export const FLOOR_HTTP_IDENTIFIER = 0x1f;

export class EPMFloor extends Structure {
  static structure: FieldDescriptor[] = [
    ['LHSByteCount', '<H=0'],
    ['_ProtocolData', '_-ProtocolData', 'self["LHSByteCount"]'],
    ['ProtocolData', ':'],
    ['RHSByteCount', '<H=0'],
    ['_RelatedData', '_-RelatedData', 'self["RHSByteCount"]'],
    ['RelatedData', ':'],
  ];
}

export class EPMRPCInterface extends EPMFloor {
  static structure: FieldDescriptor[] = [
    ['LHSByteCount', '<H=19'],
    ['InterfaceIdent', 'B=0x0d'],
    ['InterfaceUUID', '16s=""'],
    ['MajorVersion', '<H=0'],
    ['RHSByteCount', '<H=2'],
    ['MinorVersion', '<H=0'],
  ];
}

export class EPMRPCDataRepresentation extends EPMFloor {
  static structure: FieldDescriptor[] = [
    ['LHSByteCount', '<H=19'],
    ['DrepIdentifier', 'B=0x0d'],
    ['DataRepUuid', '16s=""'],
    ['MajorVersion', '<H=0'],
    ['RHSByteCount', '<H=2'],
    ['MinorVersion', '<H=0'],
  ];
}

export class EPMProtocolIdentifier extends EPMFloor {
  static structure: FieldDescriptor[] = [
    ['LHSByteCount', '<H=1'],
    ['ProtIdentifier', 'B=0'],
    ['RHSByteCount', '<H=2'],
    ['MinorVersion', '<H=0'],
  ];
}

export class EPMPipeName extends EPMFloor {
  static structure: FieldDescriptor[] = [
    ['LHSByteCount', '<H=1'],
    ['PipeIdentifier', 'B=15'],
    ['RHSByteCount', '<H=len(PipeName)'],
    ['PipeName', ':'],
  ];
}

export class EPMHostName extends EPMFloor {
  static structure: FieldDescriptor[] = [
    ['LHSByteCount', '<H=1'],
    ['HostNameIdentifier', 'B=17'],
    ['RHSByteCount', '<H=len(HostName)'],
    ['HostName', ':'],
  ];
}

export class EPMHostAddr extends EPMFloor {
  static structure: FieldDescriptor[] = [
    ['LHSByteCount', '<H=1'],
    ['HostAddressId', 'B=9'],
    ['RHSByteCount', '<H=len(Ip4addr)'],
    ['Ip4addr', '4s=""'],
  ];
}

export class EPMPortAddr extends EPMFloor {
  static structure: FieldDescriptor[] = [
    ['LHSByteCount', '<H=1'],
    ['PortIdentifier', 'B=7'],
    ['RHSByteCount', '<H=2'],
    ['IpPort', '>H=0'],
  ];
}

const EPMFloors = [EPMRPCInterface, EPMRPCDataRepresentation, EPMFloor, EPMFloor, EPMFloor, EPMFloor];

export class EPMTower extends Structure {
  static structure: FieldDescriptor[] = [
    ['NumberOfFloors', '<H'],
    ['Floors', ':'],
  ];

  floors: EPMFloor[] = [];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    if (data) {
      let floorData = this.get('Floors') as Buffer;
      const numFloors = this.get('NumberOfFloors') as number;
      for (let i = 0; i < numFloors && i < EPMFloors.length; i++) {
        const FloorClass = EPMFloors[i]!;
        const floor = new FloorClass(floorData);
        this.floors.push(floor);
        floorData = floorData.subarray(floor.getData().length);
      }
      for (let i = EPMFloors.length; i < numFloors; i++) {
        const floor = new EPMFloor(floorData);
        this.floors.push(floor);
        floorData = floorData.subarray(floor.getData().length);
      }
    }
  }

  getData(): Buffer {
    let floorData = Buffer.alloc(0);
    for (const floor of this.floors) {
      floorData = Buffer.concat([floorData, floor.getData()]);
    }
    this.set('Floors', floorData);
    this.set('NumberOfFloors', this.floors.length);
    return super.getData();
  }
}

export class RPC_IF_ID extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Uuid', UUID],
    ['VersMajor', USHORT],
    ['VersMinor', USHORT],
  ];
}

export class PRPC_IF_ID extends NDRPOINTER {
  static referent: NDRField[] = [['Data', RPC_IF_ID]];
}

export class EptLookupHandleT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['context_handle_attributes', ULONG],
    ['context_handle_uuid', UUID],
  ];

  constructor(data?: Buffer | null, isNDR64 = false) {
    super(data, isNDR64);
    if (data == null) {
      this.set('context_handle_uuid', Buffer.alloc(16, 0));
    }
  }

  isNull(): boolean {
    const uuid = this.fields['context_handle_uuid'] as NDR;
    const uuidData = uuid.fields['Data'] as Buffer;
    return uuidData.equals(Buffer.alloc(16, 0));
  }
}

export class TwrT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['tower_length', ULONG],
    ['tower_octet_string', NDRUniConformantArray],
  ];
}

export class TwrPT extends NDRPOINTER {
  static referent: NDRField[] = [['Data', TwrT]];
}

export class OctetStringT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['count', USHORT],
    ['value', LPBYTE],
  ];
}

export class ProtAndAddrT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['protocol_id', OctetStringT],
    ['address', OctetStringT],
  ];
}

export class ProtocolTowerT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['count', USHORT],
    ['floors', ProtAndAddrT],
  ];
}

export class EptEntryT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['object', UUID],
    ['tower', TwrPT],
    ['annotation', NDRUniVaryingArray],
  ];
}

export class EptEntryTArray extends NDRUniConformantVaryingArray {
  static item = EptEntryT;
}

export class TwrPTArray extends NDRUniConformantVaryingArray {
  static item = TwrPT;
}

export const ErrorStatus = ULONG;

export class EptLookupResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['entry_handle', EptLookupHandleT],
    ['num_ents', ULONG],
    ['entries', EptEntryTArray],
    ['status', ErrorStatus],
  ];
}

export class EptLookup extends NDRCALL {
  static opnum = 2;
  static structure: NDRField[] = [
    ['inquiry_type', ULONG],
    ['object', PUUID],
    ['Ifid', PRPC_IF_ID],
    ['vers_option', ULONG],
    ['entry_handle', EptLookupHandleT],
    ['max_ents', ULONG],
  ];
  static Response = EptLookupResponse;
}

export class EptMapResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['entry_handle', EptLookupHandleT],
    ['num_towers', ULONG],
    ['ITowers', TwrPTArray],
    ['status', ErrorStatus],
  ];
}

export class EptMap extends NDRCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['obj', PUUID],
    ['map_tower', TwrPT],
    ['entry_handle', EptLookupHandleT],
    ['max_towers', ULONG],
  ];
  static Response = EptMapResponse;
}

export interface EpmEntry {
  object: Buffer;
  annotation: string;
  tower: EPMTower;
}

export async function heptLookup(
  destHost: string,
  inquiryType = RPC_C_EP_ALL_ELTS,
  objectUUID: unknown = NULL,
  ifId: Buffer | null = null,
  versOption = RPC_C_VERS_ALL,
  dce?: DCERPC_v5,
): Promise<EpmEntry[]> {
  let disconnect = false;
  if (!dce) {
    const stringBinding = `ncacn_ip_tcp:${destHost}[135]`;
    const rpctransport = DCERPCTransportFactory(stringBinding) as TCPTransport;
    dce = rpctransport.getDceRpc();
    await dce.connect();
    disconnect = true;
  }

  await dce.bind(MSRPC_UUID_PORTMAP);

  const entries: EpmEntry[] = [];
  let entryHandle = new EptLookupHandleT();

  while (true) {
    const request = new EptLookup();
    request.set('inquiry_type', inquiryType);
    request.set('object', objectUUID);
    if (ifId) {
      const ifid = request.fields['Ifid'] as PRPC_IF_ID;
      const uuid = ifid.fields['Data'] as RPC_IF_ID;
      (uuid.fields['Uuid'] as NDR).fields['Data'] = ifId.subarray(0, 16);
      uuid.fields['VersMajor'] = ifId.readUInt16LE(16);
      uuid.fields['VersMinor'] = ifId.readUInt16LE(18);
    } else {
      request.set('Ifid', NULL);
    }
    request.set('vers_option', versOption);
    request.fields['entry_handle'] = entryHandle;
    request.set('max_ents', 500);

    const resp = await (dce as unknown as { request<T>(req: unknown, uuid?: unknown, checkError?: boolean): Promise<T> }).request<EptLookupResponse>(request);

    const numEnts = resp.get('num_ents') as number;
    const respEntries = (resp.fields['entries'] as NDR).fields['Data'] as unknown[];
    for (let i = 0; i < numEnts; i++) {
      const entry = respEntries[i] as EptEntryT;
      const obj = (entry.fields['object'] as NDR).fields['Data'] as Buffer;
      const annotationArr = (entry.fields['annotation'] as NDR).fields['Data'] as unknown[];
      const annotation = Buffer.concat(annotationArr.filter(Buffer.isBuffer) as Buffer[]);
      const towerNdr = (entry.fields['tower'] as TwrPT).fields['Data'] as TwrT;
      const towerOctetNdr = towerNdr.fields['tower_octet_string'] as NDR;
      const towerData = towerOctetNdr.fields['Data'];
      let towerOctets: Buffer;
      if (Buffer.isBuffer(towerData)) {
        towerOctets = towerData;
      } else if (Array.isArray(towerData)) {
        towerOctets = Buffer.from(towerData as number[]);
      } else {
        continue;
      }
      if (towerOctets.length < 2) continue;
      const tower = new EPMTower(towerOctets);
      entries.push({ object: obj, annotation: annotation.toString('utf-8'), tower });
    }

    entryHandle = resp.fields['entry_handle'] as EptLookupHandleT;
    if (entryHandle.isNull()) break;
  }

  if (disconnect) await dce.disconnect();
  return entries;
}

export async function heptMap(
  destHost: string,
  remoteIf: Buffer,
  dataRepresentation: Buffer = uuidtupToBin(['8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'])!,
  protocol = 'ncacn_np',
  dce?: DCERPC_v5,
): Promise<string | null> {
  let disconnect = false;
  if (!dce) {
    const stringBinding = `ncacn_ip_tcp:${destHost}[135]`;
    const rpctransport = DCERPCTransportFactory(stringBinding) as TCPTransport;
    dce = rpctransport.getDceRpc();
    await dce.connect();
    disconnect = true;
  }

  await dce.bind(MSRPC_UUID_PORTMAP);

  const tower = new EPMTower();
  const iface = new EPMRPCInterface();
  iface.set('InterfaceUUID', remoteIf.subarray(0, 16));
  iface.set('MajorVersion', remoteIf.readUInt16LE(16));
  iface.set('MinorVersion', remoteIf.readUInt16LE(18));

  const dataRep = new EPMRPCDataRepresentation();
  dataRep.set('DataRepUuid', dataRepresentation.subarray(0, 16));
  dataRep.set('MajorVersion', dataRepresentation.readUInt16LE(16));
  dataRep.set('MinorVersion', dataRepresentation.readUInt16LE(18));

  const protId = new EPMProtocolIdentifier();
  protId.set('ProtIdentifier', FLOOR_RPCV5_IDENTIFIER);

  let transportData: Buffer;
  if (protocol === 'ncacn_np') {
    const pipeName = new EPMPipeName();
    pipeName.set('PipeName', Buffer.from([0]));
    const hostName = new EPMHostName();
    hostName.set('HostName', Buffer.from(`${destHost}\x00`, 'utf-8'));
    transportData = Buffer.concat([pipeName.getData(), hostName.getData()]);
  } else if (protocol === 'ncacn_ip_tcp') {
    const portAddr = new EPMPortAddr();
    portAddr.set('IpPort', 0);
    const hostAddr = new EPMHostAddr();
    hostAddr.set('Ip4addr', Buffer.from([0, 0, 0, 0]));
    transportData = Buffer.concat([portAddr.getData(), hostAddr.getData()]);
  } else if (protocol === 'ncacn_http') {
    const portAddr = new EPMPortAddr();
    portAddr.set('PortIdentifier', FLOOR_HTTP_IDENTIFIER);
    portAddr.set('IpPort', 0);
    const hostAddr = new EPMHostAddr();
    hostAddr.set('Ip4addr', Buffer.from([0, 0, 0, 0]));
    transportData = Buffer.concat([portAddr.getData(), hostAddr.getData()]);
  } else {
    if (disconnect) await dce.disconnect();
    return null;
  }

  const allFloorData = Buffer.concat([iface.getData(), dataRep.getData(), protId.getData(), transportData]);
  const fullTowerData = Buffer.concat([structPack('<H', 5), allFloorData]);

  const request = new EptMap();
  request.set('max_towers', 4);
  const mapTower = request.fields['map_tower'] as TwrPT;
  const mapTowerData = mapTower.fields['Data'] as TwrT;
  mapTowerData.set('tower_length', fullTowerData.length);
  (mapTowerData.fields['tower_octet_string'] as NDRUniConformantArray).fields['Data'] = Array.from(fullTowerData);

  const objPtr = request.fields['obj'] as NDRPOINTER;
  objPtr.fields['ReferentID'] = 1;
  (request.fields['map_tower'] as NDRPOINTER).fields['ReferentID'] = 2;

  const resp = await (dce as unknown as { request<T>(req: unknown, uuid?: unknown, checkError?: boolean): Promise<T> }).request<EptMapResponse>(request);

  const iTowers = (resp.fields['ITowers'] as NDR).fields['Data'] as unknown[];
  const firstTower = iTowers[0] as TwrPT;
  const firstTowerData = (firstTower.fields['Data'] as TwrT).fields['tower_octet_string'] as NDR;
  const towerOctetArr = firstTowerData.fields['Data'] as unknown[];
  const towerOctets = Buffer.concat(
    towerOctetArr.map((v) =>
      Buffer.isBuffer(v) ? v : Buffer.from([v as number]),
    ),
  );
  const respTower = new EPMTower(towerOctets);

  let result: string | null = null;
  if (protocol === 'ncacn_np') {
    const pipeName = new EPMPipeName(respTower.floors[3]!.getData());
    const pipeNameData = pipeName.get('PipeName') as Buffer;
    result = `ncacn_np:${destHost}[${pipeNameData.toString('utf-8').slice(0, -1)}]`;
  } else if (protocol === 'ncacn_ip_tcp') {
    const portAddr = new EPMPortAddr(respTower.floors[3]!.getData());
    result = `ncacn_ip_tcp:${destHost}[${portAddr.get('IpPort')}]`;
  } else if (protocol === 'ncacn_http') {
    const portAddr = new EPMPortAddr(respTower.floors[3]!.getData());
    result = `ncacn_http:${destHost}[${portAddr.get('IpPort')}]`;
  }

  if (disconnect) await dce.disconnect();
  return result;
}

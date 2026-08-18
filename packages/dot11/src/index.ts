import { Buffer } from 'node:buffer';
import { ProtocolPacket } from '@impacket/impact';

// ---- CRC32 ----

const CRC32_TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  CRC32_TABLE[n] = c;
}

function crc32(data: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc = CRC32_TABLE[(crc ^ data[i]!) & 0xff]! ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// CRC32 with LE→BE byte swap, matching Python's crc32 + struct.pack('<L') + struct.unpack('!L')
function crc32Swap(data: Buffer): number {
  const le = crc32(data);
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(le);
  return buf.readUInt32BE(0);
}

// ---- struct helpers for RadioTap ----

function structCalcSize(format: string): number {
  let size = 0;
  for (const c of format) {
    switch (c) {
      case 'B': case 'b': size += 1; break;
      case 'H': case 'h': size += 2; break;
      case 'L': case 'l': case 'I': case 'i': size += 4; break;
      case 'Q': case 'q': size += 8; break;
    }
  }
  return size;
}

function structCountFields(format: string): number {
  let count = 0;
  for (const c of format) {
    if ('BbHhLlIiQq'.includes(c)) count++;
  }
  return count;
}

function structUnpack(format: string, buf: Buffer): (number | bigint)[] {
  const results: (number | bigint)[] = [];
  let le = true;
  let off = 0;
  for (const c of format) {
    switch (c) {
      case '<': le = true; break;
      case '>': case '!': le = false; break;
      case 'B': results.push(buf.readUInt8(off)); off += 1; break;
      case 'b': results.push(buf.readInt8(off)); off += 1; break;
      case 'H': results.push(le ? buf.readUInt16LE(off) : buf.readUInt16BE(off)); off += 2; break;
      case 'L': case 'I': results.push(le ? buf.readUInt32LE(off) : buf.readUInt32BE(off)); off += 4; break;
      case 'Q': results.push(le ? buf.readBigUInt64LE(off) : buf.readBigUInt64BE(off)); off += 8; break;
      case 'q': results.push(le ? buf.readBigInt64LE(off) : buf.readBigInt64BE(off)); off += 8; break;
    }
  }
  return results;
}

function structPack(format: string, values: (number | bigint)[]): Buffer {
  const size = structCalcSize(format);
  const buf = Buffer.alloc(size);
  let le = true;
  let off = 0;
  let vi = 0;
  for (const c of format) {
    switch (c) {
      case '<': le = true; break;
      case '>': case '!': le = false; break;
      case 'B': buf.writeUInt8(Number(values[vi]!) & 0xff, off); vi++; off += 1; break;
      case 'b': buf.writeInt8(Number(values[vi]!), off); vi++; off += 1; break;
      case 'H':
        if (le) buf.writeUInt16LE(Number(values[vi]!) & 0xffff, off);
        else buf.writeUInt16BE(Number(values[vi]!) & 0xffff, off);
        vi++; off += 2; break;
      case 'L': case 'I':
        if (le) buf.writeUInt32LE(Number(values[vi]!) >>> 0, off);
        else buf.writeUInt32BE(Number(values[vi]!) >>> 0, off);
        vi++; off += 4; break;
      case 'Q': {
        const v = typeof values[vi]! === 'bigint' ? values[vi]! as bigint : BigInt(values[vi]!);
        if (le) buf.writeBigUInt64LE(v, off);
        else buf.writeBigUInt64BE(v, off);
        vi++; off += 8; break;
      }
    }
  }
  return buf;
}

// ---- RC4 (from Dot11Crypto.py) ----

export class RC4 {
  private state: Uint8Array;

  constructor(key: Buffer) {
    this.state = new Uint8Array(256);
    for (let i = 0; i < 256; i++) this.state[i] = i;
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + this.state[i]! + key[i % key.length]!) & 0xff;
      const tmp = this.state[i]!;
      this.state[i] = this.state[j]!;
      this.state[j] = tmp;
    }
  }

  encrypt(data: Buffer): Buffer {
    let i = 0;
    let j = 0;
    const out = Buffer.alloc(data.length);
    for (let k = 0; k < data.length; k++) {
      i = (i + 1) & 0xff;
      j = (j + this.state[i]!) & 0xff;
      const tmp = this.state[i]!;
      this.state[i] = this.state[j]!;
      this.state[j] = tmp;
      out[k] = data[k]! ^ this.state[(this.state[i]! + this.state[j]!) & 0xff]!;
    }
    return out;
  }

  decrypt(data: Buffer): Buffer {
    return this.encrypt(data);
  }
}

// ---- KeyManager (from Dot11KeyManager.py) ----

export class KeyManager {
  private keys = new Map<string, Buffer>();

  private getBssidKey(bssid: Buffer | number[]): string {
    const arr = Buffer.isBuffer(bssid) ? bssid : Buffer.from(bssid);
    return arr.toString('hex');
  }

  addKey(bssid: Buffer | number[], key: Buffer): boolean {
    const k = this.getBssidKey(bssid);
    if (this.keys.has(k)) return false;
    this.keys.set(k, key);
    return true;
  }

  replaceKey(bssid: Buffer | number[], key: Buffer): boolean {
    this.keys.set(this.getBssidKey(bssid), key);
    return true;
  }

  getKey(bssid: Buffer | number[]): Buffer | false {
    return this.keys.get(this.getBssidKey(bssid)) ?? false;
  }

  deleteKey(bssid: Buffer | number[]): boolean {
    return this.keys.delete(this.getBssidKey(bssid));
  }
}

// ---- Frequency → Channel map ----

export const frequency: Record<number, number> = {
  2412: 1, 2417: 2, 2422: 3, 2427: 4, 2432: 5, 2437: 6, 2442: 7, 2447: 8, 2452: 9,
  2457: 10, 2462: 11, 2467: 12, 2472: 13, 2484: 14, 5170: 34, 5180: 36, 5190: 38,
  5200: 40, 5210: 42, 5220: 44, 5230: 46, 5240: 48, 5260: 52, 5280: 56, 5300: 60,
  5320: 64, 5500: 100, 5510: 102, 5520: 104, 5530: 106, 5540: 108, 5550: 110,
  5560: 112, 5570: 114, 5580: 116, 5590: 118, 5600: 120, 5610: 122, 5620: 124,
  5630: 126, 5640: 128, 5650: 130, 5660: 132, 5670: 134, 5680: 136, 5690: 138,
  5700: 140, 5745: 149, 5765: 153, 5785: 157, 5805: 161, 5825: 165, 5855: 170,
  5860: 172, 5865: 173, 5870: 174, 5875: 175, 5880: 176, 5885: 177, 5890: 178,
  5895: 179, 5900: 180, 5905: 181, 5910: 182, 5915: 183, 5920: 184,
};

// ---- Dot11ManagementCapabilities ----

export const Dot11ManagementCapabilities = {
  CAPABILITY_RESERVED_1:      0b1000000000000000,
  CAPABILITY_RESERVED_2:      0b0100000000000000,
  CAPABILITY_DSSS_OFDM:       0b0010000000000000,
  CAPABILITY_RESERVED_3:      0b0001000000000000,
  CAPABILITY_RESERVED_4:      0b0000100000000000,
  CAPABILITY_SHORT_SLOT_TIME: 0b0000010000000000,
  CAPABILITY_RESERVED_5:      0b0000001000000000,
  CAPABILITY_RESERVED_6:      0b0000000100000000,
  CAPABILITY_CH_AGILITY:      0b0000000010000000,
  CAPABILITY_PBCC:            0b0000000001000000,
  CAPABILITY_SHORT_PREAMBLE:  0b0000000000100000,
  CAPABILITY_PRIVACY:         0b0000000000010000,
  CAPABILITY_CF_POLL_REQ:     0b0000000000001000,
  CAPABILITY_CF_POLLABLE:     0b0000000000000100,
  CAPABILITY_IBSS:            0b0000000000000010,
  CAPABILITY_ESS:             0b0000000000000001,
} as const;

// ---- Dot11Types ----

export const Dot11Types = {
  DOT11_TYPE_MANAGEMENT: 0b00,
  DOT11_SUBTYPE_MANAGEMENT_ASSOCIATION_REQUEST:    0b0000,
  DOT11_SUBTYPE_MANAGEMENT_ASSOCIATION_RESPONSE:   0b0001,
  DOT11_SUBTYPE_MANAGEMENT_REASSOCIATION_REQUEST:  0b0010,
  DOT11_SUBTYPE_MANAGEMENT_REASSOCIATION_RESPONSE: 0b0011,
  DOT11_SUBTYPE_MANAGEMENT_PROBE_REQUEST:          0b0100,
  DOT11_SUBTYPE_MANAGEMENT_PROBE_RESPONSE:         0b0101,
  DOT11_SUBTYPE_MANAGEMENT_RESERVED1:              0b0110,
  DOT11_SUBTYPE_MANAGEMENT_RESERVED2:              0b0111,
  DOT11_SUBTYPE_MANAGEMENT_BEACON:                 0b1000,
  DOT11_SUBTYPE_MANAGEMENT_ATIM:                   0b1001,
  DOT11_SUBTYPE_MANAGEMENT_DISASSOCIATION:         0b1010,
  DOT11_SUBTYPE_MANAGEMENT_AUTHENTICATION:         0b1011,
  DOT11_SUBTYPE_MANAGEMENT_DEAUTHENTICATION:       0b1100,
  DOT11_SUBTYPE_MANAGEMENT_ACTION:                 0b1101,
  DOT11_SUBTYPE_MANAGEMENT_RESERVED3:              0b1110,
  DOT11_SUBTYPE_MANAGEMENT_RESERVED4:              0b1111,
  DOT11_TYPE_MANAGEMENT_SUBTYPE_ASSOCIATION_REQUEST:    0b00 | (0b0000 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_ASSOCIATION_RESPONSE:   0b00 | (0b0001 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_REASSOCIATION_REQUEST:  0b00 | (0b0010 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_REASSOCIATION_RESPONSE: 0b00 | (0b0011 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_PROBE_REQUEST:          0b00 | (0b0100 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_PROBE_RESPONSE:         0b00 | (0b0101 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_RESERVED1:              0b00 | (0b0110 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_RESERVED2:              0b00 | (0b0111 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_BEACON:                 0b00 | (0b1000 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_ATIM:                   0b00 | (0b1001 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_DISASSOCIATION:         0b00 | (0b1010 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_AUTHENTICATION:         0b00 | (0b1011 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_DEAUTHENTICATION:       0b00 | (0b1100 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_ACTION:                 0b00 | (0b1101 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_RESERVED3:              0b00 | (0b1110 << 2),
  DOT11_TYPE_MANAGEMENT_SUBTYPE_RESERVED4:              0b00 | (0b1111 << 2),
  DOT11_TYPE_CONTROL: 0b01,
  DOT11_SUBTYPE_CONTROL_RESERVED1:         0b0000,
  DOT11_SUBTYPE_CONTROL_RESERVED2:         0b0001,
  DOT11_SUBTYPE_CONTROL_RESERVED3:         0b0010,
  DOT11_SUBTYPE_CONTROL_RESERVED4:         0b0011,
  DOT11_SUBTYPE_CONTROL_RESERVED5:         0b0100,
  DOT11_SUBTYPE_CONTROL_RESERVED6:         0b0101,
  DOT11_SUBTYPE_CONTROL_RESERVED7:         0b0110,
  DOT11_SUBTYPE_CONTROL_RESERVED8:         0b0111,
  DOT11_SUBTYPE_CONTROL_BLOCK_ACK_REQUEST: 0b1000,
  DOT11_SUBTYPE_CONTROL_BLOCK_ACK:         0b1001,
  DOT11_SUBTYPE_CONTROL_POWERSAVE_POLL:    0b1010,
  DOT11_SUBTYPE_CONTROL_REQUEST_TO_SEND:   0b1011,
  DOT11_SUBTYPE_CONTROL_CLEAR_TO_SEND:     0b1100,
  DOT11_SUBTYPE_CONTROL_ACKNOWLEDGMENT:    0b1101,
  DOT11_SUBTYPE_CONTROL_CF_END:            0b1110,
  DOT11_SUBTYPE_CONTROL_CF_END_CF_ACK:     0b1111,
  DOT11_TYPE_CONTROL_SUBTYPE_RESERVED1:         0b01 | (0b0000 << 2),
  DOT11_TYPE_CONTROL_SUBTYPE_RESERVED2:         0b01 | (0b0001 << 2),
  DOT11_TYPE_CONTROL_SUBTYPE_RESERVED3:         0b01 | (0b0010 << 2),
  DOT11_TYPE_CONTROL_SUBTYPE_RESERVED4:         0b01 | (0b0011 << 2),
  DOT11_TYPE_CONTROL_SUBTYPE_RESERVED5:         0b01 | (0b0100 << 2),
  DOT11_TYPE_CONTROL_SUBTYPE_RESERVED6:         0b01 | (0b0101 << 2),
  DOT11_TYPE_CONTROL_SUBTYPE_RESERVED7:         0b01 | (0b0110 << 2),
  DOT11_TYPE_CONTROL_SUBTYPE_BLOCK_ACK_REQUEST: 0b01 | (0b1000 << 2),
  DOT11_TYPE_CONTROL_SUBTYPE_BLOCK_ACK:         0b01 | (0b1001 << 2),
  DOT11_TYPE_CONTROL_SUBTYPE_POWERSAVE_POLL:    0b01 | (0b1010 << 2),
  DOT11_TYPE_CONTROL_SUBTYPE_REQUEST_TO_SEND:   0b01 | (0b1011 << 2),
  DOT11_TYPE_CONTROL_SUBTYPE_CLEAR_TO_SEND:     0b01 | (0b1100 << 2),
  DOT11_TYPE_CONTROL_SUBTYPE_ACKNOWLEDGMENT:    0b01 | (0b1101 << 2),
  DOT11_TYPE_CONTROL_SUBTYPE_CF_END:            0b01 | (0b1110 << 2),
  DOT11_TYPE_CONTROL_SUBTYPE_CF_END_CF_ACK:     0b01 | (0b1111 << 2),
  DOT11_TYPE_DATA: 0b10,
  DOT11_SUBTYPE_DATA:                            0b0000,
  DOT11_SUBTYPE_DATA_CF_ACK:                     0b0001,
  DOT11_SUBTYPE_DATA_CF_POLL:                    0b0010,
  DOT11_SUBTYPE_DATA_CF_ACK_CF_POLL:             0b0011,
  DOT11_SUBTYPE_DATA_NULL_NO_DATA:               0b0100,
  DOT11_SUBTYPE_DATA_CF_ACK_NO_DATA:             0b0101,
  DOT11_SUBTYPE_DATA_CF_POLL_NO_DATA:            0b0110,
  DOT11_SUBTYPE_DATA_CF_ACK_CF_POLL_NO_DATA:     0b0111,
  DOT11_SUBTYPE_DATA_QOS_DATA:                   0b1000,
  DOT11_SUBTYPE_DATA_QOS_DATA_CF_ACK:            0b1001,
  DOT11_SUBTYPE_DATA_QOS_DATA_CF_POLL:           0b1010,
  DOT11_SUBTYPE_DATA_QOS_DATA_CF_ACK_CF_POLL:    0b1011,
  DOT11_SUBTYPE_DATA_QOS_NULL_NO_DATA:           0b1100,
  DOT11_SUBTYPE_DATA_RESERVED1:                  0b1101,
  DOT11_SUBTYPE_DATA_QOS_CF_POLL_NO_DATA:        0b1110,
  DOT11_SUBTYPE_DATA_QOS_CF_ACK_CF_POLL_NO_DATA: 0b1111,
  DOT11_TYPE_DATA_SUBTYPE_DATA:                            0b10 | (0b0000 << 2),
  DOT11_TYPE_DATA_SUBTYPE_CF_ACK:                          0b10 | (0b0001 << 2),
  DOT11_TYPE_DATA_SUBTYPE_CF_POLL:                         0b10 | (0b0010 << 2),
  DOT11_TYPE_DATA_SUBTYPE_CF_ACK_CF_POLL:                  0b10 | (0b0011 << 2),
  DOT11_TYPE_DATA_SUBTYPE_NULL_NO_DATA:                    0b10 | (0b0100 << 2),
  // Python has a bug: CF_ACK_NO_DATA uses CF_POLL_NO_DATA subtype
  DOT11_TYPE_DATA_SUBTYPE_CF_ACK_NO_DATA:                  0b10 | (0b0110 << 2),
  DOT11_TYPE_DATA_SUBTYPE_CF_ACK_CF_POLL_NO_DATA:          0b10 | (0b0111 << 2),
  DOT11_TYPE_DATA_SUBTYPE_QOS_DATA:                        0b10 | (0b1000 << 2),
  DOT11_TYPE_DATA_SUBTYPE_QOS_DATA_CF_ACK:                 0b10 | (0b1001 << 2),
  DOT11_TYPE_DATA_SUBTYPE_QOS_DATA_CF_POLL:                0b10 | (0b1010 << 2),
  DOT11_TYPE_DATA_SUBTYPE_QOS_DATA_CF_ACK_CF_POLL:         0b10 | (0b1011 << 2),
  DOT11_TYPE_DATA_SUBTYPE_QOS_NULL_NO_DATA:                0b10 | (0b1100 << 2),
  DOT11_TYPE_DATA_SUBTYPE_RESERVED1:                       0b10 | (0b1101 << 2),
  DOT11_TYPE_DATA_SUBTYPE_QOS_CF_POLL_NO_DATA:             0b10 | (0b1110 << 2),
  DOT11_TYPE_DATA_SUBTYPE_QOS_CF_ACK_CF_POLL_NO_DATA:      0b10 | (0b1111 << 2),
  DOT11_TYPE_RESERVED: 0b11,
  DOT11_SUBTYPE_RESERVED_RESERVED1:  0b0000,
  DOT11_SUBTYPE_RESERVED_RESERVED2:  0b0001,
  DOT11_SUBTYPE_RESERVED_RESERVED3:  0b0010,
  DOT11_SUBTYPE_RESERVED_RESERVED4:  0b0011,
  DOT11_SUBTYPE_RESERVED_RESERVED5:  0b0100,
  DOT11_SUBTYPE_RESERVED_RESERVED6:  0b0101,
  DOT11_SUBTYPE_RESERVED_RESERVED7:  0b0110,
  DOT11_SUBTYPE_RESERVED_RESERVED8:  0b0111,
  DOT11_SUBTYPE_RESERVED_RESERVED9:  0b1000,
  DOT11_SUBTYPE_RESERVED_RESERVED10: 0b1001,
  DOT11_SUBTYPE_RESERVED_RESERVED11: 0b1010,
  DOT11_SUBTYPE_RESERVED_RESERVED12: 0b1011,
  DOT11_SUBTYPE_RESERVED_RESERVED13: 0b1100,
  DOT11_SUBTYPE_RESERVED_RESERVED14: 0b1101,
  DOT11_SUBTYPE_RESERVED_RESERVED15: 0b1110,
  DOT11_SUBTYPE_RESERVED_RESERVED16: 0b1111,
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED1:  0b11 | (0b0000 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED2:  0b11 | (0b0001 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED3:  0b11 | (0b0010 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED4:  0b11 | (0b0011 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED5:  0b11 | (0b0100 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED6:  0b11 | (0b0101 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED7:  0b11 | (0b0110 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED8:  0b11 | (0b0111 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED9:  0b11 | (0b1000 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED10: 0b11 | (0b1001 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED11: 0b11 | (0b1010 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED12: 0b11 | (0b1011 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED13: 0b11 | (0b1100 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED14: 0b11 | (0b1101 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED15: 0b11 | (0b1110 << 2),
  DOT11_TYPE_RESERVED_SUBTYPE_RESERVED16: 0b11 | (0b1111 << 2),
} as const;

// ---- Dot11 ----

export class Dot11 extends ProtocolPacket {
  private _fcsAtEnd: boolean;

  constructor(aBuffer?: Buffer, fcsAtEnd = true) {
    const tailSize = fcsAtEnd ? 4 : 0;
    super(2, tailSize);
    this._fcsAtEnd = !!fcsAtEnd;
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getOrder(): number {
    return (this.header.getByte(1) >> 7) & 0x01;
  }

  setOrder(value: number): void {
    const masked = this.header.getByte(1) & (~0x80 & 0xff);
    this.header.setByte(1, masked | ((value & 0x01) << 7));
  }

  getProtectedFrame(): number {
    return (this.header.getByte(1) >> 6) & 0x01;
  }

  setProtectedFrame(value: number): void {
    const masked = this.header.getByte(1) & (~0x40 & 0xff);
    this.header.setByte(1, masked | ((value & 0x01) << 6));
  }

  getMoreData(): number {
    return (this.header.getByte(1) >> 5) & 0x01;
  }

  setMoreData(value: number): void {
    const masked = this.header.getByte(1) & (~0x20 & 0xff);
    this.header.setByte(1, masked | ((value & 0x01) << 5));
  }

  getPowerManagement(): number {
    return (this.header.getByte(1) >> 4) & 0x01;
  }

  setPowerManagement(value: number): void {
    const masked = this.header.getByte(1) & (~0x10 & 0xff);
    this.header.setByte(1, masked | ((value & 0x01) << 4));
  }

  getRetry(): number {
    return (this.header.getByte(1) >> 3) & 0x01;
  }

  setRetry(value: number): void {
    const masked = this.header.getByte(1) & (~0x08 & 0xff);
    this.header.setByte(1, masked | ((value & 0x01) << 3));
  }

  getMoreFrag(): number {
    return (this.header.getByte(1) >> 2) & 0x01;
  }

  setMoreFrag(value: number): void {
    const masked = this.header.getByte(1) & (~0x04 & 0xff);
    this.header.setByte(1, masked | ((value & 0x01) << 2));
  }

  getFromDS(): number {
    return (this.header.getByte(1) >> 1) & 0x01;
  }

  setFromDS(value: number): void {
    const masked = this.header.getByte(1) & (~0x02 & 0xff);
    this.header.setByte(1, masked | ((value & 0x01) << 1));
  }

  getToDS(): number {
    return this.header.getByte(1) & 0x01;
  }

  setToDS(value: number): void {
    const masked = this.header.getByte(1) & (~0x01 & 0xff);
    this.header.setByte(1, masked | (value & 0x01));
  }

  getSubtype(): number {
    return (this.header.getByte(0) >> 4) & 0x0f;
  }

  setSubtype(value: number): void {
    const masked = this.header.getByte(0) & (~0xf0 & 0xff);
    this.header.setByte(0, masked | ((value << 4) & 0xf0));
  }

  getType(): number {
    return (this.header.getByte(0) >> 2) & 0x03;
  }

  setType(value: number): void {
    const masked = this.header.getByte(0) & (~0x0c & 0xff);
    this.header.setByte(0, masked | ((value << 2) & 0x0c));
  }

  getTypeNSubtype(): number {
    return (this.header.getByte(0) >> 2) & 0x3f;
  }

  setTypeNSubtype(value: number): void {
    const masked = this.header.getByte(0) & (~0xfc & 0xff);
    this.header.setByte(0, masked | ((value << 2) & 0xfc));
  }

  getVersion(): number {
    return this.header.getByte(0) & 0x03;
  }

  setVersion(value: number): void {
    const masked = this.header.getByte(0) & (~0x03 & 0xff);
    this.header.setByte(0, masked | (value & 0x03));
  }

  computeChecksum(data: Buffer): number {
    return crc32Swap(data);
  }

  isQoSFrame(): boolean {
    return !!(this.header.getByte(0) & 0x80);
  }

  isNoFramebodyFrame(): boolean {
    return !!(this.header.getByte(0) & 0x40);
  }

  isCfPollFrame(): boolean {
    return !!(this.header.getByte(0) & 0x20);
  }

  isCfAckFrame(): boolean {
    return !!(this.header.getByte(0) & 0x10);
  }

  getFcs(): number | null {
    if (!this._fcsAtEnd) return null;
    return this.tail.getLong(-4, '>');
  }

  setFcs(value?: number | null): void {
    if (!this._fcsAtEnd) return;
    let v = value;
    if (v === undefined || v === null) {
      const payload = this.getBodyAsString();
      v = this.computeChecksum(payload);
    }
    this.tail.setLong(-4, v & 0xffffffff);
  }
}

// ---- Control Frames ----

export class Dot11ControlFrameCTS extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(8, 0);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getDuration(): number { return this.header.getWord(0, '<'); }
  setDuration(value: number): void { this.header.setWord(0, value & 0xffff, '<'); }

  getRa(): Buffer { return this.header.getBytes().subarray(2, 8); }
  setRa(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(2 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }
}

export class Dot11ControlFrameACK extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(8, 0);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getDuration(): number { return this.header.getWord(0, '<'); }
  setDuration(value: number): void { this.header.setWord(0, value & 0xffff, '<'); }

  getRa(): Buffer { return this.header.getBytes().subarray(2, 8); }
  setRa(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(2 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }
}

export class Dot11ControlFrameRTS extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(14, 0);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getDuration(): number { return this.header.getWord(0, '<'); }
  setDuration(value: number): void { this.header.setWord(0, value & 0xffff, '<'); }

  getRa(): Buffer { return this.header.getBytes().subarray(2, 8); }
  setRa(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(2 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }

  getTa(): Buffer { return this.header.getBytes().subarray(8, 14); }
  setTa(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(8 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }
}

export class Dot11ControlFramePSPoll extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(14, 0);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getAid(): number { return this.header.getWord(0, '<'); }
  setAid(value: number): void { this.header.setWord(0, value & 0xffff, '<'); }

  getBssid(): Buffer { return this.header.getBytes().subarray(2, 8); }
  setBssid(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(2 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }

  getTa(): Buffer { return this.header.getBytes().subarray(8, 14); }
  setTa(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(8 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }
}

export class Dot11ControlFrameCFEnd extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(14, 0);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getDuration(): number { return this.header.getWord(0, '<'); }
  setDuration(value: number): void { this.header.setWord(0, value & 0xffff, '<'); }

  getRa(): Buffer { return this.header.getBytes().subarray(2, 8); }
  setRa(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(2 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }

  getBssid(): Buffer { return this.header.getBytes().subarray(8, 14); }
  setBssid(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(8 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }
}

export class Dot11ControlFrameCFEndCFACK extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(14, 0);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getDuration(): number { return this.header.getWord(0, '<'); }
  setDuration(value: number): void { this.header.setWord(0, value & 0xffff, '<'); }

  getRa(): Buffer { return this.header.getBytes().subarray(2, 8); }
  setRa(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(2 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }

  getBssid(): Buffer { return this.header.getBytes().subarray(8, 16); }
  setBssid(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(8 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }
}

// ---- Data Frames ----

export class Dot11DataFrame extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(22, 0);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getDuration(): number { return this.header.getWord(0, '<'); }
  setDuration(value: number): void { this.header.setWord(0, value & 0xffff, '<'); }

  getAddress1(): Buffer { return this.header.getBytes().subarray(2, 8); }
  setAddress1(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(2 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }

  getAddress2(): Buffer { return this.header.getBytes().subarray(8, 14); }
  setAddress2(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(8 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }

  getAddress3(): Buffer { return this.header.getBytes().subarray(14, 20); }
  setAddress3(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(14 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }

  getSequenceControl(): number { return this.header.getWord(20, '<'); }
  setSequenceControl(value: number): void { this.header.setWord(20, value & 0xffff, '<'); }

  getFragmentNumber(): number { return this.header.getWord(20, '<') & 0x000f; }
  setFragmentNumber(value: number): void {
    const masked = this.header.getWord(20, '<') & (~0x000f & 0xffff);
    this.header.setWord(20, masked | (value & 0x000f), '<');
  }

  getSequenceNumber(): number { return (this.header.getWord(20, '<') >> 4) & 0xfff; }
  setSequenceNumber(value: number): void {
    const masked = this.header.getWord(20, '<') & (~0xfff0 & 0xffff);
    this.header.setWord(20, masked | ((value & 0x0fff) << 4), '<');
  }

  getFrameBody(): Buffer { return this.getBodyAsString(); }
  setFrameBody(data: Buffer): void { this.loadBody(data); }
}

export class Dot11DataQoSFrame extends Dot11DataFrame {
  constructor(aBuffer?: Buffer) {
    super();
    // Re-init with proper header size
    (this as unknown as { loadHeader(b: Buffer): void }).loadHeader(Buffer.alloc(24));
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getQoS(): number { return this.header.getWord(22, '<'); }
  setQoS(value: number): void { this.header.setWord(22, value & 0xffff, '<'); }
}

export class Dot11DataAddr4Frame extends Dot11DataFrame {
  constructor(aBuffer?: Buffer) {
    super();
    (this as unknown as { loadHeader(b: Buffer): void }).loadHeader(Buffer.alloc(28));
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getAddress4(): Buffer { return this.header.getBytes().subarray(22, 28); }
  setAddress4(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(22 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }
}

export class Dot11DataAddr4QoSFrame extends Dot11DataAddr4Frame {
  constructor(aBuffer?: Buffer) {
    super();
    (this as unknown as { loadHeader(b: Buffer): void }).loadHeader(Buffer.alloc(30));
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getQoS(): number { return this.header.getWord(28, '<'); }
  setQoS(value: number): void { this.header.setWord(28, value & 0xffff, '<'); }
}

// ---- SAPTypes ----

export const SAPTypes = {
  NULL: 0x00,
  LLC_SLMGMT: 0x02,
  SNA_PATHCTRL: 0x04,
  IP: 0x06,
  SNA1: 0x08,
  SNA2: 0x0c,
  PROWAY_NM_INIT: 0x0e,
  NETWARE1: 0x10,
  OSINL1: 0x14,
  TI: 0x18,
  OSINL2: 0x20,
  OSINL3: 0x34,
  SNA3: 0x40,
  BPDU: 0x42,
  RS511: 0x4e,
  OSINL4: 0x54,
  X25: 0x7e,
  XNS: 0x80,
  BACNET: 0x82,
  NESTAR: 0x86,
  PROWAY_ASLM: 0x8e,
  ARP: 0x98,
  SNAP: 0xaa,
  HPJD: 0xb4,
  VINES1: 0xba,
  VINES2: 0xbc,
  NETWARE2: 0xe0,
  NETBIOS: 0xf0,
  IBMNM: 0xf4,
  HPEXT: 0xf8,
  UB: 0xfa,
  RPL: 0xfc,
  OSINL5: 0xfe,
  GLOBAL: 0xff,
} as const;

// ---- LLC ----

export class LLC extends ProtocolPacket {
  static readonly DLC_UNNUMBERED_FRAMES = 0x03;

  constructor(aBuffer?: Buffer) {
    super(3, 0);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getDSAP(): number { return this.header.getByte(0); }
  setDSAP(value: number): void { this.header.setByte(0, value); }

  getSSAP(): number { return this.header.getByte(1); }
  setSSAP(value: number): void { this.header.setByte(1, value); }

  getControl(): number { return this.header.getByte(2); }
  setControl(value: number): void { this.header.setByte(2, value); }
}

// ---- SNAP ----

export class SNAP extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(5, 0);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getOUI(): number {
    const b = this.header.getBytes().subarray(0, 3);
    const padded = Buffer.concat([Buffer.from([0x00]), b]);
    return padded.readUInt32BE(0);
  }

  setOUI(value: number): void {
    const mask = (~0xffffff00 & 0xff) >>> 0;
    const masked = this.header.getLong(0, '>') & mask;
    const nb = masked | ((value & 0x00ffffff) << 8);
    this.header.setLong(0, nb);
  }

  getProtoID(): number { return this.header.getWord(3, '>'); }
  setProtoID(value: number): void { this.header.setWord(3, value, '>'); }
}

// ---- WEP ----

export class Dot11WEP extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(4, 0);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  isWEP(): boolean {
    return !(this.header.getByte(3) & 0x20);
  }

  getIV(): number {
    const b = this.header.getBytes().subarray(0, 3);
    const padded = Buffer.concat([Buffer.from([0x00]), b]);
    return padded.readUInt32BE(0);
  }

  setIV(value: number): void {
    const mask = (~0xffffff00 & 0xff) >>> 0;
    const masked = this.header.getLong(0, '>') & mask;
    const nb = masked | ((value & 0x00ffffff) << 8);
    this.header.setLong(0, nb);
  }

  getKeyID(): number {
    return (this.header.getByte(3) >> 6) & 0x03;
  }

  setKeyID(value: number): void {
    const masked = this.header.getByte(3) & (~0xc0 & 0xff);
    this.header.setByte(3, masked | ((value & 0x03) << 6));
  }

  getDecryptedData(keyString: Buffer): Buffer {
    if (this.bodyString.length < 8) return this.bodyString;
    const ivBuf = Buffer.alloc(4);
    ivBuf.writeUInt32BE(this.getIV());
    const iv = ivBuf.subarray(1);
    const key = Buffer.concat([iv, keyString]);
    const rc4 = new RC4(key);
    return rc4.decrypt(this.bodyString);
  }

  getEncryptedData(keyString: Buffer): Buffer {
    return this.getDecryptedData(keyString);
  }

  encryptFrame(keyString: Buffer): void {
    const enc = this.getEncryptedData(keyString);
    this.loadBody(enc);
  }
}

export class Dot11WEPData extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(0, 4);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getICV(): number {
    return this.tail.getLong(-4, '>');
  }

  setICV(value?: number | null): void {
    let v = value;
    if (v === undefined || v === null) {
      v = this.getComputedICV();
    }
    this.tail.setLong(-4, v & 0xffffffff);
  }

  getComputedICV(): number {
    return crc32Swap(this.bodyString);
  }

  checkICV(): boolean {
    return this.getComputedICV() === this.getICV();
  }
}

// ---- WPA ----

export class Dot11WPA extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(8, 0);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  isWPA(): boolean {
    const b = this.getWEPSeed() === ((this.getTSC1() | 0x20) & 0x7f);
    return b && !!this.getExtIV();
  }

  getKeyID(): number {
    return (this.header.getByte(3) >> 6) & 0x03;
  }

  setKeyID(value: number): void {
    const masked = this.header.getByte(3) & (~0xc0 & 0xff);
    this.header.setByte(3, masked | ((value & 0x03) << 6));
  }

  getDecryptedData(): Buffer { return this.bodyString; }

  getTSC1(): number { return this.header.getByte(0) & 0xff; }
  setTSC1(value: number): void { this.header.setByte(0, value & 0xff); }

  getWEPSeed(): number { return this.header.getByte(1) & 0xff; }
  setWEPSeed(value: number): void { this.header.setByte(1, value & 0xff); }

  getTSC0(): number { return this.header.getByte(2) & 0xff; }
  setTSC0(value: number): void { this.header.setByte(2, value & 0xff); }

  getExtIV(): number { return (this.header.getByte(3) >> 5) & 0x1; }
  setExtIV(value: number): void {
    const masked = this.header.getByte(3) & (~0x20 & 0xff);
    this.header.setByte(3, masked | ((value & 0x01) << 5));
  }

  getTSC2(): number { return this.header.getByte(4) & 0xff; }
  setTSC2(value: number): void { this.header.setByte(4, value & 0xff); }

  getTSC3(): number { return this.header.getByte(5) & 0xff; }
  setTSC3(value: number): void { this.header.setByte(5, value & 0xff); }

  getTSC4(): number { return this.header.getByte(6) & 0xff; }
  setTSC4(value: number): void { this.header.setByte(6, value & 0xff); }

  getTSC5(): number { return this.header.getByte(7) & 0xff; }
  setTSC5(value: number): void { this.header.setByte(7, value & 0xff); }
}

export class Dot11WPAData extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(0, 12);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getICV(): number {
    return this.tail.getLong(-4, '>');
  }

  setICV(value?: number | null): void {
    let v = value;
    if (v === undefined || v === null) {
      v = crc32Swap(this.bodyString);
    }
    this.tail.setLong(-4, v & 0xffffffff);
  }

  getMIC(): Buffer {
    return this.getTailAsString().subarray(0, 8);
  }

  setMIC(value: Buffer): void {
    let v = value.length < 8
      ? Buffer.concat([value, Buffer.alloc(8 - value.length)])
      : value;
    v = v.subarray(0, 8);
    const icv = this.tail.getBufferAsString().subarray(-4);
    this.tail.setBytesFromString(Buffer.concat([v, icv]));
  }
}

// ---- WPA2 ----

export class Dot11WPA2 extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(8, 0);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  isWPA2(): boolean {
    const b = this.getPN1() === ((this.getPN0() | 0x20) & 0x7f);
    return !b && !!this.getExtIV();
  }

  getExtIV(): number { return (this.header.getByte(3) >> 5) & 0x1; }
  setExtIV(value: number): void {
    const masked = this.header.getByte(3) & (~0x20 & 0xff);
    this.header.setByte(3, masked | ((value & 0x01) << 5));
  }

  getKeyID(): number { return (this.header.getByte(3) >> 6) & 0x03; }
  setKeyID(value: number): void {
    const masked = this.header.getByte(3) & (~0xc0 & 0xff);
    this.header.setByte(3, masked | ((value & 0x03) << 6));
  }

  getDecryptedData(): Buffer { return this.bodyString; }

  getPN0(): number { return this.header.getByte(0) & 0xff; }
  setPN0(value: number): void { this.header.setByte(0, value & 0xff); }

  getPN1(): number { return this.header.getByte(1) & 0xff; }
  setPN1(value: number): void { this.header.setByte(1, value & 0xff); }

  getPN2(): number { return this.header.getByte(4) & 0xff; }
  setPN2(value: number): void { this.header.setByte(4, value & 0xff); }

  getPN3(): number { return this.header.getByte(5) & 0xff; }
  setPN3(value: number): void { this.header.setByte(5, value & 0xff); }

  getPN4(): number { return this.header.getByte(6) & 0xff; }
  setPN4(value: number): void { this.header.setByte(6, value & 0xff); }

  getPN5(): number { return this.header.getByte(7) & 0xff; }
  setPN5(value: number): void { this.header.setByte(7, value & 0xff); }
}

export class Dot11WPA2Data extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(0, 8);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getMIC(): Buffer { return this.getTailAsString(); }

  setMIC(value: Buffer): void {
    let v = value.length < 8
      ? Buffer.concat([value, Buffer.alloc(8 - value.length)])
      : value;
    v = v.subarray(0, 8);
    this.tail.setBytesFromString(v);
  }
}

// ---- RadioTap ----

export interface RadioTapFieldDef {
  readonly BIT_NUMBER: number;
  readonly STRUCTURE: string;
  readonly ALIGNMENT: number;
}

export class RadioTap extends ProtocolPacket {
  private static readonly HEADER_BASE_SIZE = 8;
  static readonly PRESENT_FLAGS_SIZE = 4;
  static readonly BASE_PRESENT_FLAGS_OFFSET = 4;

  static readonly RTF_TSFT: RadioTapFieldDef = { BIT_NUMBER: 0, STRUCTURE: '<Q', ALIGNMENT: 8 };

  static readonly RTF_FLAGS = {
    BIT_NUMBER: 1, STRUCTURE: '<B', ALIGNMENT: 1,
    PROPERTY_CFP: 0x01,
    PROPERTY_SHORTPREAMBLE: 0x02,
    PROPERTY_WEP: 0x04,
    PROPERTY_FRAGMENTATION: 0x08,
    PROPERTY_FCS_AT_END: 0x10,
    PROPERTY_PAYLOAD_PADDING: 0x20,
    PROPERTY_BAD_FCS: 0x40,
    PROPERTY_SHORT_GI: 0x80,
  } as const;

  static readonly RTF_RATE: RadioTapFieldDef = { BIT_NUMBER: 2, STRUCTURE: '<B', ALIGNMENT: 1 };
  static readonly RTF_CHANNEL: RadioTapFieldDef = { BIT_NUMBER: 3, STRUCTURE: '<HH', ALIGNMENT: 2 };
  static readonly RTF_FHSS: RadioTapFieldDef = { BIT_NUMBER: 4, STRUCTURE: '<BB', ALIGNMENT: 1 };
  static readonly RTF_DBM_ANTSIGNAL: RadioTapFieldDef = { BIT_NUMBER: 5, STRUCTURE: '<B', ALIGNMENT: 1 };
  static readonly RTF_DBM_ANTNOISE: RadioTapFieldDef = { BIT_NUMBER: 6, STRUCTURE: '<B', ALIGNMENT: 1 };
  static readonly RTF_LOCK_QUALITY: RadioTapFieldDef = { BIT_NUMBER: 7, STRUCTURE: '<H', ALIGNMENT: 2 };
  static readonly RTF_TX_ATTENUATION: RadioTapFieldDef = { BIT_NUMBER: 8, STRUCTURE: '<H', ALIGNMENT: 2 };
  static readonly RTF_DB_TX_ATTENUATION: RadioTapFieldDef = { BIT_NUMBER: 9, STRUCTURE: '<H', ALIGNMENT: 2 };
  static readonly RTF_DBM_TX_POWER: RadioTapFieldDef = { BIT_NUMBER: 10, STRUCTURE: '<b', ALIGNMENT: 2 };
  static readonly RTF_ANTENNA: RadioTapFieldDef = { BIT_NUMBER: 11, STRUCTURE: '<B', ALIGNMENT: 1 };
  static readonly RTF_DB_ANTSIGNAL: RadioTapFieldDef = { BIT_NUMBER: 12, STRUCTURE: '<B', ALIGNMENT: 1 };
  static readonly RTF_DB_ANTNOISE: RadioTapFieldDef = { BIT_NUMBER: 13, STRUCTURE: '<B', ALIGNMENT: 1 };
  static readonly RTF_FCS_IN_HEADER: RadioTapFieldDef = { BIT_NUMBER: 14, STRUCTURE: '<L', ALIGNMENT: 4 };
  static readonly RTF_TX_FLAGS: RadioTapFieldDef = { BIT_NUMBER: 15, STRUCTURE: '<H', ALIGNMENT: 2 };
  static readonly RTF_RTS_RETRIES: RadioTapFieldDef = { BIT_NUMBER: 16, STRUCTURE: '<B', ALIGNMENT: 1 };
  static readonly RTF_DATA_RETRIES: RadioTapFieldDef = { BIT_NUMBER: 17, STRUCTURE: '<B', ALIGNMENT: 1 };
  static readonly RTF_XCHANNEL: RadioTapFieldDef = { BIT_NUMBER: 18, STRUCTURE: '<LHBB', ALIGNMENT: 4 };
  static readonly RTF_EXT: RadioTapFieldDef = { BIT_NUMBER: 31, STRUCTURE: '', ALIGNMENT: 1 };

  static readonly radiotapFields: RadioTapFieldDef[] = [
    RadioTap.RTF_TSFT, RadioTap.RTF_FLAGS, RadioTap.RTF_RATE, RadioTap.RTF_CHANNEL,
    RadioTap.RTF_FHSS, RadioTap.RTF_DBM_ANTSIGNAL, RadioTap.RTF_DBM_ANTNOISE,
    RadioTap.RTF_LOCK_QUALITY, RadioTap.RTF_TX_ATTENUATION, RadioTap.RTF_DB_TX_ATTENUATION,
    RadioTap.RTF_DBM_TX_POWER, RadioTap.RTF_ANTENNA, RadioTap.RTF_DB_ANTSIGNAL,
    RadioTap.RTF_DB_ANTNOISE, RadioTap.RTF_FCS_IN_HEADER, RadioTap.RTF_TX_FLAGS,
    RadioTap.RTF_RTS_RETRIES, RadioTap.RTF_DATA_RETRIES, RadioTap.RTF_XCHANNEL, RadioTap.RTF_EXT,
  ].sort((a, b) => a.BIT_NUMBER - b.BIT_NUMBER);

  constructor(aBuffer?: Buffer) {
    if (aBuffer) {
      const length = aBuffer.readUInt16LE(2);
      super(length, 0);
      this.loadPacket(aBuffer);
    } else {
      super(RadioTap.HEADER_BASE_SIZE, 0);
      this.setVersion(0);
      this._setPresent(0x00000000);
    }
  }

  getHeaderLength(): number {
    this._updateHeaderLength();
    return this.header.getWord(2, '<');
  }

  getVersion(): number { return this.header.getByte(0); }
  setVersion(value: number): void { this.header.setByte(0, value & 0xff); }

  getPresent(offset = RadioTap.BASE_PRESENT_FLAGS_OFFSET): number {
    return this.header.getLong(offset, '<');
  }

  private _setPresent(value: number): void {
    this.header.setLong(4, value, '<');
  }

  getPresentBit(field: RadioTapFieldDef, offset = 4): boolean {
    const present = this.getPresent(offset);
    return !!((1 << field.BIT_NUMBER) & present);
  }

  private _setPresentBit(field: RadioTapFieldDef): void {
    const npresent = ((1 << field.BIT_NUMBER) | this.getPresent()) >>> 0;
    this.header.setLong(4, npresent, '<');
  }

  private _unsetPresentBit(field: RadioTapFieldDef): void {
    const npresent = (~(1 << field.BIT_NUMBER) & this.getPresent()) >>> 0;
    this.header.setLong(4, npresent, '<');
  }

  private _align(val: number, align: number): number {
    return ((((val) + ((align) - 1)) & ~((align) - 1)) - val);
  }

  private _getFieldPosition(field: RadioTapFieldDef): number | null {
    let offset = RadioTap.BASE_PRESENT_FLAGS_OFFSET;
    let extraPresentFlagsCount = 0;
    while (this.getPresentBit(RadioTap.RTF_EXT, offset)) {
      offset += RadioTap.PRESENT_FLAGS_SIZE;
      extraPresentFlagsCount++;
    }

    let fieldPosition = RadioTap.HEADER_BASE_SIZE + (RadioTap.BASE_PRESENT_FLAGS_OFFSET * extraPresentFlagsCount);

    for (const f of RadioTap.radiotapFields) {
      fieldPosition += this._align(fieldPosition, f.ALIGNMENT);
      if (f === field) return fieldPosition;
      if (this.getPresentBit(f)) {
        fieldPosition += structCalcSize(f.STRUCTURE);
      }
    }

    return null;
  }

  unsetField(field: RadioTapFieldDef): false | void {
    if (!this.getPresentBit(field)) return false;
    const bytePos = this._getFieldPosition(field);
    if (bytePos === null) return false;

    this._unsetPresentBit(field);
    let header = this.getHeaderAsString();
    const totalLength = structCalcSize(field.STRUCTURE);
    header = Buffer.concat([header.subarray(0, bytePos), header.subarray(bytePos + totalLength)]);
    this.loadHeader(header);
  }

  private _getFieldValues(field: RadioTapFieldDef): (number | bigint)[] | null {
    if (!this.getPresentBit(field)) return null;
    const bytePos = this._getFieldPosition(field);
    if (bytePos === null) return null;
    const header = this.getHeaderAsString();
    const totalLength = structCalcSize(field.STRUCTURE);
    const v = header.subarray(bytePos, bytePos + totalLength);
    return structUnpack(field.STRUCTURE, v);
  }

  private _setFieldValues(field: RadioTapFieldDef, values: (number | bigint)[]): void {
    const numFields = structCountFields(field.STRUCTURE);
    if (values.length !== numFields) {
      throw new Error(`Field has exactly ${numFields} items`);
    }

    const isPresent = this.getPresentBit(field);
    if (!isPresent) this._setPresentBit(field);

    const bytePos = this._getFieldPosition(field);
    if (bytePos === null) throw new Error('Cannot find field position');
    let header = this.getHeaderAsString();
    const totalLength = structCalcSize(field.STRUCTURE);
    const newStr = structPack(field.STRUCTURE, values);

    if (isPresent) {
      header = Buffer.concat([header.subarray(0, bytePos), newStr, header.subarray(bytePos + totalLength)]);
    } else {
      header = Buffer.concat([header.subarray(0, bytePos), newStr, header.subarray(bytePos)]);
    }
    this.loadHeader(header);
  }

  setTsft(nvalue: bigint): void { this._setFieldValues(RadioTap.RTF_TSFT, [nvalue]); }
  getTsft(): bigint | null {
    const v = this._getFieldValues(RadioTap.RTF_TSFT);
    return v ? v[0]! as bigint : null;
  }

  setFlags(nvalue: number): void { this._setFieldValues(RadioTap.RTF_FLAGS, [nvalue]); }
  getFlags(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_FLAGS);
    return v ? Number(v[0]!) : null;
  }

  setRate(nvalue: number): void { this._setFieldValues(RadioTap.RTF_RATE, [nvalue]); }
  getRate(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_RATE);
    return v ? Number(v[0]!) : null;
  }

  setChannel(freq: number, flags: number): void { this._setFieldValues(RadioTap.RTF_CHANNEL, [freq, flags]); }
  getChannel(): (number | bigint)[] | null { return this._getFieldValues(RadioTap.RTF_CHANNEL); }

  setFHSS(hopSet: number, hopPattern: number): void { this._setFieldValues(RadioTap.RTF_FHSS, [hopSet, hopPattern]); }
  getFHSS(): (number | bigint)[] | null { return this._getFieldValues(RadioTap.RTF_FHSS); }

  setDBmAntSignal(signal: number): void { this._setFieldValues(RadioTap.RTF_DBM_ANTSIGNAL, [signal]); }
  getDBmAntSignal(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_DBM_ANTSIGNAL);
    return v ? Number(v[0]!) : null;
  }

  setDBmAntNoise(signal: number): void { this._setFieldValues(RadioTap.RTF_DBM_ANTNOISE, [signal]); }
  getDBmAntNoise(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_DBM_ANTNOISE);
    return v ? Number(v[0]!) : null;
  }

  setLockQuality(quality: number): void { this._setFieldValues(RadioTap.RTF_LOCK_QUALITY, [quality]); }
  getLockQuality(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_LOCK_QUALITY);
    return v ? Number(v[0]!) : null;
  }

  setTxAttenuation(power: number): void { this._setFieldValues(RadioTap.RTF_TX_ATTENUATION, [power]); }
  getTxAttenuation(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_TX_ATTENUATION);
    return v ? Number(v[0]!) : null;
  }

  setDBTxAttenuation(power: number): void { this._setFieldValues(RadioTap.RTF_DB_TX_ATTENUATION, [power]); }
  getDBTxAttenuation(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_DB_TX_ATTENUATION);
    return v ? Number(v[0]!) : null;
  }

  setDBmTxPower(power: number): void { this._setFieldValues(RadioTap.RTF_DBM_TX_POWER, [power]); }
  getDBmTxPower(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_DBM_TX_POWER);
    return v ? Number(v[0]!) : null;
  }

  setAntenna(antennaIndex: number): void { this._setFieldValues(RadioTap.RTF_ANTENNA, [antennaIndex]); }
  getAntenna(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_ANTENNA);
    return v ? Number(v[0]!) : null;
  }

  setDBAntSignal(signal: number): void { this._setFieldValues(RadioTap.RTF_DB_ANTSIGNAL, [signal]); }
  getDBAntSignal(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_DB_ANTSIGNAL);
    return v ? Number(v[0]!) : null;
  }

  setDBAntNoise(signal: number): void { this._setFieldValues(RadioTap.RTF_DB_ANTNOISE, [signal]); }
  getDBAntNoise(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_DB_ANTNOISE);
    return v ? Number(v[0]!) : null;
  }

  setFCSInHeader(fcs: number): void { this._setFieldValues(RadioTap.RTF_FCS_IN_HEADER, [fcs]); }
  getFCSInHeader(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_FCS_IN_HEADER);
    return v ? Number(v[0]!) : null;
  }

  setTxFlags(flags: number): void { this._setFieldValues(RadioTap.RTF_TX_FLAGS, [flags]); }
  getTxFlags(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_TX_FLAGS);
    return v ? Number(v[0]!) : null;
  }

  setRTSRetries(retries: number): void { this._setFieldValues(RadioTap.RTF_RTS_RETRIES, [retries]); }
  getRTSRetries(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_RTS_RETRIES);
    return v ? Number(v[0]!) : null;
  }

  setDataRetries(retries: number): void { this._setFieldValues(RadioTap.RTF_DATA_RETRIES, [retries]); }
  getDataRetries(): number | null {
    const v = this._getFieldValues(RadioTap.RTF_DATA_RETRIES);
    return v ? Number(v[0]!) : null;
  }

  setXchannel(flags: number, freq: number, channel: number, maxpower: number): void {
    this._setFieldValues(RadioTap.RTF_XCHANNEL, [flags, freq, channel, maxpower]);
  }
  getXchannel(): (number | bigint)[] | null {
    return this._getFieldValues(RadioTap.RTF_XCHANNEL);
  }

  private _updateHeaderLength(): void {
    this.header.setWord(2, this.getHeaderSize(), '<');
  }

  override getPacket(): Buffer {
    this._updateHeaderLength();
    return super.getPacket();
  }
}

// ---- Management Frame ----

export class Dot11ManagementFrame extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(22, 0);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getDuration(): number { return this.header.getWord(0, '<'); }
  setDuration(value: number): void { this.header.setWord(0, value & 0xffff, '<'); }

  getDestinationAddress(): Buffer { return this.header.getBytes().subarray(2, 8); }
  setDestinationAddress(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(2 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }

  getSourceAddress(): Buffer { return this.header.getBytes().subarray(8, 14); }
  setSourceAddress(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(8 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }

  getBssid(): Buffer { return this.header.getBytes().subarray(14, 20); }
  setBssid(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(14 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }

  getSequenceControl(): number { return this.header.getWord(20, '<'); }
  setSequenceControl(value: number): void { this.header.setWord(20, value & 0xffff, '<'); }

  getFragmentNumber(): number { return this.getSequenceControl() & 0x000f; }
  setFragmentNumber(value: number): void {
    const masked = this.header.getWord(20, '<') & (~0x000f & 0xffff);
    this.header.setWord(20, masked | (value & 0x000f), '<');
  }

  getSequenceNumber(): number { return (this.getSequenceControl() >> 4) & 0xfff; }
  setSequenceNumber(value: number): void {
    const masked = this.header.getWord(20, '<') & (~0xfff0 & 0xffff);
    this.header.setWord(20, masked | ((value & 0x0fff) << 4), '<');
  }

  getFrameBody(): Buffer { return this.getBodyAsString(); }
  setFrameBody(data: Buffer): void { this.loadBody(data); }
}

// ---- Management Elements ----

export const DOT11_MANAGEMENT_ELEMENTS = {
  SSID: 0,
  SUPPORTED_RATES: 1,
  FH_PARAMETER_SET: 2,
  DS_PARAMETER_SET: 3,
  CF_PARAMETER_SET: 4,
  TIM: 5,
  IBSS_PARAMETER_SET: 6,
  COUNTRY: 7,
  HOPPING_PARAMETER: 8,
  HOPPING_TABLE: 9,
  REQUEST: 10,
  BSS_LOAD: 11,
  EDCA_PARAMETER_SET: 12,
  TSPEC: 13,
  TCLAS: 14,
  SCHEDULE: 15,
  CHALLENGE_TEXT: 16,
  POWER_CONSTRAINT: 32,
  POWER_CAPABILITY: 33,
  TPC_REQUEST: 34,
  TPC_REPORT: 35,
  SUPPORTED_CHANNELS: 36,
  CHANNEL_SWITCH_ANN: 37,
  MEASURE_REQ: 38,
  MEASURE_REP: 39,
  QUIET: 40,
  IBSS_DFS: 41,
  ERP_INFO: 42,
  TS_DELAY: 43,
  TCLAS_PROCESSING: 44,
  QOS_CAPABILITY: 46,
  RSN: 48,
  EXT_SUPPORTED_RATES: 50,
  EXTENDED_CAPABILITIES: 127,
  VENDOR_SPECIFIC: 221,
} as const;

// ---- Management Helper ----

export class Dot11ManagementHelper extends ProtocolPacket {
  private _headerBaseSize: number;

  constructor(headerSize: number, tailSize: number, aBuffer?: Buffer) {
    if (aBuffer) {
      const elementsLength = Dot11ManagementHelper._calculateElementsLength(aBuffer.subarray(headerSize));
      super(headerSize + elementsLength, tailSize);
      this._headerBaseSize = headerSize;
      this.loadPacket(aBuffer);
    } else {
      super(headerSize, tailSize);
      this._headerBaseSize = headerSize;
    }
  }

  protected *_findElement(elements: Buffer, elementId: number | null): Generator<[number, number, number | null]> {
    let remaining = elements.length;
    let offset = 0;
    while (remaining > 0) {
      if (remaining < 2) break;
      const id = elements[offset]!;
      let length = elements[offset + 1]!;
      if (elementId === null) {
        // pass through to compute total length
      } else if (id === elementId) {
        yield [0, offset, length + 2];
      }
      length += 2;
      offset += length;
      if (length > remaining) length = remaining;
      remaining -= length;
    }
    yield [-1, offset, null];
  }

  private static _calculateElementsLength(elements: Buffer): number {
    let remaining = elements.length;
    let offset = 0;
    while (remaining > 0) {
      if (remaining < 2) break;
      let length = elements[offset + 1]!;
      length += 2;
      offset += length;
      if (length > remaining) length = remaining;
      remaining -= length;
    }
    return offset;
  }

  protected *_getElementsGenerator(elementId: number): Generator<Buffer> {
    const elements = this.getHeaderAsString().subarray(this._headerBaseSize);
    const gen = this._findElement(elements, elementId);
    while (true) {
      const result = gen.next();
      if (result.done) return;
      const [match, offset, length] = result.value;
      if (match !== 0) return;
      const valueOffset = offset + 2;
      const valueEnd = offset + length!;
      yield elements.subarray(valueOffset, valueEnd);
    }
  }

  protected _getElement(elementId: number): Buffer | null {
    const gen = this._getElementsGenerator(elementId);
    const result = gen.next();
    if (result.done) return null;
    return result.value;
  }

  deleteElement(elementId: number, multiple = false): boolean {
    let header = this.getHeaderAsString();
    const elements = header.subarray(this._headerBaseSize);
    const gen = this._findElement(elements, elementId);
    let found = false;
    while (true) {
      const result = gen.next();
      if (result.done) break;
      const [match, offset, length] = result.value;
      if (match !== 0) break;
      const start = this._headerBaseSize + offset;
      header = Buffer.concat([header.subarray(0, start), header.subarray(start + length!)]);
      found = true;
      if (!multiple) break;
    }
    if (!found) return false;
    this.loadHeader(header);
    return true;
  }

  protected _setElement(elementId: number, value: Buffer, replace = true): void {
    const parameter = Buffer.concat([Buffer.from([elementId, value.length]), value]);
    let header = this.getHeaderAsString();
    const elements = header.subarray(this._headerBaseSize);
    const gen = this._findElement(elements, elementId);
    let found = false;
    while (true) {
      const result = gen.next();
      if (result.done) break;
      const [match, offset, length] = result.value;
      const start = this._headerBaseSize + offset;
      if (match === 0 && replace) {
        header = Buffer.concat([header.subarray(0, start), parameter, header.subarray(start + length!)]);
        found = true;
        break;
      } else if (match > 0) {
        header = Buffer.concat([header.subarray(0, start), parameter, header.subarray(start)]);
        found = true;
        break;
      } else {
        break;
      }
    }
    if (!found) {
      header = Buffer.concat([header, parameter]);
    }
    this.loadHeader(header);
  }
}

// ---- Management Beacon ----

export class Dot11ManagementBeacon extends Dot11ManagementHelper {
  constructor(aBuffer?: Buffer) {
    super(12, 0, aBuffer);
  }

  getTimestamp(): bigint { return this.header.getLongLong(0, '<'); }
  setTimestamp(value: bigint): void {
    this.header.setLongLong(0, value & 0xFFFFFFFFFFFFFFFFn, '<');
  }

  getBeaconInterval(): number { return this.header.getWord(8, '<'); }
  setBeaconInterval(value: number): void { this.header.setWord(8, value & 0xffff, '<'); }

  getCapabilities(): number { return this.header.getWord(10, '<'); }
  setCapabilities(value: number): void { this.header.setWord(10, value & 0xffff, '<'); }

  getSsid(): Buffer | null { return this._getElement(DOT11_MANAGEMENT_ELEMENTS.SSID); }
  setSsid(ssid: Buffer): void { this._setElement(DOT11_MANAGEMENT_ELEMENTS.SSID, ssid); }

  getSupportedRates(humanReadable = false): number[] | null {
    const s = this._getElement(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES);
    if (s === null) return null;
    const rates = [...s];
    if (!humanReadable) return rates;
    return rates.map(x => (x & 0x7f) * 0.5);
  }

  setSupportedRates(rates: number[]): void {
    if (rates.length > 8) throw new Error('requires up to eight rates');
    this._setElement(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES, Buffer.from(rates));
  }

  getDsParameterSet(): number | null {
    const s = this._getElement(DOT11_MANAGEMENT_ELEMENTS.DS_PARAMETER_SET);
    if (s === null) return null;
    return s[0]!;
  }

  setDsParameterSet(channel: number): void {
    this._setElement(DOT11_MANAGEMENT_ELEMENTS.DS_PARAMETER_SET, Buffer.from([channel]));
  }

  getRsn(): Buffer | null { return this._getElement(DOT11_MANAGEMENT_ELEMENTS.RSN); }
  setRsn(data: Buffer): void { this._setElement(DOT11_MANAGEMENT_ELEMENTS.RSN, data); }

  getErp(): number | null {
    const s = this._getElement(DOT11_MANAGEMENT_ELEMENTS.ERP_INFO);
    if (s === null) return null;
    return s[0]!;
  }

  setErp(erp: number): void {
    this._setElement(DOT11_MANAGEMENT_ELEMENTS.ERP_INFO, Buffer.from([erp]));
  }

  getCountry(): [Buffer, number, number, number] | null {
    const s = this._getElement(DOT11_MANAGEMENT_ELEMENTS.COUNTRY);
    if (s === null) return null;
    return [s.subarray(0, 3), s[3]!, s[4]!, s[5]!];
  }

  setCountry(code: Buffer, firstChannel: number, numberOfChannels: number, maxPower: number): void {
    if (code.length > 3) throw new Error('Country code must be up to 3 bytes long');
    const paddedCode = Buffer.alloc(3, 0x20);
    code.copy(paddedCode, 0, 0, Math.min(code.length, 3));
    this._setElement(
      DOT11_MANAGEMENT_ELEMENTS.COUNTRY,
      Buffer.concat([paddedCode, Buffer.from([firstChannel, numberOfChannels, maxPower])]),
    );
  }

  getVendorSpecific(): [Buffer, Buffer][] {
    const vs: [Buffer, Buffer][] = [];
    const gen = this._getElementsGenerator(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC);
    for (const s of gen) {
      vs.push([s.subarray(0, 3), s.subarray(3)]);
    }
    return vs;
  }

  addVendorSpecific(oui: Buffer, data: Buffer): void {
    if (data.length > 252) throw new Error('data allow up to 252 bytes long');
    if (oui.length > 3) throw new Error('oui is three bytes long');
    this._setElement(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC, Buffer.concat([oui, data]), false);
  }
}

// ---- Management Probe Request ----

export class Dot11ManagementProbeRequest extends Dot11ManagementHelper {
  constructor(aBuffer?: Buffer) {
    super(0, 0, aBuffer);
  }

  getSsid(): Buffer | null { return this._getElement(DOT11_MANAGEMENT_ELEMENTS.SSID); }
  setSsid(ssid: Buffer): void { this._setElement(DOT11_MANAGEMENT_ELEMENTS.SSID, ssid); }

  getSupportedRates(humanReadable = false): number[] | null {
    const s = this._getElement(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES);
    if (s === null) return null;
    const rates = [...s];
    if (!humanReadable) return rates;
    return rates.map(x => (x & 0x7f) * 0.5);
  }

  setSupportedRates(rates: number[]): void {
    if (rates.length > 8) throw new Error('requires up to eight rates');
    this._setElement(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES, Buffer.from(rates));
  }
}

// ---- Management Probe Response ----

export class Dot11ManagementProbeResponse extends Dot11ManagementBeacon {
  constructor(aBuffer?: Buffer) {
    super(aBuffer);
  }
}

// ---- Reason Codes ----

export const DOT11_REASON_CODES = {
  UNSPECIFIED_REASON: 1,
  PREV_AUTH_NO_LONGER_VALID: 2,
  DEAUTH_STA_IS_LEAVING: 3,
  DISASS_DUE_TO_INACTIVITY: 4,
  DISASS_AP_UNABLE_HANDLE_ALL_STA: 5,
  C2_FRAME_FROM_NONAUTHENTICATED_STA: 6,
  C3_FRAME_FROM_NONASSOCIATED_STA: 7,
  DISSASS_STA_IS_LEAVING: 8,
  STA_REQ_NOT_AUTH_STA: 9,
  DISASS_POWER_CAP_IE_UNNACCEPTABLE: 10,
  DISASS_SUP_CH_IE_UNNACCEPTABLE: 11,
  INVALID_IE: 13,
  MIC_FAILURE: 14,
  FOUR_WAY_HANDSHAKE_TIMEOUT: 15,
  GROUP_KEY_HANDSHAKE_TIMEOUT: 16,
  IE_FOUR_WAY_HANDSHAKE_DIFFERENT: 17,
  INVALID_GROUP_CIPHER: 18,
  INVALID_PAIRWISE_CIPHER: 19,
  INVALID_AKMP: 20,
  UNSUPPORTED_RSN_IE_VERSION: 21,
  INVALID_RSN_IE_CAP: 22,
  X_AUTH_FAILED: 23,
  CIPHER_SUITE_REJECTED_SECURITY_POLICY: 24,
  DISASS_QOS_RELATED_REASON: 32,
  DISASS_QOS_UNSUFFICIENT_BANDWIDTH: 33,
  DISASS_EXCESSIVE_FRAMES_WITHOUT_ACK: 34,
  DISASS_STA_TX_OUTSIDE_TXOPS: 35,
  REQ_STA_LEAVING: 36,
  REQ_STA_NOT_WANT_MECHANISM: 37,
  REQ_STA_RECV_FRAMES_WHICH_SETUP_REQ: 38,
  REQ_STA_DUE_TIMEOUT: 39,
  STA_NOT_SUPPORT_CIPHER_SUITE: 45,
} as const;

// ---- Management Deauthentication ----

export class Dot11ManagementDeauthentication extends ProtocolPacket {
  constructor(aBuffer?: Buffer) {
    super(2, 0);
    if (aBuffer) this.loadPacket(aBuffer);
  }

  getReasonCode(): number { return this.header.getWord(0, '<'); }
  setReasonCode(rc: number): void { this.header.setWord(0, rc, '<'); }
}

// ---- Auth Algorithms ----

export const DOT11_AUTH_ALGORITHMS = {
  OPEN: 0,
  SHARED_KEY: 1,
} as const;

// ---- Auth Status Codes ----

export const DOT11_AUTH_STATUS_CODES = {
  SUCCESSFUL: 0,
  UNSPECIFIED_FAILURE: 1,
  CAP_REQ_UNSUPPORTED: 10,
  REASS_DENIED_CANNOT_CONFIRM_ASS_EXISTS: 11,
  ASS_DENIED_REASON_OUTSIDE_SCOPE_STANDARD: 12,
  STA_NOT_SUPPORT_AUTH_ALGORITHM: 13,
  AUTH_SEQ_OUT_OF_EXPECTED: 14,
  AUTH_REJECTED_CHALLENGE_FAILURE: 15,
  AUTH_REJECTED_TIMEOUT: 16,
  ASS_DENIED_AP_UNABLE_HANDLE_MORE_STA: 17,
  ASS_DENIED_STA_NOT_SUPPORTING_DATA_RATES: 18,
  ASS_DENIED_STA_NOT_SUPPORTING_SHORT_PREAMBLE: 19,
  ASS_DENIED_STA_NOT_SUPPORTING_PBCC_MODULATION: 20,
  ASS_DENIED_STA_NOT_SUPPORTING_CHANNEL_AGILITY: 21,
  ASS_REQUEST_REJECTED_SPACTRUM_MGT_CAP: 22,
  ASS_REQUEST_REJECTED_POWER_CAP_IE_UNNACCEPTABLE: 23,
  ASS_REQUEST_REJECTED_SUP_CH_IE_UNNACCEPTABLE: 24,
  ASS_DENIED_STA_NOT_SUPPORTING_SHORT_SLOT_TIME: 25,
  ASS_DENIED_STA_NOT_SUPPORTING_DSSS_OFDM: 26,
  UNSPECIFIED_QOS: 32,
  ASS_DENIED_QOS_UNSUFFICIENT_BANDWIDTH: 33,
  ASS_DENIED_EXCESSIVE_FRAME_LOST: 34,
  ASS_DENIED_STA_NOT_SUPPORT_QOS: 35,
  REQ_HAS_BEEN_DECLINED: 37,
  REQ_NOT_SUCCESSFUL_PARAM_INVALID_VALUE: 38,
  TSPEC: 39,
  INVALID_IE: 40,
  INVALID_GROUP_CIPHER: 41,
  INVALID_PAIRWISE_CIPHER: 42,
  INVALID_AKMP: 43,
  UNSUPPORTED_RSN_IE_VERSION: 44,
  INVALID_RSN_IE_CAP: 45,
  CIPHER_SUITE_REJECTED_SECURITY_POLICY: 46,
  TS_NOT_CREATED: 47,
  DIRECT_LINK_NOT_ALLOWED_BSS_POLICY: 48,
  DST_STA_NOT_PRESENT_IN_BSS: 49,
  DST_STA_NOT_QOS_STA: 50,
  ASS_DENIED_LISTEN_INTERVAL_TOO_LARGE: 51,
} as const;

// ---- Management Authentication ----

export class Dot11ManagementAuthentication extends Dot11ManagementHelper {
  constructor(aBuffer?: Buffer) {
    super(6, 0, aBuffer);
  }

  getAuthenticationAlgorithm(): number { return this.header.getWord(0, '<'); }
  setAuthenticationAlgorithm(algorithm: number): void { this.header.setWord(0, algorithm, '<'); }

  getAuthenticationSequence(): number { return this.header.getWord(2, '<'); }
  setAuthenticationSequence(seq: number): void { this.header.setWord(2, seq, '<'); }

  getAuthenticationStatus(): number { return this.header.getWord(4, '<'); }
  setAuthenticationStatus(status: number): void { this.header.setWord(4, status, '<'); }

  getChallengeText(): Buffer | null {
    return this._getElement(DOT11_MANAGEMENT_ELEMENTS.CHALLENGE_TEXT);
  }

  setChallengeText(challenge: Buffer): void {
    this._setElement(DOT11_MANAGEMENT_ELEMENTS.CHALLENGE_TEXT, challenge);
  }

  getVendorSpecific(): [Buffer, Buffer][] {
    const vs: [Buffer, Buffer][] = [];
    const gen = this._getElementsGenerator(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC);
    for (const s of gen) {
      vs.push([s.subarray(0, 3), s.subarray(3)]);
    }
    return vs;
  }

  addVendorSpecific(oui: Buffer, data: Buffer): void {
    if (data.length > 252) throw new Error('data allow up to 252 bytes long');
    if (oui.length > 3) throw new Error('oui is three bytes long');
    this._setElement(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC, Buffer.concat([oui, data]), false);
  }
}

// ---- Management Disassociation ----

export class Dot11ManagementDisassociation extends Dot11ManagementDeauthentication {
  constructor(aBuffer?: Buffer) {
    super(aBuffer);
  }
}

// ---- Management Association Request ----

export class Dot11ManagementAssociationRequest extends Dot11ManagementHelper {
  constructor(aBuffer?: Buffer) {
    super(4, 0, aBuffer);
  }

  getCapabilities(): number { return this.header.getWord(0, '<'); }
  setCapabilities(value: number): void { this.header.setWord(0, value & 0xffff, '<'); }

  getListenInterval(): number { return this.header.getWord(2, '<'); }
  setListenInterval(value: number): void { this.header.setWord(2, value, '<'); }

  getSsid(): Buffer | null { return this._getElement(DOT11_MANAGEMENT_ELEMENTS.SSID); }
  setSsid(ssid: Buffer): void { this._setElement(DOT11_MANAGEMENT_ELEMENTS.SSID, ssid); }

  getSupportedRates(humanReadable = false): number[] | null {
    const s = this._getElement(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES);
    if (s === null) return null;
    const rates = [...s];
    if (!humanReadable) return rates;
    return rates.map(x => (x & 0x7f) * 0.5);
  }

  setSupportedRates(rates: number[]): void {
    if (rates.length > 8) throw new Error('requires up to eight rates');
    this._setElement(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES, Buffer.from(rates));
  }

  getRsn(): Buffer | null { return this._getElement(DOT11_MANAGEMENT_ELEMENTS.RSN); }
  setRsn(data: Buffer): void { this._setElement(DOT11_MANAGEMENT_ELEMENTS.RSN, data); }

  getVendorSpecific(): [Buffer, Buffer][] {
    const vs: [Buffer, Buffer][] = [];
    const gen = this._getElementsGenerator(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC);
    for (const s of gen) {
      vs.push([s.subarray(0, 3), s.subarray(3)]);
    }
    return vs;
  }

  addVendorSpecific(oui: Buffer, data: Buffer): void {
    if (data.length > 252) throw new Error('data allow up to 252 bytes long');
    if (oui.length > 3) throw new Error('oui is three bytes long');
    this._setElement(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC, Buffer.concat([oui, data]), false);
  }
}

// ---- Management Association Response ----

export class Dot11ManagementAssociationResponse extends Dot11ManagementHelper {
  constructor(aBuffer?: Buffer) {
    super(6, 0, aBuffer);
  }

  getCapabilities(): number { return this.header.getWord(0, '<'); }
  setCapabilities(value: number): void { this.header.setWord(0, value & 0xffff, '<'); }

  getStatusCode(): number { return this.header.getWord(2, '<'); }
  setStatusCode(value: number): void { this.header.setWord(2, value, '<'); }

  getAssociationId(): number { return this.header.getWord(4, '<'); }
  setAssociationId(value: number): void { this.header.setWord(4, value, '<'); }

  getSupportedRates(humanReadable = false): number[] | null {
    const s = this._getElement(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES);
    if (s === null) return null;
    const rates = [...s];
    if (!humanReadable) return rates;
    return rates.map(x => (x & 0x7f) * 0.5);
  }

  setSupportedRates(rates: number[]): void {
    if (rates.length > 8) throw new Error('requires up to eight rates');
    this._setElement(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES, Buffer.from(rates));
  }

  getVendorSpecific(): [Buffer, Buffer][] {
    const vs: [Buffer, Buffer][] = [];
    const gen = this._getElementsGenerator(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC);
    for (const s of gen) {
      vs.push([s.subarray(0, 3), s.subarray(3)]);
    }
    return vs;
  }

  addVendorSpecific(oui: Buffer, data: Buffer): void {
    if (data.length > 252) throw new Error('data allow up to 252 bytes long');
    if (oui.length > 3) throw new Error('oui is three bytes long');
    this._setElement(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC, Buffer.concat([oui, data]), false);
  }
}

// ---- Management Reassociation Request ----

export class Dot11ManagementReassociationRequest extends Dot11ManagementHelper {
  constructor(aBuffer?: Buffer) {
    super(10, 0, aBuffer);
  }

  getCapabilities(): number { return this.header.getWord(0, '<'); }
  setCapabilities(value: number): void { this.header.setWord(0, value & 0xffff, '<'); }

  getListenInterval(): number { return this.header.getWord(2, '<'); }
  setListenInterval(value: number): void { this.header.setWord(2, value, '<'); }

  getCurrentAp(): Buffer { return this.header.getBytes().subarray(4, 10); }
  setCurrentAp(value: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) this.header.setByte(4 + i, Buffer.isBuffer(value) ? value[i]! : value[i]!);
  }

  getSsid(): Buffer | null { return this._getElement(DOT11_MANAGEMENT_ELEMENTS.SSID); }
  setSsid(ssid: Buffer): void { this._setElement(DOT11_MANAGEMENT_ELEMENTS.SSID, ssid); }

  getSupportedRates(humanReadable = false): number[] | null {
    const s = this._getElement(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES);
    if (s === null) return null;
    const rates = [...s];
    if (!humanReadable) return rates;
    return rates.map(x => (x & 0x7f) * 0.5);
  }

  setSupportedRates(rates: number[]): void {
    if (rates.length > 8) throw new Error('requires up to eight rates');
    this._setElement(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES, Buffer.from(rates));
  }

  getRsn(): Buffer | null { return this._getElement(DOT11_MANAGEMENT_ELEMENTS.RSN); }
  setRsn(data: Buffer): void { this._setElement(DOT11_MANAGEMENT_ELEMENTS.RSN, data); }

  getVendorSpecific(): [Buffer, Buffer][] {
    const vs: [Buffer, Buffer][] = [];
    const gen = this._getElementsGenerator(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC);
    for (const s of gen) {
      vs.push([s.subarray(0, 3), s.subarray(3)]);
    }
    return vs;
  }

  addVendorSpecific(oui: Buffer, data: Buffer): void {
    if (data.length > 252) throw new Error('data allow up to 252 bytes long');
    if (oui.length > 3) throw new Error('oui is three bytes long');
    this._setElement(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC, Buffer.concat([oui, data]), false);
  }
}

// ---- Management Reassociation Response ----

export class Dot11ManagementReassociationResponse extends Dot11ManagementAssociationResponse {
  constructor(aBuffer?: Buffer) {
    super(aBuffer);
  }
}

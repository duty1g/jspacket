import { Buffer } from 'node:buffer';

export class ImpactPacketException extends Error {
  constructor(value: string) {
    super(value);
    this.name = 'ImpactPacketException';
  }
}

export function arrayTobytes(buf: Buffer): Buffer {
  return buf;
}

const BYTE_ORDER: Record<string, string> = {
  '!': 'BE',
  '>': 'BE',
  '<': 'LE',
  '=': 'LE',
};

export class PacketBuffer {
  private _bytes: Buffer;

  constructor(length?: number) {
    this._bytes = length ? Buffer.alloc(length) : Buffer.alloc(0);
  }

  setBytesFromString(data: Buffer | Uint8Array): void {
    this._bytes = Buffer.from(data);
  }

  getBufferAsString(): Buffer {
    return Buffer.from(this._bytes);
  }

  getBytes(): Buffer {
    return this._bytes;
  }

  setBytes(bytes: Buffer): void {
    this._bytes = Buffer.from(bytes);
  }

  setByte(index: number, value: number): void {
    index = this._validateIndex(index, 1);
    this._bytes[index] = value & 0xff;
  }

  getByte(index: number): number {
    index = this._validateIndex(index, 1);
    return this._bytes[index]!;
  }

  setWord(index: number, value: number, order = '!'): void {
    index = this._validateIndex(index, 2);
    if (BYTE_ORDER[order] === 'BE') {
      this._bytes.writeUInt16BE(value & 0xffff, index < 0 ? this._bytes.length + index : index);
    } else {
      this._bytes.writeUInt16LE(value & 0xffff, index < 0 ? this._bytes.length + index : index);
    }
  }

  getWord(index: number, order = '!'): number {
    index = this._validateIndex(index, 2);
    const off = index < 0 ? this._bytes.length + index : index;
    return BYTE_ORDER[order] === 'BE'
      ? this._bytes.readUInt16BE(off)
      : this._bytes.readUInt16LE(off);
  }

  setLong(index: number, value: number, order = '!'): void {
    index = this._validateIndex(index, 4);
    const off = index < 0 ? this._bytes.length + index : index;
    if (BYTE_ORDER[order] === 'BE') {
      this._bytes.writeUInt32BE(value >>> 0, off);
    } else {
      this._bytes.writeUInt32LE(value >>> 0, off);
    }
  }

  getLong(index: number, order = '!'): number {
    index = this._validateIndex(index, 4);
    const off = index < 0 ? this._bytes.length + index : index;
    return BYTE_ORDER[order] === 'BE'
      ? this._bytes.readUInt32BE(off)
      : this._bytes.readUInt32LE(off);
  }

  setLongLong(index: number, value: bigint, order = '!'): void {
    index = this._validateIndex(index, 8);
    const off = index < 0 ? this._bytes.length + index : index;
    if (BYTE_ORDER[order] === 'BE') {
      this._bytes.writeBigUInt64BE(value, off);
    } else {
      this._bytes.writeBigUInt64LE(value, off);
    }
  }

  getLongLong(index: number, order = '!'): bigint {
    index = this._validateIndex(index, 8);
    const off = index < 0 ? this._bytes.length + index : index;
    return BYTE_ORDER[order] === 'BE'
      ? this._bytes.readBigUInt64BE(off)
      : this._bytes.readBigUInt64LE(off);
  }

  getIpAddress(index: number): string {
    index = this._validateIndex(index, 4);
    const off = index < 0 ? this._bytes.length + index : index;
    return `${this._bytes[off]}.${this._bytes[off + 1]}.${this._bytes[off + 2]}.${this._bytes[off + 3]}`;
  }

  setIpAddress(index: number, ipString: string): void {
    index = this._validateIndex(index, 4);
    const parts = ipString.split('.').map(Number);
    const off = index < 0 ? this._bytes.length + index : index;
    for (let i = 0; i < 4; i++) {
      this._bytes[off + i] = parts[i]!;
    }
  }

  setChecksumFromData(index: number, data: Buffer): void {
    this.setWord(index, this.computeChecksum(data));
  }

  computeChecksum(anArray: Buffer | number[]): number {
    const arr = Buffer.isBuffer(anArray) ? anArray : Buffer.from(anArray);
    let nleft = arr.length;
    let sum = 0;
    let pos = 0;
    while (nleft > 1) {
      sum = arr[pos]! * 256 + (arr[pos + 1]! + sum);
      pos += 2;
      nleft -= 2;
    }
    if (nleft === 1) {
      sum = sum + arr[pos]! * 256;
    }
    return this.normalizeChecksum(sum);
  }

  normalizeChecksum(aValue: number): number {
    let sum = aValue;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    sum = ~sum & 0xffff;
    return sum;
  }

  private _validateIndex(index: number, size: number): number {
    const origIndex = index;
    const curlen = this._bytes.length;
    if (index < 0) {
      index = curlen + index;
    }
    const diff = index + size - curlen;
    if (diff > 0) {
      this._bytes = Buffer.concat([this._bytes, Buffer.alloc(diff)]);
      if (origIndex < 0) {
        return origIndex - diff;
      }
    }
    return origIndex;
  }
}

export class ProtocolLayer {
  private _child: ProtocolLayer | null = null;
  private _parent: ProtocolLayer | null = null;

  contains(aHeader: ProtocolLayer): void {
    this._child = aHeader;
    aHeader.setParent(this);
  }

  setParent(myParent: ProtocolLayer | null): void {
    this._parent = myParent;
  }

  child(): ProtocolLayer | null {
    return this._child;
  }

  parent(): ProtocolLayer | null {
    return this._parent;
  }

  unlinkChild(): void {
    if (this._child) {
      this._child.setParent(null);
      this._child = null;
    }
  }

  getPacket(): Buffer {
    return Buffer.alloc(0);
  }

  getSize(): number {
    return 0;
  }
}

export class ProtocolPacket extends ProtocolLayer {
  private _HEADER_SIZE: number;
  private _BODY_SIZE = 0;
  private _TAIL_SIZE: number;
  private _header: PacketBuffer;
  private _body: PacketBuffer;
  private _tail: PacketBuffer;

  constructor(headerSize: number, tailSize: number) {
    super();
    this._HEADER_SIZE = headerSize;
    this._TAIL_SIZE = tailSize;
    this._header = new PacketBuffer(this._HEADER_SIZE);
    this._body = new PacketBuffer();
    this._tail = new PacketBuffer(this._TAIL_SIZE);
  }

  private _updateBodyFromChild(): void {
    if (this.child()) {
      const body = this.child()!.getPacket();
      this._BODY_SIZE = body.length;
      this._body.setBytesFromString(body);
    }
  }

  get header(): PacketBuffer {
    return this._header;
  }

  get body(): PacketBuffer {
    this._updateBodyFromChild();
    return this._body;
  }

  get tail(): PacketBuffer {
    return this._tail;
  }

  getHeaderSize(): number {
    return this._HEADER_SIZE;
  }

  getTailSize(): number {
    return this._TAIL_SIZE;
  }

  getBodySize(): number {
    this._updateBodyFromChild();
    return this._BODY_SIZE;
  }

  override getSize(): number {
    return this.getHeaderSize() + this.getBodySize() + this.getTailSize();
  }

  loadHeader(aBuffer: Buffer): void {
    this._HEADER_SIZE = aBuffer.length;
    this._header.setBytesFromString(aBuffer);
  }

  loadBody(aBuffer: Buffer): void {
    this.unlinkChild();
    this._BODY_SIZE = aBuffer.length;
    this._body.setBytesFromString(aBuffer);
  }

  loadTail(aBuffer: Buffer): void {
    this._TAIL_SIZE = aBuffer.length;
    this._tail.setBytesFromString(aBuffer);
  }

  loadPacket(aBuffer: Buffer): void {
    this.unlinkChild();
    this.loadHeader(aBuffer.subarray(0, this._HEADER_SIZE));
    const end = this._TAIL_SIZE <= 0 ? aBuffer.length : aBuffer.length - this._TAIL_SIZE;
    this._BODY_SIZE = end - this._HEADER_SIZE;
    this._body.setBytesFromString(aBuffer.subarray(this._HEADER_SIZE, end));
    if (this._TAIL_SIZE > 0) {
      this._tail.setBytesFromString(aBuffer.subarray(-this._TAIL_SIZE));
    }
  }

  getHeaderAsString(): Buffer {
    return this._header.getBufferAsString();
  }

  getBodyAsString(): Buffer {
    this._updateBodyFromChild();
    return this._body.getBufferAsString();
  }

  get bodyString(): Buffer {
    return this.getBodyAsString();
  }

  getTailAsString(): Buffer {
    return this._tail.getBufferAsString();
  }

  get tailString(): Buffer {
    return this.getTailAsString();
  }

  override getPacket(): Buffer {
    this._updateBodyFromChild();
    const parts: Buffer[] = [];
    const header = this.getHeaderAsString();
    if (header.length) parts.push(header);
    const body = this.getBodyAsString();
    if (body.length) parts.push(body);
    const tail = this.getTailAsString();
    if (tail.length) parts.push(tail);
    return Buffer.concat(parts);
  }
}

// Header combines PacketBuffer + ProtocolLayer via composition
export class Header extends ProtocolLayer {
  private _pb: PacketBuffer;
  autoChecksum = 1;
  static ethertype: number | null = null;
  static protocol: number | null = null;

  constructor(length?: number) {
    super();
    this._pb = new PacketBuffer(length);
  }

  // PacketBuffer delegations
  setBytesFromString(data: Buffer | Uint8Array): void { this._pb.setBytesFromString(data); }
  getBufferAsString(): Buffer { return this._pb.getBufferAsString(); }
  getBytes(): Buffer { return this._pb.getBytes(); }
  setBytes(bytes: Buffer): void { this._pb.setBytes(bytes); }
  setByte(index: number, value: number): void { this._pb.setByte(index, value); }
  getByte(index: number): number { return this._pb.getByte(index); }
  setWord(index: number, value: number, order = '!'): void { this._pb.setWord(index, value, order); }
  getWord(index: number, order = '!'): number { return this._pb.getWord(index, order); }
  setLong(index: number, value: number, order = '!'): void { this._pb.setLong(index, value, order); }
  getLong(index: number, order = '!'): number { return this._pb.getLong(index, order); }
  setLongLong(index: number, value: bigint, order = '!'): void { this._pb.setLongLong(index, value, order); }
  getLongLong(index: number, order = '!'): bigint { return this._pb.getLongLong(index, order); }
  getIpAddress(index: number): string { return this._pb.getIpAddress(index); }
  setIpAddress(index: number, ipString: string): void { this._pb.setIpAddress(index, ipString); }
  setChecksumFromData(index: number, data: Buffer): void { this._pb.setChecksumFromData(index, data); }
  computeChecksum(anArray: Buffer | number[]): number { return this._pb.computeChecksum(anArray); }
  normalizeChecksum(aValue: number): number { return this._pb.normalizeChecksum(aValue); }

  getDataAsString(): Buffer | null {
    if (this.child()) {
      return this.child()!.getPacket();
    }
    return null;
  }

  override getPacket(): Buffer {
    this.calculateChecksum();
    const data = this.getDataAsString();
    if (data) {
      return Buffer.concat([this.getBufferAsString(), data]);
    }
    return this.getBufferAsString();
  }

  override getSize(): number {
    let val = this.getHeaderSize();
    if (this.child()) {
      val += this.child()!.getSize();
    }
    return val;
  }

  calculateChecksum(): void { /* override in subclasses */ }

  getPseudoHeader(): Buffer {
    return Buffer.alloc(0);
  }

  loadHeader(aBuffer: Buffer): void {
    this.setBytesFromString(aBuffer);
    const hdrLen = this.getHeaderSize();
    let buf = aBuffer;
    if (buf.length < hdrLen) {
      buf = Buffer.concat([buf, Buffer.alloc(hdrLen - buf.length)]);
    }
    this.setBytesFromString(buf.subarray(0, hdrLen));
  }

  getHeaderSize(): number {
    throw new Error(`Method ${this.constructor.name}.getHeaderSize must be overridden.`);
  }

  toString(): string {
    const bytes = this.getBytes();
    if (bytes.length === 0) return '';
    let result = '';
    for (let i = 0; i < bytes.length; i++) {
      result += bytes[i]!.toString(16).padStart(2, '0');
      if (i % 2 === 1) result += ' ';
    }
    if (this.child()) {
      result += '\n' + this.child()!.toString();
    }
    return result;
  }
}

export class Data extends Header {
  constructor(aBuffer?: Buffer | string) {
    super();
    if (aBuffer) {
      this.setData(typeof aBuffer === 'string' ? Buffer.from(aBuffer) : aBuffer);
    }
  }

  setData(data: Buffer): void {
    this.setBytesFromString(data);
  }

  override getHeaderSize(): number {
    return this.getBytes().length;
  }

  override getSize(): number {
    return this.getBytes().length;
  }
}

export class EthernetTag extends PacketBuffer {
  constructor(value = 0x81000000) {
    super(4);
    this.setLong(0, value);
  }

  getTpid(): number { return this.getWord(0); }
  setTpid(value: number): void { this.setWord(0, value); }

  getPcp(): number { return (this.getByte(2) & 0xe0) >> 5; }
  setPcp(value: number): void {
    const orig = this.getByte(2);
    this.setByte(2, (orig & 0x1f) | ((value & 0x07) << 5));
  }

  getDei(): number { return (this.getByte(2) & 0x10) >> 4; }
  setDei(value: number): void {
    const orig = this.getByte(2);
    this.setByte(2, value ? orig | 0x10 : orig & 0xef);
  }

  getVid(): number { return this.getWord(2) & 0x0fff; }
  setVid(value: number): void {
    const orig = this.getWord(2);
    this.setWord(2, (orig & 0xf000) | (value & 0x0fff));
  }
}

export class Ethernet extends Header {
  static override ethertype = 0;
  tagCnt = 0;

  constructor(aBuffer?: Buffer) {
    super(14);
    if (aBuffer) {
      this.loadHeader(aBuffer);
    }
  }

  setEtherType(aValue: number): void {
    this.setWord(12 + 4 * this.tagCnt, aValue);
  }

  getEtherType(): number {
    return this.getWord(12 + 4 * this.tagCnt);
  }

  getTag(index: number): EthernetTag {
    index = this._validateTagIndex(index);
    return new EthernetTag(this.getLong(12 + 4 * index));
  }

  setTag(index: number, tag: EthernetTag): void {
    index = this._validateTagIndex(index);
    const pos = 12 + 4 * index;
    const tagBytes = tag.getBytes();
    for (let i = 0; i < tagBytes.length; i++) {
      this.setByte(pos + i, tagBytes[i]!);
    }
  }

  pushTag(tag: EthernetTag, index = 0): void {
    if (index < 0) index += this.tagCnt;
    const pos = 12 + 4 * Math.max(0, Math.min(index, this.tagCnt));
    const data = this.getBytes();
    const tagBytes = tag.getBytes();
    const newData = Buffer.concat([data.subarray(0, pos), tagBytes, data.subarray(pos)]);
    this.setBytes(newData);
    this.tagCnt += 1;
  }

  popTag(index = 0): EthernetTag {
    index = this._validateTagIndex(index);
    const pos = 12 + 4 * index;
    const tag = this.getLong(pos);
    const data = this.getBytes();
    const newData = Buffer.concat([data.subarray(0, pos), data.subarray(pos + 4)]);
    this.setBytes(newData);
    this.tagCnt -= 1;
    return new EthernetTag(tag);
  }

  override loadHeader(aBuffer: Buffer): void {
    this.tagCnt = 0;
    while (aBuffer.length > 13 + 4 * this.tagCnt) {
      const tpid = aBuffer.readUInt16BE(12 + 4 * this.tagCnt);
      if (tpid === 0x8100 || tpid === 0x88a8 || tpid === 0x9100) {
        this.tagCnt++;
      } else {
        break;
      }
    }
    const hdrLen = this.getHeaderSize();
    let buf = aBuffer;
    if (buf.length < hdrLen) {
      buf = Buffer.concat([buf, Buffer.alloc(hdrLen - buf.length)]);
    }
    this.setBytesFromString(buf.subarray(0, hdrLen));
  }

  override getHeaderSize(): number {
    return 14 + 4 * this.tagCnt;
  }

  override getPacket(): Buffer {
    if (this.child()) {
      try {
        const childEthertype = (this.child()!.constructor as typeof Header).ethertype;
        if (childEthertype) this.setEtherType(childEthertype);
      } catch { /* Data child */ }
    }
    return super.getPacket();
  }

  getEtherDhost(): Buffer {
    return this.getBytes().subarray(0, 6);
  }

  setEtherDhost(aValue: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) {
      this.setByte(i, Array.isArray(aValue) ? aValue[i]! : aValue[i]!);
    }
  }

  getEtherShost(): Buffer {
    return this.getBytes().subarray(6, 12);
  }

  setEtherShost(aValue: Buffer | number[]): void {
    for (let i = 0; i < 6; i++) {
      this.setByte(i + 6, Array.isArray(aValue) ? aValue[i]! : aValue[i]!);
    }
  }

  static asEthAddr(anArray: Buffer | number[]): string {
    const arr = Buffer.isBuffer(anArray) ? [...anArray] : anArray;
    return arr.map(x => x.toString(16).padStart(2, '0')).join(':');
  }

  private _validateTagIndex(index: number): number {
    if (index < 0) index += this.tagCnt;
    if (index < 0 || index >= this.tagCnt) {
      throw new IndexError('Tag index out of range');
    }
    return index;
  }
}

class IndexError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'IndexError';
  }
}

export class LinuxSLL extends Header {
  static typeDescriptions = [
    'sent to us by somebody else',
    'broadcast by somebody else',
    'multicast by somebody else',
    'sent to somebody else to somebody else',
    'sent by us',
  ];

  constructor(aBuffer?: Buffer) {
    super(16);
    if (aBuffer) this.loadHeader(aBuffer);
  }

  setType(type: number): void { this.setWord(0, type); }
  getType(): number { return this.getWord(0); }
  setArphdr(value: number): void { this.setWord(2, value); }
  getArphdr(): number { return this.getWord(2); }
  setAddrLen(len: number): void { this.setWord(4, len); }
  getAddrLen(): number { return this.getWord(4); }

  setAddr(addr: Buffer): void {
    let buf = addr;
    if (buf.length < 8) buf = Buffer.concat([buf, Buffer.alloc(8 - buf.length)]);
    buf.copy(this.getBytes(), 6, 0, 8);
  }

  getAddr(): Buffer {
    return this.getBytes().subarray(6, 14);
  }

  setEtherType(aValue: number): void { this.setWord(14, aValue); }
  getEtherType(): number { return this.getWord(14); }
  override getHeaderSize(): number { return 16; }

  override getPacket(): Buffer {
    if (this.child()) {
      const childEt = (this.child()!.constructor as typeof Header).ethertype;
      if (childEt) this.setEtherType(childEt);
    }
    return super.getPacket();
  }

  getTypeDesc(): string {
    const type = this.getType();
    return type < LinuxSLL.typeDescriptions.length
      ? LinuxSLL.typeDescriptions[type]!
      : 'Unknown';
  }
}

export class IPOption extends PacketBuffer {
  static IPOPT_EOL = 0;
  static IPOPT_NOP = 1;
  static IPOPT_RR = 7;
  static IPOPT_TS = 68;
  static IPOPT_LSRR = 131;
  static IPOPT_SSRR = 137;

  constructor(opcode = 0, size?: number) {
    if (size && (size < 3 || size > 40)) {
      throw new ImpactPacketException('IP Options must have a size between 3 and 40 bytes');
    }

    if (opcode === IPOption.IPOPT_EOL || opcode === IPOption.IPOPT_NOP) {
      super(1);
      this.setCode(opcode);
    } else if (opcode === IPOption.IPOPT_RR || opcode === IPOption.IPOPT_LSRR || opcode === IPOption.IPOPT_SSRR) {
      const s = size || 39;
      super(s);
      this.setCode(opcode);
      this.setLen(s);
      this.setPtr(4);
    } else if (opcode === IPOption.IPOPT_TS) {
      const s = size || 40;
      super(s);
      this.setCode(opcode);
      this.setLen(s);
      this.setPtr(5);
      this.setFlags(0);
    } else {
      if (!size) throw new ImpactPacketException('Size required for this type');
      super(size);
      this.setCode(opcode);
      this.setLen(size);
    }
  }

  appendIp(ip: string): void {
    const op = this.getCode();
    if (![IPOption.IPOPT_RR, IPOption.IPOPT_LSRR, IPOption.IPOPT_SSRR, IPOption.IPOPT_TS].includes(op)) {
      throw new ImpactPacketException(`append_ip() not supported for option type ${op}`);
    }
    let p = this.getPtr();
    if (!p) throw new ImpactPacketException('append_ip() failed, option ptr uninitialized');
    if (p + 4 > this.getLen()) throw new ImpactPacketException('append_ip() would overflow option');
    this.setIpAddress(p - 1, ip);
    p += 4;
    this.setPtr(p);
  }

  setCode(value: number): void { this.setByte(0, value); }
  getCode(): number { return this.getByte(0); }

  setFlags(flags: number): void {
    if (this.getCode() !== IPOption.IPOPT_TS) {
      throw new ImpactPacketException('Operation only supported on Timestamp option');
    }
    this.setByte(3, flags);
  }

  getFlags(): number {
    if (this.getCode() !== IPOption.IPOPT_TS) {
      throw new ImpactPacketException('Operation only supported on Timestamp option');
    }
    return this.getByte(3);
  }

  setLen(len: number): void { this.setByte(1, len); }
  setPtr(ptr: number): void { this.setByte(2, ptr); }
  getPtr(): number { return this.getByte(2); }
  getLen(): number { return this.getBytes().length; }
}

export class IP extends Header {
  static override ethertype = 0x0800;
  static override protocol: number | null = null;
  private _optionList: IPOption[] = [];
  private isBSD = false;

  constructor(aBuffer?: Buffer) {
    super(20);
    this.setIpV(4);
    this.setIpHl(5);
    this.setIpTtl(255);
    if (aBuffer) {
      this.autoChecksum = 0;
      this.loadHeader(aBuffer);
    }
    this.isBSD = process.platform.includes('bsd');
  }

  override getPacket(): Buffer {
    if (this.getIpP() === 0 && this.child()) {
      const childProto = (this.child()!.constructor as typeof Header).protocol;
      if (childProto) this.setIpP(childProto);
    }
    if (this.getIpLen() === 0) {
      this.setIpLen(this.getSize());
    }

    const childData = this.getDataAsString();

    if (this.autoChecksum) this.resetIpSum();

    const myBytes = Buffer.from(this.getBytes());
    const optBuffers: Buffer[] = [myBytes];
    for (const op of this._optionList) {
      optBuffers.push(op.getBytes());
    }
    let combined = Buffer.concat(optBuffers);
    const numPad = (4 - (combined.length % 4)) % 4;
    if (numPad) combined = Buffer.concat([combined, Buffer.alloc(numPad)]);

    if (this._optionList.length) {
      this.setIpHl(combined.length / 4);
    }

    if (this.autoChecksum) {
      const cksum = this.computeChecksum(combined);
      combined.writeUInt16BE(cksum, 10);
    }

    return childData ? Buffer.concat([combined, childData]) : combined;
  }

  override getPseudoHeader(): Buffer {
    const srcDst = this.getBytes().subarray(12, 20);
    const proto = Buffer.from([0, this.getBytes()[9]!]);
    const childSize = this.child() ? this.child()!.getSize() : 0;
    const sizeStr = Buffer.alloc(2);
    sizeStr.writeUInt16BE(childSize);
    return Buffer.concat([srcDst, proto, sizeStr]);
  }

  addOption(option: IPOption): void {
    this._optionList.push(option);
    let sum = 0;
    for (const op of this._optionList) sum += op.getLen();
    if (sum > 40) throw new ImpactPacketException(`Options overflowed in IP packet with length: ${sum}`);
  }

  getIpV(): number { return this.getByte(0) >> 4; }
  setIpV(value: number): void {
    let n = this.getByte(0);
    n = (n & 0x0f) | ((value & 0x0f) << 4);
    this.setByte(0, n);
  }

  getIpHl(): number { return this.getByte(0) & 0x0f; }
  setIpHl(value: number): void {
    let n = this.getByte(0);
    n = (n & 0xf0) | (value & 0x0f);
    this.setByte(0, n);
  }

  getIpTos(): number { return this.getByte(1); }
  setIpTos(value: number): void { this.setByte(1, value); }

  getIpLen(): number { return this.isBSD ? this.getWord(2, '=') : this.getWord(2); }
  setIpLen(value: number): void { if (this.isBSD) this.setWord(2, value, '='); else this.setWord(2, value); }

  getIpId(): number { return this.getWord(4); }
  setIpId(value: number): void { this.setWord(4, value); }

  getIpOff(): number { return this.isBSD ? this.getWord(6, '=') : this.getWord(6); }
  setIpOff(aValue: number): void { if (this.isBSD) this.setWord(6, aValue, '='); else this.setWord(6, aValue); }

  getIpOffmask(): number { return this.getIpOff() & 0x1fff; }
  setIpOffmask(aValue: number): void {
    let tmp = this.getIpOff() & 0xd000;
    tmp |= aValue;
    this.setIpOff(tmp);
  }

  getIpRf(): number { return this.getIpOff() & 0x8000; }
  setIpRf(aValue: boolean | number): void {
    let tmp = this.getIpOff();
    if (aValue) tmp |= 0x8000;
    else tmp &= 0xffff ^ 0x8000;
    this.setIpOff(tmp);
  }

  getIpDf(): number { return this.getIpOff() & 0x4000; }
  setIpDf(aValue: boolean | number): void {
    let tmp = this.getIpOff();
    if (aValue) tmp |= 0x4000;
    else tmp &= 0xffff ^ 0x4000;
    this.setIpOff(tmp);
  }

  getIpMf(): number { return this.getIpOff() & 0x2000; }
  setIpMf(aValue: boolean | number): void {
    let tmp = this.getIpOff();
    if (aValue) tmp |= 0x2000;
    else tmp &= 0xffff ^ 0x2000;
    this.setIpOff(tmp);
  }

  getIpTtl(): number { return this.getByte(8); }
  setIpTtl(value: number): void { this.setByte(8, value); }

  getIpP(): number { return this.getByte(9); }
  setIpP(value: number): void { this.setByte(9, value); }

  getIpSum(): number { return this.getWord(10); }
  setIpSum(value: number): void {
    this.autoChecksum = 0;
    this.setWord(10, value);
  }
  resetIpSum(): void {
    this.setIpSum(0x0000);
    this.autoChecksum = 1;
  }

  getIpSrc(): string { return this.getIpAddress(12); }
  setIpSrc(value: string): void { this.setIpAddress(12, value); }
  getIpDst(): string { return this.getIpAddress(16); }
  setIpDst(value: string): void { this.setIpAddress(16, value); }

  override getHeaderSize(): number {
    let opLen = 0;
    for (const op of this._optionList) opLen += op.getLen();
    const numPad = (4 - (opLen % 4)) % 4;
    return 20 + opLen + numPad;
  }

  override loadHeader(aBuffer: Buffer): void {
    this.setBytesFromString(aBuffer.subarray(0, 20));
    let optLeft = (this.getIpHl() - 5) * 4;
    const optBytes = Buffer.from(aBuffer.subarray(20, 20 + optLeft));
    if (optBytes.length !== optLeft) {
      throw new ImpactPacketException('Cannot load options from truncated packet');
    }
    let pos = 0;
    while (optLeft > 0) {
      const opType = optBytes[pos]!;
      let opLen: number;
      let newOption: IPOption;
      if (opType === IPOption.IPOPT_EOL || opType === IPOption.IPOPT_NOP) {
        newOption = new IPOption(opType);
        opLen = 1;
      } else {
        opLen = optBytes[pos + 1]!;
        if (opLen > optBytes.length - pos) throw new ImpactPacketException('IP Option length is too high');
        newOption = new IPOption(opType, opLen);
        newOption.setBytes(Buffer.from(optBytes.subarray(pos, pos + opLen)));
      }
      pos += opLen;
      optLeft -= opLen;
      this.addOption(newOption);
      if (opType === IPOption.IPOPT_EOL) break;
    }
  }

  fragmentBySize(aSize: number): IP[] {
    const dataLen = this.getDataAsString()?.length ?? 0;
    let numFrags = Math.floor(dataLen / aSize);
    if (dataLen % aSize) numFrags++;
    const sizeList: number[] = [];
    for (let i = 0; i < numFrags; i++) sizeList.push(aSize);
    return this.fragmentByList(sizeList);
  }

  fragmentByList(aList: number[]): IP[] {
    const childProto = this.child() ? (this.child()!.constructor as typeof Header).protocol ?? 0 : 0;
    let childData = this.getDataAsString();
    if (!childData) return [this];

    const ipHeaderBytes = this.getBytes();
    let currentOffset = 0;
    const fragmentList: IP[] = [];

    for (let fragSize of aList) {
      const ip = new IP();
      ip.setBytes(Buffer.from(ipHeaderBytes));
      ip.setIpP(childProto);
      if (fragSize % 8) fragSize += 8 - (fragSize % 8);
      ip.setIpOffmask(currentOffset / 8);
      currentOffset += fragSize;

      const data = new Data(childData.subarray(0, fragSize));
      childData = childData.subarray(fragSize);
      ip.setIpLen(20 + data.getSize());
      ip.contains(data);

      if (childData.length) {
        ip.setIpMf(1);
        fragmentList.push(ip);
      } else {
        ip.setIpMf(0);
        fragmentList.push(ip);
        return fragmentList;
      }
    }

    if (childData.length) {
      const ip = new IP();
      ip.setBytes(Buffer.from(ipHeaderBytes));
      ip.setIpOffmask(currentOffset);
      ip.setIpLen(20 + childData.length);
      const data = new Data(childData);
      ip.contains(data);
      fragmentList.push(ip);
    }

    return fragmentList;
  }
}

export class TCPOption extends PacketBuffer {
  static TCPOPT_EOL = 0;
  static TCPOPT_NOP = 1;
  static TCPOPT_MAXSEG = 2;
  static TCPOPT_WINDOW = 3;
  static TCPOPT_SACK_PERMITTED = 4;
  static TCPOPT_SACK = 5;
  static TCPOPT_TIMESTAMP = 8;
  static TCPOPT_SIGNATURE = 19;

  constructor(kind: number, data?: number) {
    if (kind === TCPOption.TCPOPT_EOL || kind === TCPOption.TCPOPT_NOP) {
      super(1);
      this.setKind(kind);
    } else if (kind === TCPOption.TCPOPT_MAXSEG) {
      super(4);
      this.setKind(kind);
      this.setLen(4);
      this.setMss(data ?? 512);
    } else if (kind === TCPOption.TCPOPT_WINDOW) {
      super(3);
      this.setKind(kind);
      this.setLen(3);
      this.setShiftCnt(data ?? 0);
    } else if (kind === TCPOption.TCPOPT_TIMESTAMP) {
      super(10);
      this.setKind(kind);
      this.setLen(10);
      this.setTs(data ?? 0);
    } else if (kind === TCPOption.TCPOPT_SACK_PERMITTED) {
      super(2);
      this.setKind(kind);
      this.setLen(2);
    } else if (kind === TCPOption.TCPOPT_SACK) {
      super(2);
      this.setKind(kind);
    } else {
      super(2);
      this.setKind(kind);
    }
  }

  setLeftEdge(aValue: number): void { this.setLong(2, aValue); }
  setRightEdge(aValue: number): void { this.setLong(6, aValue); }
  setKind(kind: number): void { this.setByte(0, kind); }
  getKind(): number { return this.getByte(0); }

  setLen(len: number): void {
    if (this.getSize() < 2) throw new ImpactPacketException('Cannot set length field on an option having a size smaller than 2 bytes');
    this.setByte(1, len);
  }

  getLen(): number {
    if (this.getSize() < 2) throw new ImpactPacketException('Cannot retrieve length field from an option having a size smaller than 2 bytes');
    return this.getByte(1);
  }

  getSize(): number { return this.getBytes().length; }

  setMss(len: number): void {
    if (this.getKind() !== TCPOption.TCPOPT_MAXSEG) throw new ImpactPacketException('Can only set MSS on TCPOPT_MAXSEG option');
    this.setWord(2, len);
  }

  getMss(): number {
    if (this.getKind() !== TCPOption.TCPOPT_MAXSEG) throw new ImpactPacketException('Can only retrieve MSS from TCPOPT_MAXSEG option');
    return this.getWord(2);
  }

  setShiftCnt(cnt: number): void {
    if (this.getKind() !== TCPOption.TCPOPT_WINDOW) throw new ImpactPacketException('Can only set Shift Count on TCPOPT_WINDOW option');
    this.setByte(2, cnt);
  }

  getShiftCnt(): number {
    if (this.getKind() !== TCPOption.TCPOPT_WINDOW) throw new ImpactPacketException('Can only retrieve Shift Count from TCPOPT_WINDOW option');
    return this.getByte(2);
  }

  getTs(): number {
    if (this.getKind() !== TCPOption.TCPOPT_TIMESTAMP) throw new ImpactPacketException('Can only retrieve timestamp from TCPOPT_TIMESTAMP option');
    return this.getLong(2);
  }

  setTs(ts: number): void {
    if (this.getKind() !== TCPOption.TCPOPT_TIMESTAMP) throw new ImpactPacketException('Can only set timestamp on TCPOPT_TIMESTAMP option');
    this.setLong(2, ts);
  }

  getTsEcho(): number {
    if (this.getKind() !== TCPOption.TCPOPT_TIMESTAMP) throw new ImpactPacketException('Can only retrieve timestamp from TCPOPT_TIMESTAMP option');
    return this.getLong(6);
  }

  setTsEcho(ts: number): void {
    if (this.getKind() !== TCPOption.TCPOPT_TIMESTAMP) throw new ImpactPacketException('Can only set timestamp on TCPOPT_TIMESTAMP option');
    this.setLong(6, ts);
  }
}

export class UDP extends Header {
  static override protocol = 17;

  constructor(aBuffer?: Buffer) {
    super(8);
    if (aBuffer) this.loadHeader(aBuffer);
  }

  getUhSport(): number { return this.getWord(0); }
  setUhSport(value: number): void { this.setWord(0, value); }
  getUhDport(): number { return this.getWord(2); }
  setUhDport(value: number): void { this.setWord(2, value); }
  getUhUlen(): number { return this.getWord(4); }
  setUhUlen(value: number): void { this.setWord(4, value); }
  getUhSum(): number { return this.getWord(6); }
  setUhSum(value: number): void { this.setWord(6, value); this.autoChecksum = 0; }

  override calculateChecksum(): void {
    if (this.autoChecksum && !this.getUhSum()) {
      if (!this.parent()) return;
      const pseudo = (this.parent() as Header).getPseudoHeader();
      const parts: Buffer[] = [pseudo, this.getBytes()];
      const data = this.getDataAsString();
      if (data) parts.push(data);
      const buffer = Buffer.concat(parts);
      this.setUhSum(this.computeChecksum(buffer));
    }
  }

  override getHeaderSize(): number { return 8; }

  override getPacket(): Buffer {
    if (this.getUhUlen() === 0) this.setUhUlen(this.getSize());
    return super.getPacket();
  }
}

export class TCP extends Header {
  static override protocol = 6;
  static TCP_FLAGS_MASK = 0x00ff;
  private _optionList: TCPOption[] = [];

  constructor(aBuffer?: Buffer) {
    super(20);
    this.setThOff(5);
    if (aBuffer) this.loadHeader(aBuffer);
  }

  addOption(option: TCPOption): void {
    this._optionList.push(option);
    let sum = 0;
    for (const op of this._optionList) sum += op.getSize();
    if (sum > 40) throw new ImpactPacketException('Cannot add TCP option, would overflow option space');
  }

  getOptions(): TCPOption[] { return this._optionList; }

  swapSourceAndDestination(): void {
    const oldSource = this.getThSport();
    this.setThSport(this.getThDport());
    this.setThDport(oldSource);
  }

  setThSport(aValue: number): void { this.setWord(0, aValue); }
  getThSport(): number { return this.getWord(0); }
  getThDport(): number { return this.getWord(2); }
  setThDport(aValue: number): void { this.setWord(2, aValue); }
  getThSeq(): number { return this.getLong(4); }
  setThSeq(aValue: number): void { this.setLong(4, aValue); }
  getThAck(): number { return this.getLong(8); }
  setThAck(aValue: number): void { this.setLong(8, aValue); }

  getThFlags(): number { return this.getWord(12) & TCP.TCP_FLAGS_MASK; }
  setThFlags(aValue: number): void {
    const masked = this.getWord(12) & ~TCP.TCP_FLAGS_MASK;
    this.setWord(12, masked | (aValue & TCP.TCP_FLAGS_MASK), '>');
  }

  getThWin(): number { return this.getWord(14); }
  setThWin(aValue: number): void { this.setWord(14, aValue); }
  setThSum(aValue: number): void { this.setWord(16, aValue); this.autoChecksum = 0; }
  getThSum(): number { return this.getWord(16); }
  getThUrp(): number { return this.getWord(18); }
  setThUrp(aValue: number): void { this.setWord(18, aValue); }

  getThReserved(): number { return this.getByte(12) & 0x0f; }
  getThOff(): number { return this.getByte(12) >> 4; }
  setThOff(aValue: number): void {
    const masked = this.getByte(12) & ~0xf0;
    this.setByte(12, masked | ((aValue << 4) & 0xf0));
  }

  getCWR(): number { return this._getFlag(128); }
  setCWR(): void { this._setFlags(128); }
  resetCWR(): void { this._resetFlags(128); }
  getECE(): number { return this._getFlag(64); }
  setECE(): void { this._setFlags(64); }
  resetECE(): void { this._resetFlags(64); }
  getURG(): number { return this._getFlag(32); }
  setURG(): void { this._setFlags(32); }
  resetURG(): void { this._resetFlags(32); }
  getACK(): number { return this._getFlag(16); }
  setACK(): void { this._setFlags(16); }
  resetACK(): void { this._resetFlags(16); }
  getPSH(): number { return this._getFlag(8); }
  setPSH(): void { this._setFlags(8); }
  resetPSH(): void { this._resetFlags(8); }
  getRST(): number { return this._getFlag(4); }
  setRST(): void { this._setFlags(4); }
  resetRST(): void { this._resetFlags(4); }
  getSYN(): number { return this._getFlag(2); }
  setSYN(): void { this._setFlags(2); }
  resetSYN(): void { this._resetFlags(2); }
  getFIN(): number { return this._getFlag(1); }
  setFIN(): void { this._setFlags(1); }
  resetFIN(): void { this._resetFlags(1); }

  override getHeaderSize(): number {
    return 20 + this._getPaddedOptions().length;
  }

  override calculateChecksum(): void {
    if (!this.autoChecksum || !this.parent()) return;
    this.setThSum(0);
    const pseudo = (this.parent() as Header).getPseudoHeader();
    const parts: Buffer[] = [pseudo, this.getBytes(), this._getPaddedOptions()];
    const data = this.getDataAsString();
    if (data) parts.push(data);
    const buffer = Buffer.concat(parts);
    this.setThSum(this.computeChecksum(buffer));
  }

  override getPacket(): Buffer {
    if (this._optionList.length) {
      this.setThOff(this.getHeaderSize() / 4);
    }
    this.calculateChecksum();
    const bytes = Buffer.concat([this.getBytes(), this._getPaddedOptions()]);
    const data = this.getDataAsString();
    return data ? Buffer.concat([bytes, data]) : bytes;
  }

  override loadHeader(aBuffer: Buffer): void {
    this.setBytesFromString(aBuffer.subarray(0, 20));
    let optLeft = (this.getThOff() - 5) * 4;
    const optBytes = Buffer.from(aBuffer.subarray(20, 20 + optLeft));
    if (optBytes.length !== optLeft) {
      throw new ImpactPacketException('Cannot load options from truncated packet');
    }
    let pos = 0;
    while (optLeft > 0) {
      const opKind = optBytes[pos]!;
      let opLen: number;
      let newOption: TCPOption;
      if (opKind === TCPOption.TCPOPT_EOL || opKind === TCPOption.TCPOPT_NOP) {
        newOption = new TCPOption(opKind);
        opLen = 1;
      } else {
        opLen = optBytes[pos + 1]!;
        if (opLen > optBytes.length - pos) throw new ImpactPacketException('TCP Option length is too high');
        if (opLen < 2) throw new ImpactPacketException('TCP Option length is too low');
        newOption = new TCPOption(opKind);
        newOption.setBytes(Buffer.from(optBytes.subarray(pos, pos + opLen)));
      }
      pos += opLen;
      optLeft -= opLen;
      this.addOption(newOption);
      if (opKind === TCPOption.TCPOPT_EOL) break;
    }
  }

  private _getFlag(bit: number): number {
    return this.getThFlags() & bit ? 1 : 0;
  }

  private _resetFlags(aValue: number): void {
    this.setThFlags(this.getThFlags() & ~aValue);
  }

  private _setFlags(aValue: number): void {
    this.setThFlags(this.getThFlags() | aValue);
  }

  private _getPaddedOptions(): Buffer {
    const parts: Buffer[] = [];
    for (const op of this._optionList) parts.push(op.getBytes());
    let opBuf = Buffer.concat(parts);
    const numPad = (4 - (opBuf.length % 4)) % 4;
    if (numPad) opBuf = Buffer.concat([opBuf, Buffer.alloc(numPad)]);
    return opBuf;
  }
}

export class ICMP extends Header {
  static override protocol = 1;
  static ICMP_ECHOREPLY = 0;
  static ICMP_UNREACH = 3;
  static ICMP_UNREACH_NET = 0;
  static ICMP_UNREACH_HOST = 1;
  static ICMP_UNREACH_PROTOCOL = 2;
  static ICMP_UNREACH_PORT = 3;
  static ICMP_UNREACH_NEEDFRAG = 4;
  static ICMP_UNREACH_SRCFAIL = 5;
  static ICMP_SOURCEQUENCH = 4;
  static ICMP_REDIRECT = 5;
  static ICMP_REDIRECT_NET = 0;
  static ICMP_REDIRECT_HOST = 1;
  static ICMP_ECHO = 8;
  static ICMP_ROUTERADVERT = 9;
  static ICMP_ROUTERSOLICIT = 10;
  static ICMP_TIMXCEED = 11;
  static ICMP_TIMXCEED_INTRANS = 0;
  static ICMP_TIMXCEED_REASS = 1;
  static ICMP_PARAMPROB = 12;
  static ICMP_TSTAMP = 13;
  static ICMP_TSTAMPREPLY = 14;
  static ICMP_IREQ = 15;
  static ICMP_IREQREPLY = 16;
  static ICMP_MASKREQ = 17;
  static ICMP_MASKREPLY = 18;

  constructor(aBuffer?: Buffer) {
    super(8);
    if (aBuffer) this.loadHeader(aBuffer);
  }

  override getHeaderSize(): number {
    const anomalies: Record<number, number> = {
      [ICMP.ICMP_TSTAMP]: 20, [ICMP.ICMP_TSTAMPREPLY]: 20,
      [ICMP.ICMP_MASKREQ]: 12, [ICMP.ICMP_MASKREPLY]: 12,
    };
    return anomalies[this.getIcmpType()] ?? 8;
  }

  getIcmpType(): number { return this.getByte(0); }
  setIcmpType(aValue: number): void { this.setByte(0, aValue); }
  getIcmpCode(): number { return this.getByte(1); }
  setIcmpCode(aValue: number): void { this.setByte(1, aValue); }
  getIcmpCksum(): number { return this.getWord(2); }
  setIcmpCksum(aValue: number): void { this.setWord(2, aValue); this.autoChecksum = 0; }
  getIcmpGwaddr(): string { return this.getIpAddress(4); }
  setIcmpGwaddr(ip: string): void { this.setIpAddress(4, ip); }
  getIcmpId(): number { return this.getWord(4); }
  setIcmpId(aValue: number): void { this.setWord(4, aValue); }
  getIcmpSeq(): number { return this.getWord(6); }
  setIcmpSeq(aValue: number): void { this.setWord(6, aValue); }
  getIcmpVoid(): number { return this.getLong(4); }
  setIcmpVoid(aValue: number): void { this.setLong(4, aValue); }
  getIcmpNextmtu(): number { return this.getWord(6); }
  setIcmpNextmtu(aValue: number): void { this.setWord(6, aValue); }
  getIcmpNumAddrs(): number { return this.getByte(4); }
  setIcmpNumAddrs(aValue: number): void { this.setByte(4, aValue); }
  getIcmpWpa(): number { return this.getByte(5); }
  setIcmpWpa(aValue: number): void { this.setByte(5, aValue); }
  getIcmpLifetime(): number { return this.getWord(6); }
  setIcmpLifetime(aValue: number): void { this.setWord(6, aValue); }
  getIcmpOtime(): number { return this.getLong(8); }
  setIcmpOtime(aValue: number): void { this.setLong(8, aValue); }
  getIcmpRtime(): number { return this.getLong(12); }
  setIcmpRtime(aValue: number): void { this.setLong(12, aValue); }
  getIcmpTtime(): number { return this.getLong(16); }
  setIcmpTtime(aValue: number): void { this.setLong(16, aValue); }
  getIcmpMask(): string { return this.getIpAddress(8); }
  setIcmpMask(mask: string): void { this.setIpAddress(8, mask); }

  override calculateChecksum(): void {
    if (this.autoChecksum && !this.getIcmpCksum()) {
      let buffer = this.getBufferAsString();
      const data = this.getDataAsString();
      if (data) buffer = Buffer.concat([buffer, data]);
      this.setIcmpCksum(this.computeChecksum(buffer));
    }
  }

  isDestinationUnreachable(): boolean { return this.getIcmpType() === 3; }
  isError(): boolean { return !this.isQuery(); }
  isHostUnreachable(): boolean { return this.isDestinationUnreachable() && this.getIcmpCode() === 1; }
  isNetUnreachable(): boolean { return this.isDestinationUnreachable() && this.getIcmpCode() === 0; }
  isPortUnreachable(): boolean { return this.isDestinationUnreachable() && this.getIcmpCode() === 3; }
  isProtocolUnreachable(): boolean { return this.isDestinationUnreachable() && this.getIcmpCode() === 2; }
  isQuery(): boolean { return [8, 9, 10, 13, 14, 15, 16, 17, 18].includes(this.getIcmpType()); }
}

export class IGMP extends Header {
  static override protocol = 2;

  constructor(aBuffer?: Buffer) {
    super(8);
    if (aBuffer) this.loadHeader(aBuffer);
  }

  getIgmpType(): number { return this.getByte(0); }
  setIgmpType(aValue: number): void { this.setByte(0, aValue); }
  getIgmpCode(): number { return this.getByte(1); }
  setIgmpCode(aValue: number): void { this.setByte(1, aValue); }
  getIgmpCksum(): number { return this.getWord(2); }
  setIgmpCksum(aValue: number): void { this.setWord(2, aValue); }
  getIgmpGroup(): number { return this.getLong(4); }
  setIgmpGroup(aValue: number): void { this.setLong(4, aValue); }
  override getHeaderSize(): number { return 8; }

  override calculateChecksum(): void {
    if (this.autoChecksum && !this.getIgmpCksum()) {
      this.setIgmpCksum(this.computeChecksum(this.getBytes()));
    }
  }
}

export class ARP extends Header {
  static override ethertype = 0x0806;

  constructor(aBuffer?: Buffer) {
    super(7);
    if (aBuffer) this.loadHeader(aBuffer);
  }

  getArHrd(): number { return this.getWord(0); }
  setArHrd(aValue: number): void { this.setWord(0, aValue); }
  getArPro(): number { return this.getWord(2); }
  setArPro(aValue: number): void { this.setWord(2, aValue); }
  getArHln(): number { return this.getByte(4); }
  setArHln(aValue: number): void { this.setByte(4, aValue); }
  getArPln(): number { return this.getByte(5); }
  setArPln(aValue: number): void { this.setByte(5, aValue); }
  getArOp(): number { return this.getWord(6); }
  setArOp(aValue: number): void { this.setWord(6, aValue); }

  getArSha(): number[] { return [...this.getBytes().subarray(8, 8 + this.getArHln())]; }
  setArSha(aValue: number[]): void {
    for (let i = 0; i < this.getArHln(); i++) this.setByte(i + 8, aValue[i]!);
  }

  getArSpa(): number[] {
    const off = 8 + this.getArHln();
    return [...this.getBytes().subarray(off, off + this.getArPln())];
  }
  setArSpa(aValue: number[]): void {
    const off = 8 + this.getArHln();
    for (let i = 0; i < this.getArPln(); i++) this.setByte(i + off, aValue[i]!);
  }

  getArTha(): number[] {
    const from = 8 + this.getArHln() + this.getArPln();
    return [...this.getBytes().subarray(from, from + this.getArHln())];
  }
  setArTha(aValue: number[]): void {
    const from = 8 + this.getArHln() + this.getArPln();
    for (let i = 0; i < this.getArHln(); i++) this.setByte(i + from, aValue[i]!);
  }

  getArTpa(): number[] {
    const from = 8 + 2 * this.getArHln() + this.getArPln();
    return [...this.getBytes().subarray(from, from + this.getArPln())];
  }
  setArTpa(aValue: number[]): void {
    const from = 8 + 2 * this.getArHln() + this.getArPln();
    for (let i = 0; i < this.getArPln(); i++) this.setByte(i + from, aValue[i]!);
  }

  override getHeaderSize(): number {
    return 8 + 2 * this.getArHln() + 2 * this.getArPln();
  }

  static getOpName(arOp: number): string {
    const map: Record<number, string> = { 1: 'REQUEST', 2: 'REPLY', 3: 'REVREQUEST', 4: 'REVREPLY', 8: 'INVREQUEST', 9: 'INVREPLY' };
    return map[arOp] ?? 'UNKNOWN';
  }

  static getHrdName(arHrd: number): string {
    const map: Record<number, string> = { 1: 'ARPHRD ETHER', 6: 'ARPHRD IEEE802', 15: 'ARPHRD FRELAY' };
    return map[arHrd] ?? 'UNKNOWN';
  }
}

// ── Decoders ──

export class Decoder {
  protected _decodedProtocol: ProtocolLayer | null = null;

  decode(_aBuffer: Buffer): ProtocolLayer {
    return new Data();
  }

  setDecodedProtocol(protocol: ProtocolLayer): void {
    this._decodedProtocol = protocol;
  }

  getProtocol<T extends ProtocolLayer>(aprotocol: new (...args: unknown[]) => T): T | null {
    let protocol = this._decodedProtocol;
    while (protocol) {
      if (protocol instanceof aprotocol) return protocol;
      protocol = protocol.child();
    }
    return null;
  }
}

export class EthDecoder extends Decoder {
  override decode(aBuffer: Buffer): Ethernet {
    const e = new Ethernet(aBuffer);
    this.setDecodedProtocol(e);
    const off = e.getHeaderSize();

    let packet: ProtocolLayer;
    if (e.getEtherType() === IP.ethertype) {
      packet = new IPDecoder().decode(aBuffer.subarray(off));
    } else if (e.getEtherType() === ARP.ethertype) {
      packet = new ARPDecoder().decode(aBuffer.subarray(off));
    } else {
      packet = new DataDecoder().decode(aBuffer.subarray(off));
    }
    e.contains(packet);
    return e;
  }
}

export class LinuxSLLDecoder extends Decoder {
  override decode(aBuffer: Buffer): LinuxSLL {
    const e = new LinuxSLL(aBuffer);
    this.setDecodedProtocol(e);
    const off = 16;
    let packet: ProtocolLayer;
    if (e.getEtherType() === IP.ethertype) {
      packet = new IPDecoder().decode(aBuffer.subarray(off));
    } else if (e.getEtherType() === ARP.ethertype) {
      packet = new ARPDecoder().decode(aBuffer.subarray(off));
    } else {
      packet = new DataDecoder().decode(aBuffer.subarray(off));
    }
    e.contains(packet);
    return e;
  }
}

export class IPDecoder extends Decoder {
  override decode(aBuffer: Buffer): IP {
    const i = new IP(aBuffer);
    this.setDecodedProtocol(i);
    const off = i.getHeaderSize();
    let end = i.getIpLen();
    if (end === 0) {
      console.warn('IP len reported as 0, most probably because of TCP segmentation offload. Attempting to fix its size');
      i.setIpLen(aBuffer.length);
      end = i.getIpLen();
    }

    let packet: ProtocolLayer;
    if (i.getIpP() === UDP.protocol) {
      packet = new UDPDecoder().decode(aBuffer.subarray(off, end));
    } else if (i.getIpP() === TCP.protocol) {
      packet = new TCPDecoder().decode(aBuffer.subarray(off, end));
    } else if (i.getIpP() === ICMP.protocol) {
      packet = new ICMPDecoder().decode(aBuffer.subarray(off, end));
    } else if (i.getIpP() === IGMP.protocol) {
      packet = new IGMPDecoder().decode(aBuffer.subarray(off, end));
    } else {
      packet = new DataDecoder().decode(aBuffer.subarray(off, end));
    }
    i.contains(packet);
    return i;
  }
}

export class ARPDecoder extends Decoder {
  override decode(aBuffer: Buffer): ARP {
    const arp = new ARP(aBuffer);
    this.setDecodedProtocol(arp);
    const off = arp.getHeaderSize();
    const packet = new DataDecoder().decode(aBuffer.subarray(off));
    arp.contains(packet);
    return arp;
  }
}

export class UDPDecoder extends Decoder {
  override decode(aBuffer: Buffer): UDP {
    const u = new UDP(aBuffer);
    this.setDecodedProtocol(u);
    const off = u.getHeaderSize();
    const packet = new DataDecoder().decode(aBuffer.subarray(off));
    u.contains(packet);
    return u;
  }
}

export class TCPDecoder extends Decoder {
  override decode(aBuffer: Buffer): TCP {
    const t = new TCP(aBuffer);
    this.setDecodedProtocol(t);
    const off = t.getHeaderSize();
    const packet = new DataDecoder().decode(aBuffer.subarray(off));
    t.contains(packet);
    return t;
  }
}

export class ICMPDecoder extends Decoder {
  override decode(aBuffer: Buffer): ICMP {
    const ic = new ICMP(aBuffer);
    this.setDecodedProtocol(ic);
    const off = ic.getHeaderSize();
    let packet: ProtocolLayer;
    if (ic.getIcmpType() === ICMP.ICMP_UNREACH) {
      packet = new IPDecoderForICMP().decode(aBuffer.subarray(off));
    } else {
      packet = new DataDecoder().decode(aBuffer.subarray(off));
    }
    ic.contains(packet);
    return ic;
  }
}

export class IGMPDecoder extends Decoder {
  override decode(aBuffer: Buffer): IGMP {
    const ig = new IGMP(aBuffer);
    const off = ig.getHeaderSize();
    const packet = new DataDecoder().decode(aBuffer.subarray(off));
    ig.contains(packet);
    return ig;
  }
}

export class IPDecoderForICMP extends Decoder {
  override decode(aBuffer: Buffer): IP {
    const i = new IP(aBuffer);
    this.setDecodedProtocol(i);
    const off = i.getHeaderSize();
    let packet: ProtocolLayer;
    if (i.getIpP() === UDP.protocol) {
      packet = new UDPDecoder().decode(aBuffer.subarray(off));
    } else {
      packet = new DataDecoder().decode(aBuffer.subarray(off));
    }
    i.contains(packet);
    return i;
  }
}

export interface KeyManager {
  getKey(bssid: string): string | Buffer | false;
}

export class BaseDot11Decoder extends Decoder {
  protected keyManager: KeyManager | null = null;

  constructor(keyManager?: KeyManager | null) {
    super();
    this.setKeyManager(keyManager ?? null);
  }

  setKeyManager(keyManager: KeyManager | null): void {
    this.keyManager = keyManager;
  }

  findKey(bssid: string): string | Buffer | false {
    if (!this.keyManager) return false;
    try {
      return this.keyManager.getKey(bssid);
    } catch {
      return false;
    }
  }
}

export class DataDecoder extends Decoder {
  override decode(aBuffer: Buffer): Data {
    const d = new Data(aBuffer);
    this.setDecodedProtocol(d);
    return d;
  }
}

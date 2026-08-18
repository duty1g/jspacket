import { Buffer } from 'node:buffer';
import { Header, PacketBuffer, ImpactPacketException } from '@impacket/impact';

const SEPARATOR = ':';
const SCOPE_SEPARATOR = '%';
const ADDRESS_BYTE_SIZE = 16;
const TOTAL_HEX_GROUPS = 8;
const HEX_GROUP_SIZE = 4;
const TOTAL_SEPARATORS = TOTAL_HEX_GROUPS - 1;
const ADDRESS_TEXT_SIZE = (TOTAL_HEX_GROUPS * HEX_GROUP_SIZE) + TOTAL_SEPARATORS;

export class IP6_Address {
  static ADDRESS_BYTE_SIZE = ADDRESS_BYTE_SIZE;

  private _bytes: Buffer;
  private _scopeId = '';

  constructor(address: string | Buffer | Uint8Array) {
    this._bytes = Buffer.alloc(ADDRESS_BYTE_SIZE);

    if (typeof address === 'string') {
      this._fromString(address);
    } else {
      this._fromBytes(address);
    }
  }

  private _fromString(address: string): void {
    if (address.includes(SCOPE_SEPARATOR)) {
      const parts = address.split(SCOPE_SEPARATOR);
      address = parts[0]!;
      if (parts[1] === '') throw new Error('Empty scope ID');
      this._scopeId = parts[1]!;
    }

    if (this._isCompressed(address)) {
      address = this._expandCompressed(address);
    }

    address = this._insertLeadingZeroes(address);

    if (address.length !== ADDRESS_TEXT_SIZE) {
      throw new Error(`IP6_Address - from_string - address size != ${ADDRESS_TEXT_SIZE}`);
    }

    const hexGroups = address.split(SEPARATOR);
    if (hexGroups.length !== TOTAL_HEX_GROUPS) {
      throw new Error(`IP6_Address - parsed hex groups != ${TOTAL_HEX_GROUPS}`);
    }

    let offset = 0;
    for (const group of hexGroups) {
      if (group.length !== HEX_GROUP_SIZE) {
        throw new Error(`IP6_Address - parsed hex group length != ${HEX_GROUP_SIZE}`);
      }
      const val = parseInt(group, 16);
      this._bytes[offset] = (val & 0xff00) >> 8;
      this._bytes[offset + 1] = val & 0x00ff;
      offset += 2;
    }
  }

  private _fromBytes(bytes: Buffer | Uint8Array): void {
    if (bytes.length !== ADDRESS_BYTE_SIZE) {
      throw new Error(`IP6_Address - from_bytes - array size != ${ADDRESS_BYTE_SIZE}`);
    }
    Buffer.from(bytes).copy(this._bytes);
  }

  private _isCompressed(address: string): boolean {
    if (address.includes(':::')) {
      throw new Error('IP6_Address - found triple colon');
    }
    const count = (address.match(/::/g) ?? []).length;
    if (count === 0) return false;
    if (count === 1) return true;
    throw new Error('IP6_Address - more than one compression marker ("::") found');
  }

  private _countCompressedGroups(address: string): number {
    const trimmed = address.replace('::', ':');
    return (trimmed.match(/:/g) ?? []).length + 1;
  }

  private _insertLeadingZeroes(address: string): string {
    const groups = address.split(SEPARATOR);
    return groups.map(g => g.padStart(4, '0')).join(SEPARATOR);
  }

  private _expandCompressed(address: string): string {
    const groupCount = this._countCompressedGroups(address);
    const groupsToInsert = TOTAL_HEX_GROUPS - groupCount;

    let pos = address.indexOf('::') + 1;
    let result = address;
    for (let i = 0; i < groupsToInsert; i++) {
      result = result.slice(0, pos) + '0000:' + result.slice(pos);
      pos += 5;
    }

    result = result.replace('::', ':');
    return result;
  }

  private _trimLeadingZeroes(s: string): string {
    const groups = s.split(SEPARATOR);
    return groups.map(g => {
      const trimmed = g.replace(/^0+/, '');
      return trimmed || '0';
    }).join(SEPARATOR);
  }

  private _trimLongestZeroChain(address: string): string {
    let chainSize = 8;

    while (chainSize > 0) {
      const groups = address.split(SEPARATOR);

      for (let index = 0; index < groups.length; index++) {
        if (groups[index] === '0') {
          const startIndex = index;
          let endIndex = index;
          while (endIndex < 7 && groups[endIndex + 1] === '0') {
            endIndex++;
          }
          const foundSize = endIndex - startIndex + 1;
          if (foundSize === chainSize) {
            return groups.slice(0, startIndex).join(SEPARATOR) +
              '::' +
              groups.slice(endIndex + 1).join(SEPARATOR);
          }
        }
      }
      chainSize--;
    }
    return address;
  }

  asString(compressAddress = true, scopedAddress = true): string {
    let s = '';
    for (let i = 0; i < this._bytes.length; i++) {
      s += this._bytes[i]!.toString(16).padStart(2, '0');
      if (i % 2 === 1) s += SEPARATOR;
    }
    s = s.slice(0, -1).toUpperCase();

    if (compressAddress) {
      s = this._trimLeadingZeroes(s);
      s = this._trimLongestZeroChain(s);
    }

    if (scopedAddress && this._scopeId !== '') {
      s += SCOPE_SEPARATOR + this._scopeId;
    }
    return s;
  }

  asBytes(): Buffer {
    return this._bytes;
  }

  toString(): string {
    return this.asString();
  }

  getScopeId(): string {
    return this._scopeId;
  }

  getUnscopedAddress(): string {
    return this.asString(true, false);
  }

  isMulticast(): boolean {
    return this._bytes[0] === 0xff;
  }

  isUnicast(): boolean {
    return this._bytes[0] === 0xfe;
  }

  isLinkLocalUnicast(): boolean {
    return this.isUnicast() && (this._bytes[1]! & 0xc0) === 0x80;
  }

  isSiteLocalUnicast(): boolean {
    return this.isUnicast() && (this._bytes[1]! & 0xc0) === 0xc0;
  }

  isUniqueLocalUnicast(): boolean {
    return this._bytes[0] === 0xfd;
  }

  getHumanReadableAddressType(): string {
    if (this.isMulticast()) return 'multicast';
    if (this.isUnicast()) {
      if (this.isLinkLocalUnicast()) return 'link-local unicast';
      if (this.isSiteLocalUnicast()) return 'site-local unicast';
      return 'unicast';
    }
    if (this.isUniqueLocalUnicast()) return 'unique-local unicast';
    return 'unknown type';
  }

  static isAValidTextRepresentation(text: string): boolean {
    try {
      new IP6_Address(text);
      return true;
    } catch {
      return false;
    }
  }
}

export class ExtensionOption extends PacketBuffer {
  static MAX_OPTION_LEN = 256;
  static OPTION_TYPE_VALUE = -1;
  static OPTION_DESCRIPTION = 'Unknown';

  constructor(optionType: number, size: number) {
    if (size > ExtensionOption.MAX_OPTION_LEN) {
      throw new ImpactPacketException(
        `Option size of ${size} is greater than the maximum of ${ExtensionOption.MAX_OPTION_LEN}`,
      );
    }
    super(size);
    this.setOptionType(optionType);
  }

  setOptionType(t: number): void { this.setByte(0, t); }
  getOptionType(): number { return this.getByte(0); }
  setOptionLength(len: number): void { this.setByte(1, len); }
  getOptionLength(): number { return this.getByte(1); }

  setData(data: Buffer | Uint8Array): void {
    this.setOptionLength(data.length);
    const bytes = this.getBytes();
    Buffer.from(data).copy(bytes, 2);
    this.setBytes(bytes);
  }

  getLen(): number { return this.getBytes().length; }
}

export class OptionPAD1 extends ExtensionOption {
  static override OPTION_TYPE_VALUE = 0x00;
  static override OPTION_DESCRIPTION = 'Pad1 Option';

  constructor() {
    super(OptionPAD1.OPTION_TYPE_VALUE, 1);
  }

  override getLen(): number { return 1; }
}

export class OptionPADN extends ExtensionOption {
  static override OPTION_TYPE_VALUE = 0x01;
  static override OPTION_DESCRIPTION = 'PadN Option';

  constructor(paddingSize: number) {
    if (paddingSize < 2) {
      throw new ImpactPacketException('PadN Extension Option must be greater than 2 bytes');
    }
    super(OptionPADN.OPTION_TYPE_VALUE, paddingSize);
    this.setData(Buffer.alloc(paddingSize - 2));
  }
}

export class IP6_Extension_Header extends Header {
  static HEADER_TYPE_VALUE = -1;
  static EXTENSION_HEADER_FIELDS_SIZE = 2;
  static HEADER_EXTENSION_DESCRIPTION = 'Unknown';

  protected _optionList: ExtensionOption[] = [];

  constructor(buffer?: Buffer) {
    const ctor = new.target as typeof IP6_Extension_Header;
    super(ctor.EXTENSION_HEADER_FIELDS_SIZE);
    if (buffer) {
      this.loadExtHeader(buffer);
    } else {
      this.reset();
    }
  }

  protected loadExtHeader(buffer: Buffer): void {
    const ctor = this.constructor as typeof IP6_Extension_Header;
    const fieldsSize = ctor.EXTENSION_HEADER_FIELDS_SIZE;
    this.setBytesFromString(buffer.subarray(0, fieldsSize));

    let remainingBytes = (this.getHeaderExtensionLength() + 1) * 8 - fieldsSize;
    let buf = Buffer.from(buffer.subarray(fieldsSize));

    if (remainingBytes > buf.length) {
      throw new ImpactPacketException('Cannot load options from truncated packet');
    }

    while (remainingBytes > 0) {
      const optionType = buf[0]!;
      if (optionType === OptionPAD1.OPTION_TYPE_VALUE) {
        this._optionList.push(new OptionPAD1());
        remainingBytes -= 1;
        buf = buf.subarray(1);
      } else {
        let optionLength = buf[1]!;
        optionLength += 2;
        this._optionList.push(new OptionPADN(optionLength));
        remainingBytes -= optionLength;
        buf = buf.subarray(optionLength);
      }
    }
  }

  reset(): void {}

  getHeaderType(): number {
    return (this.constructor as typeof IP6_Extension_Header).HEADER_TYPE_VALUE;
  }

  getHeadersFieldSize(): number {
    return IP6_Extension_Header.EXTENSION_HEADER_FIELDS_SIZE;
  }

  override getHeaderSize(): number {
    let size = this.getHeadersFieldSize();
    for (const opt of this._optionList) {
      size += opt.getLen();
    }
    return size;
  }

  getNextHeader(): number { return this.getByte(0); }
  getHeaderExtensionLength(): number { return this.getByte(1); }
  setNextHeader(v: number): void { this.setByte(0, v & 0xff); }
  setHeaderExtensionLength(v: number): void { this.setByte(1, v & 0xff); }

  addOption(option: ExtensionOption): void {
    this._optionList.push(option);
  }

  getOptions(): ExtensionOption[] {
    return this._optionList;
  }

  getPacket(): Buffer {
    this.setHeaderExtensionLength(Math.floor(this.getHeaderSize() / 8) - 1);

    const parts: Buffer[] = [this.getBufferAsString()];
    for (const opt of this._optionList) {
      parts.push(opt.getBufferAsString());
    }

    const data = this.getDataAsString();
    if (data && data.length > 0) {
      parts.push(data);
    }
    return Buffer.concat(parts);
  }

  override contains(aHeader: Header): void {
    super.contains(aHeader);
    if (aHeader instanceof IP6_Extension_Header) {
      this.setNextHeader(aHeader.getHeaderType());
    }
  }

  getPseudoHeader(): Buffer {
    return (this.parent() as unknown as { getPseudoHeader(): Buffer }).getPseudoHeader();
  }
}

export class BasicExtensionHeader extends IP6_Extension_Header {
  static MAX_OPTIONS_LEN = 256 * 8;
  static MIN_HEADER_LEN = 8;
  static MAX_HEADER_LEN = 8 + 256 * 8;

  private padded = false;

  override reset(): void {
    this.setNextHeader(0);
    this.setHeaderExtensionLength(0);
    this.addPadding();
  }

  override addOption(option: ExtensionOption): void {
    if (this.padded) {
      this._optionList.pop();
      this.padded = false;
    }
    super.addOption(option);
    this.addPadding();
  }

  addPadding(): void {
    const requiredOctets = 8 - (this.getHeaderSize() % 8);
    if (this.getHeaderSize() + requiredOctets > BasicExtensionHeader.MAX_HEADER_LEN) {
      throw new Error('Not enough space for the padding');
    }

    if (requiredOctets > 0 && requiredOctets < 8) {
      if (requiredOctets === 1) {
        super.addOption(new OptionPAD1());
      } else {
        super.addOption(new OptionPADN(requiredOctets));
      }
      this.padded = true;
    } else {
      this.padded = false;
    }
  }
}

export class HopByHop extends BasicExtensionHeader {
  static override HEADER_TYPE_VALUE = 0x00;
  static override HEADER_EXTENSION_DESCRIPTION = 'Hop By Hop Options';
}

export class DestinationOptions extends BasicExtensionHeader {
  static override HEADER_TYPE_VALUE = 0x3c;
  static override HEADER_EXTENSION_DESCRIPTION = 'Destination Options';
}

export class RoutingOptions extends IP6_Extension_Header {
  static override HEADER_TYPE_VALUE = 0x2b;
  static override HEADER_EXTENSION_DESCRIPTION = 'Routing Options';
  static ROUTING_OPTIONS_HEADER_FIELDS_SIZE = 8;

  override reset(): void {
    this.setNextHeader(0);
    this.setHeaderExtensionLength(0);
    this.setRoutingType(0);
    this.setSegmentsLeft(0);
  }

  override getHeadersFieldSize(): number {
    return RoutingOptions.ROUTING_OPTIONS_HEADER_FIELDS_SIZE;
  }

  setRoutingType(v: number): void { this.setByte(2, v); }
  getRoutingType(): number { return this.getByte(2); }
  setSegmentsLeft(v: number): void { this.setByte(3, v); }
  getSegmentsLeft(): number { return this.getByte(3); }
}

export class IP6 extends Header {
  static ethertype = 0x86dd;
  static HEADER_SIZE = 40;
  static IP_PROTOCOL_VERSION = 6;

  constructor(buffer?: Buffer) {
    super(IP6.HEADER_SIZE);
    this.setIpV(IP6.IP_PROTOCOL_VERSION);
    if (buffer) {
      this.loadHeader(buffer);
    }
  }

  override contains(aHeader: Header): void {
    super.contains(aHeader);
    if (aHeader instanceof IP6_Extension_Header) {
      this.setNextHeader(aHeader.getHeaderType());
    }
  }

  override getHeaderSize(): number {
    return IP6.HEADER_SIZE;
  }

  getPseudoHeader(): Buffer {
    const sourceAddress = this.getIpSrc().asBytes();
    const destinationAddress = this.getIpDst().asBytes();

    let upperLayerPacketLength = this.getPayloadLength();
    let upperLayerProtocolNumber = this.getNextHeader();

    let nextHeader = this.child();
    while (nextHeader instanceof IP6_Extension_Header) {
      upperLayerPacketLength -= nextHeader.getHeaderSize();
      upperLayerProtocolNumber = nextHeader.getNextHeader();
      nextHeader = nextHeader.child();
    }

    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(upperLayerPacketLength);

    return Buffer.concat([
      sourceAddress,
      destinationAddress,
      lenBuf,
      Buffer.from([0x00, 0x00, 0x00]),
      Buffer.from([upperLayerProtocolNumber]),
    ]);
  }

  getIpV(): number { return (this.getByte(0) & 0xf0) >> 4; }
  getTrafficClass(): number { return ((this.getByte(0) & 0x0f) << 4) | ((this.getByte(1) & 0xf0) >> 4); }
  getFlowLabel(): number { return ((this.getByte(1) & 0x0f) << 16) | (this.getByte(2) << 8) | this.getByte(3); }
  getPayloadLength(): number { return (this.getByte(4) << 8) | this.getByte(5); }
  getNextHeader(): number { return this.getByte(6); }
  getHopLimit(): number { return this.getByte(7); }

  getIpSrc(): IP6_Address {
    return new IP6_Address(this.getBytes().subarray(8, 24));
  }

  getIpDst(): IP6_Address {
    return new IP6_Address(this.getBytes().subarray(24, 40));
  }

  setIpV(version: number): void {
    if (version !== 6) throw new Error('set_ip_v - version != 6');
    let b = this.getByte(0) & 0x0f;
    b |= (version << 4);
    this.setByte(0, b);
  }

  setTrafficClass(tc: number): void {
    let b0 = this.getByte(0) & 0xf0;
    let b1 = this.getByte(1) & 0x0f;
    b0 |= (tc & 0xf0) >> 4;
    b1 |= (tc & 0x0f) << 4;
    this.setByte(0, b0);
    this.setByte(1, b1);
  }

  setFlowLabel(fl: number): void {
    let b1 = this.getByte(1) & 0xf0;
    b1 |= (fl & 0xf0000) >> 16;
    this.setByte(1, b1);
    this.setByte(2, (fl & 0x0ff00) >> 8);
    this.setByte(3, fl & 0x000ff);
  }

  setPayloadLength(pl: number): void {
    this.setByte(4, (pl & 0xff00) >> 8);
    this.setByte(5, pl & 0x00ff);
  }

  setNextHeader(nh: number): void { this.setByte(6, nh); }
  setHopLimit(hl: number): void { this.setByte(7, hl); }

  setIpSrc(address: string | Buffer | Uint8Array): void {
    const addr = new IP6_Address(address);
    const bytes = this.getBytes();
    addr.asBytes().copy(bytes, 8);
    this.setBytes(bytes);
  }

  setIpDst(address: string | Buffer | Uint8Array): void {
    const addr = new IP6_Address(address);
    const bytes = this.getBytes();
    addr.asBytes().copy(bytes, 24);
    this.setBytes(bytes);
  }
}

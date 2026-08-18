import { Buffer } from 'node:buffer';
import { Header } from '@impacket/impact';

const IP_ADDRESS_LENGTH = 4;

export class CDPTypes {
  static DeviceID_Type = 1;
  static Address_Type = 2;
  static PortID_Type = 3;
  static Capabilities_Type = 4;
  static SoftVersion_Type = 5;
  static Platform_Type = 6;
  static IPPrefix_Type = 7;
  static ProtocolHello_Type = 8;
  static MTU_Type = 17;
  static SystemName_Type = 20;
  static SystemObjectId_Type = 21;
  static SnmpLocation = 23;
}

function getByteFn(buffer: Buffer, offset: number): number {
  return buffer.readUInt8(offset);
}

function getWordFn(buffer: Buffer, offset: number): number {
  return buffer.readInt16BE(offset);
}

function getLongFn(buffer: Buffer, offset: number): number {
  return buffer.readUInt32BE(offset);
}

function getBytesFn(buffer: Buffer, offset: number, count: number): Buffer {
  return buffer.subarray(offset, offset + count);
}

export function macToString(macBytes: Buffer): string {
  const parts: string[] = [];
  for (let i = 0; i < 6; i++) {
    parts.push(macBytes[i]!.toString(16).padStart(2, '0'));
  }
  return parts.join(':');
}

function inetNtoa(ip: Buffer): string {
  return `${ip[0]}.${ip[1]}.${ip[2]}.${ip[3]}`;
}

export class CDPElement extends Header {
  protected _length = 8;

  constructor(aBuffer?: Buffer) {
    super(8);
    if (aBuffer) {
      this._length = CDPElement.GetLength(aBuffer);
      this.loadHeader(aBuffer.subarray(0, this._length));
    }
  }

  static GetLength(aBuffer: Buffer): number {
    return aBuffer.readInt16BE(2);
  }

  override getHeaderSize(): number {
    return this._length;
  }

  getLength(): number {
    return this.getWord(2);
  }

  getData(): Buffer {
    return this.getBytes().subarray(4, this.getLength());
  }

  getType(): number { return this.getWord(0); }

  getIpAddress(offset = 0, ip?: Buffer): string {
    if (!ip) {
      ip = this.getBytes().subarray(offset, offset + IP_ADDRESS_LENGTH);
    }
    return inetNtoa(ip);
  }
}

export class CDPDevice extends CDPElement {
  static Type = 1;

  getType(): number { return CDPDevice.Type; }
  getDeviceId(): Buffer { return this.getData(); }
  override toString(): string { return 'Device:' + this.getDeviceId().toString(); }
}

export class AddressDetails {
  static PROTOCOL_IP = 0xcc;

  totalLength = 0;
  buffer: Buffer = Buffer.alloc(0);

  static create(buff: Buffer): AddressDetails {
    return new AddressDetails(buff);
  }

  constructor(aBuffer?: Buffer) {
    if (aBuffer) {
      const addrLength = aBuffer.readInt16BE(3);
      this.totalLength = addrLength + 5;
      this.buffer = Buffer.from(aBuffer.subarray(0, this.totalLength));
    }
  }

  getTotalLength(): number { return this.totalLength; }
  getProtocolType(): Buffer { return this.buffer.subarray(0, 1); }
  getProtocolLength(): number { return getByteFn(this.buffer, 1); }
  getProtocol(): number { return getByteFn(this.buffer, 2); }
  getAddressLength(): number { return getWordFn(this.buffer, 3); }

  getAddress(): string | Buffer {
    const address = getBytesFn(this.buffer, 5, this.getAddressLength());
    if (this.getProtocol() === AddressDetails.PROTOCOL_IP) {
      return inetNtoa(address);
    }
    return address;
  }

  isProtocolIP(): boolean {
    return this.getProtocol() === AddressDetails.PROTOCOL_IP;
  }

  toString(): string {
    return `Protocol Type:${String(this.getProtocolType())} Protocol:${this.getProtocol()} Address Length:${this.getAddressLength()} Address:${String(this.getAddress())}`;
  }
}

export class Address extends CDPElement {
  static Type = 2;
  addressDetails: AddressDetails[] = [];

  constructor(aBuffer?: Buffer) {
    super(aBuffer);
    if (aBuffer) {
      let data = this.getBytes().subarray(8);
      this.addressDetails = [];
      while (data.length > 0) {
        const address = AddressDetails.create(data);
        this.addressDetails.push(address);
        data = data.subarray(address.getTotalLength());
      }
    }
  }

  getType(): number { return Address.Type; }
  getNumber(): number { return this.getLong(4); }
  getAddressDetails(): AddressDetails[] { return this.addressDetails; }

  override toString(): string {
    let s = 'Addresses:';
    for (const ad of this.addressDetails) {
      s += '\n' + ad.toString();
    }
    return s;
  }
}

export class Port extends CDPElement {
  static Type = 3;
  getType(): number { return Port.Type; }
  getPort(): Buffer { return this.getData(); }
  override toString(): string { return 'Port:' + this.getPort().toString(); }
}

export class Capabilities extends CDPElement {
  static Type = 4;

  private _router = false;
  private _transparentBridge = false;
  private _sourceRouteBridge = false;
  private _switch = false;
  private _host = false;
  private _igmpCapable = false;
  private _repeater = false;

  constructor(aBuffer?: Buffer) {
    super(aBuffer);
    this._initCapabilities();
  }

  getType(): number { return Capabilities.Type; }
  getCapabilities(): Buffer { return this.getData(); }

  private _initCapabilities(): void {
    const capData = this.getCapabilities();
    if (capData.length < 4) return;
    const capabilities = capData.readUInt32BE(0);
    this._router = (capabilities & 0x01) > 0;
    this._transparentBridge = (capabilities & 0x02) > 0;
    this._sourceRouteBridge = (capabilities & 0x04) > 0;
    this._switch = (capabilities & 0x08) > 0;
    this._host = (capabilities & 0x10) > 0;
    this._igmpCapable = (capabilities & 0x20) > 0;
    this._repeater = (capabilities & 0x40) > 0;
  }

  isRouter(): boolean { return this._router; }
  isTransparentBridge(): boolean { return this._transparentBridge; }
  isSourceRouteBridge(): boolean { return this._sourceRouteBridge; }
  isSwitch(): boolean { return this._switch; }
  isHost(): boolean { return this._host; }
  isIgmpCapable(): boolean { return this._igmpCapable; }
  isRepeater(): boolean { return this._repeater; }

  override toString(): string { return 'Capabilities:' + this.getCapabilities().toString('hex'); }
}

export class SoftVersion extends CDPElement {
  static Type = 5;
  getType(): number { return SoftVersion.Type; }
  getVersion(): Buffer { return this.getData(); }
  override toString(): string { return 'Version:' + this.getVersion().toString(); }
}

export class Platform extends CDPElement {
  static Type = 6;
  getType(): number { return Platform.Type; }
  getPlatform(): Buffer { return this.getData(); }
  override toString(): string { return 'Platform:' + this.getPlatform().toString(); }
}

export class IpPrefix extends CDPElement {
  static Type = 7;
  getType(): number { return IpPrefix.Type; }
  getIpPrefix(): string { return this.getIpAddress(4); }
  getBits(): number { return this.getByte(8); }
  override toString(): string { return `IP Prefix/Gateway: ${this.getIpPrefix()}/${this.getBits()}`; }
}

export class ProtocolHello extends CDPElement {
  static Type = 8;
  getType(): number { return ProtocolHello.Type; }
  getMasterIp(): string { return this.getIpAddress(9); }
  getVersion(): number { return this.getByte(17); }
  getSubVersion(): number { return this.getByte(18); }
  getStatus(): number { return this.getByte(19); }
  getClusterCommandMac(): Buffer { return this.getBytes().subarray(20, 26); }
  getSwitchMac(): Buffer { return this.getBytes().subarray(28, 34); }
  getManagementVlan(): number { return this.getWord(36); }

  override toString(): string {
    return `ProtocolHello: Master IP:${this.getMasterIp()} version:${this.getVersion()} subversion:${this.getSubVersion()} status:${this.getStatus()} Switch's Mac:${macToString(this.getSwitchMac())} Management VLAN:${this.getManagementVlan()}`;
  }
}

export class VTPManagementDomain extends CDPElement {
  static Type = 9;
  getType(): number { return VTPManagementDomain.Type; }
  getDomain(): Buffer { return this.getData(); }
}

export class VLAN extends CDPElement {
  static Type = 0x0a;
  getType(): number { return VLAN.Type; }
  getVlanNumber(): Buffer { return this.getData(); }
}

export class Duplex extends CDPElement {
  static Type = 0x0b;
  getType(): number { return Duplex.Type; }
  getDuplex(): Buffer { return this.getData(); }
  isFullDuplex(): boolean { return this.getDuplex()[0] === 0x01; }
}

export class TrustBitmap extends CDPElement {
  static Type = 0x12;
  getType(): number { return TrustBitmap.Type; }
  getTrustBitmap(): Buffer { return this.getData(); }
  override toString(): string { return 'TrustBitmap Trust Bitmap:' + this.getTrustBitmap().toString('hex'); }
}

export class UntrustedPortCoS extends CDPElement {
  static Type = 0x13;
  getType(): number { return UntrustedPortCoS.Type; }
  getPortCoS(): Buffer { return this.getData(); }
  override toString(): string { return 'UntrustedPortCoS port CoS ' + this.getPortCoS().toString('hex'); }
}

export class ManagementAddresses extends Address {
  static override Type = 0x16;
  override getType(): number { return ManagementAddresses.Type; }
}

export class MTU extends CDPElement {
  static Type = 0x11;
  getType(): number { return MTU.Type; }
}

export class SystemName extends CDPElement {
  static Type = 0x14;
  getType(): number { return SystemName.Type; }
}

export class SystemObjectId extends CDPElement {
  static Type = 0x15;
  getType(): number { return SystemObjectId.Type; }
}

export class SnmpLocation extends CDPElement {
  static Type = 0x17;
  getType(): number { return SnmpLocation.Type; }
}

export class DummyCdpElement extends CDPElement {
  static Type = 0x99;
  getType(): number { return DummyCdpElement.Type; }
}

type CDPElementConstructor = new (aBuffer?: Buffer) => CDPElement;

export class CDPElementFactory {
  static elementTypeMap: Record<number, CDPElementConstructor> = {
    [CDPDevice.Type]: CDPDevice,
    [Port.Type]: Port,
    [Capabilities.Type]: Capabilities,
    [Address.Type]: Address,
    [SoftVersion.Type]: SoftVersion,
    [Platform.Type]: Platform,
    [IpPrefix.Type]: IpPrefix,
    [ProtocolHello.Type]: ProtocolHello,
    [VTPManagementDomain.Type]: VTPManagementDomain,
    [VLAN.Type]: VLAN,
    [Duplex.Type]: Duplex,
    [TrustBitmap.Type]: TrustBitmap,
    [UntrustedPortCoS.Type]: UntrustedPortCoS,
    [ManagementAddresses.Type]: ManagementAddresses,
    [MTU.Type]: MTU,
    [SystemName.Type]: SystemName,
    [SystemObjectId.Type]: SystemObjectId,
    [SnmpLocation.Type]: SnmpLocation,
  };

  static create(aBuffer: Buffer): CDPElement {
    const type = aBuffer.readInt16BE(0);
    const ClassType = CDPElementFactory.elementTypeMap[type] ?? DummyCdpElement;
    return new ClassType(aBuffer);
  }
}

export class CDP extends Header {
  static Type = 0x2000;
  static OUI = 0x00000c;

  private _elements: CDPElement[] = [];

  constructor(aBuffer?: Buffer) {
    super(8);
    if (aBuffer) {
      this.loadHeader(aBuffer);
      this._elements = this._getElements(aBuffer);
    }
  }

  private _getElements(aBuffer: Buffer): CDPElement[] {
    let buff = aBuffer.subarray(4);
    const l: CDPElement[] = [];
    while (buff.length > 0) {
      const elem = CDPElementFactory.create(buff);
      l.push(elem);
      buff = buff.subarray(elem.getLength());
    }
    return l;
  }

  override getHeaderSize(): number { return 8; }
  getCdpVersion(): number { return this.getByte(0); }
  getTtl(): number { return this.getByte(1); }
  getChecksum(): number { return this.getWord(2); }
  getCdpType(): number { return this.getWord(4); }
  getCdpLength(): number { return this.getWord(6); }
  getElements(): CDPElement[] { return this._elements; }

  override toString(): string {
    let s = 'CDP Details:\n';
    for (const element of this._elements) {
      s += `** Type:${element.getType()} ${element.toString()}\n`;
    }
    return s;
  }
}

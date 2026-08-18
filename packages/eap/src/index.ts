import { ProtocolPacket, Byte, Word, Long, ThreeBytesBigEndian } from '@impacket/helper';

export const DOT1X_AUTHENTICATION = 0x888e;

const _eapExpandedVendorId = new ThreeBytesBigEndian(0);
const _eapExpandedVendorType = new Long(3, '>');

export class EAPExpanded extends ProtocolPacket {
  static WFA_SMI = 0x00372a;
  static SIMPLE_CONFIG = 0x00000001;
  static override headerSize = 7;
  static override tailSize = 0;

  getVendorId(): number { return _eapExpandedVendorId.getter(this) as number; }
  setVendorId(v: number): void { _eapExpandedVendorId.setter(this, v); }
  getVendorType(): number { return _eapExpandedVendorType.getter(this) as number; }
  setVendorType(v: number): void { _eapExpandedVendorType.setter(this, v); }
}

const _eaprType = new Byte(0);

export class EAPR extends ProtocolPacket {
  static IDENTITY = 0x01;
  static EXPANDED = 0xfe;
  static override headerSize = 1;
  static override tailSize = 0;

  getType(): number { return _eaprType.getter(this) as number; }
  setType(v: number): void { _eaprType.setter(this, v); }
}

const _eapCode = new Byte(0);
const _eapIdentifier = new Byte(1);
const _eapLength = new Word(2, '>');

export class EAP extends ProtocolPacket {
  static REQUEST = 0x01;
  static RESPONSE = 0x02;
  static SUCCESS = 0x03;
  static FAILURE = 0x04;
  static override headerSize = 4;
  static override tailSize = 0;

  getCode(): number { return _eapCode.getter(this) as number; }
  setCode(v: number): void { _eapCode.setter(this, v); }
  getIdentifier(): number { return _eapIdentifier.getter(this) as number; }
  setIdentifier(v: number): void { _eapIdentifier.setter(this, v); }
  getLength(): number { return _eapLength.getter(this) as number; }
  setLength(v: number): void { _eapLength.setter(this, v); }
}

const _eapolVersion = new Byte(0);
const _eapolPacketType = new Byte(1);
const _eapolBodyLength = new Word(2, '>');

export class EAPOL extends ProtocolPacket {
  static EAP_PACKET = 0x00;
  static EAPOL_START = 0x01;
  static EAPOL_LOGOFF = 0x02;
  static EAPOL_KEY = 0x03;
  static EAPOL_ENCAPSULATED_ASF_ALERT = 0x04;
  static DOT1X_VERSION = 0x01;
  static override headerSize = 4;
  static override tailSize = 0;

  getVersion(): number { return _eapolVersion.getter(this) as number; }
  setVersion(v: number): void { _eapolVersion.setter(this, v); }
  getPacketType(): number { return _eapolPacketType.getter(this) as number; }
  setPacketType(v: number): void { _eapolPacketType.setter(this, v); }
  getBodyLength(): number { return _eapolBodyLength.getter(this) as number; }
  setBodyLength(v: number): void { _eapolBodyLength.setter(this, v); }
}

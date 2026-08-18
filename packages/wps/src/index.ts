import { Buffer } from 'node:buffer';
import { ProtocolPacket, Byte, Bit } from '@impacket/helper';

export interface ValueBuilder {
  fromBuf(buf: Buffer): unknown;
  toBuf(value: unknown): Buffer;
}

export class ArrayBuilder implements ValueBuilder {
  fromBuf(buf: Buffer): Buffer { return buf; }
  toBuf(value: unknown): Buffer { return Buffer.from(value as Buffer); }
}

export class ByteBuilder implements ValueBuilder {
  fromBuf(buf: Buffer): number { return buf[0]!; }
  toBuf(value: unknown): Buffer { return Buffer.from([value as number]); }
}

export class StringBuilder implements ValueBuilder {
  fromBuf(buf: Buffer): Buffer { return Buffer.from(buf); }
  toBuf(value: unknown): Buffer { return Buffer.from(value as Buffer); }
}

export class NumBuilder implements ValueBuilder {
  constructor(public readonly size: number) {}

  fromBuf(buf: Buffer): bigint {
    if (buf.length !== this.size) {
      throw new Error(`Expected ${this.size} size but got ${buf.length}`);
    }
    let result = 0n;
    for (const b of buf) {
      result = result * 256n + BigInt(b);
    }
    return result;
  }

  toBuf(value: unknown): Buffer {
    const val0 = value as bigint | number;
    let v = typeof val0 === 'number' ? BigInt(val0) : val0;
    const rv: number[] = [];
    for (let i = 0; i < this.size; i++) {
      rv.push(Number(v % 256n));
      v = v / 256n;
    }
    if (v !== 0n) {
      throw new Error(`${val0} is too big. Max size: ${this.size}`);
    }
    rv.reverse();
    return Buffer.from(rv);
  }
}

export class TLVContainer {
  private builders: Map<number, ValueBuilder>;
  private defaultBuilder: ValueBuilder;
  private elems: [number, Buffer][] = [];
  private descs: Map<number, string>;
  private _parent: unknown = null;

  constructor(
    builders: Record<number, ValueBuilder>,
    defaultBuilder: ValueBuilder = new ArrayBuilder(),
    descs?: Record<number, string>,
  ) {
    this.builders = new Map(Object.entries(builders).map(([k, v]) => [Number(k), v]));
    this.defaultBuilder = defaultBuilder;
    this.descs = new Map(Object.entries(descs ?? {}).map(([k, v]) => [Number(k), v]));
  }

  builder(kind: number): ValueBuilder {
    return this.builders.get(kind) ?? this.defaultBuilder;
  }

  fromBuf(buf: Buffer): this {
    let i = 0;
    while (i < buf.length) {
      const kind = buf.readUInt16BE(i);
      const length = buf.readUInt16BE(i + 2);
      i += 4;
      const value = Buffer.from(buf.subarray(i, i + length));
      this.elems.push([kind, value]);
      i += length;
    }
    return this;
  }

  append(kind: number, value: unknown): void {
    const buf = this.builder(kind).toBuf(value);
    this.elems.push([kind, buf]);
  }

  *[Symbol.iterator](): Generator<[number, unknown]> {
    for (const [k, v] of this.elems) {
      yield [k, this.builder(k).fromBuf(v)];
    }
  }

  all(kind: number): unknown[] {
    const result: unknown[] = [];
    for (const [k, v] of this) {
      if (k === kind) result.push(v);
    }
    return result;
  }

  has(kind: number): boolean {
    return this.all(kind).length > 0;
  }

  first(kind: number): unknown {
    return this.all(kind)[0];
  }

  toBuf(): Buffer {
    const parts: Buffer[] = [];
    for (const [k, v] of this.elems) {
      const kBuf = Buffer.alloc(2);
      kBuf.writeUInt16BE(k);
      const lBuf = Buffer.alloc(2);
      lBuf.writeUInt16BE(v.length);
      parts.push(kBuf, lBuf, v);
    }
    return Buffer.concat(parts);
  }

  getPacket(): Buffer {
    return this.toBuf();
  }

  setParent(parent: unknown): void {
    this._parent = parent;
  }

  parent(): unknown {
    return this._parent;
  }

  child(): null {
    return null;
  }

  toString(): string {
    const desc = (kind: number): string | number => this.descs.get(kind) ?? kind;
    const items: string[] = [];
    for (const [k, v] of this) {
      items.push(`[${String(desc(k))}, ${String(v)}]`);
    }
    return `<TLVContainer ${items.join(', ')}>`;
  }
}

export class SCElem {
  static AP_CHANNEL = 0x1001;
  static ASSOCIATION_STATE = 0x1002;
  static AUTHENTICATION_TYPE = 0x1003;
  static AUTHENTICATION_TYPE_FLAGS = 0x1004;
  static AUTHENTICATOR = 0x1005;
  static CONFIG_METHODS = 0x1008;
  static CONFIGURATION_ERROR = 0x1009;
  static CONFIRMATION_URL4 = 0x100a;
  static CONFIRMATION_URL6 = 0x100b;
  static CONNECTION_TYPE = 0x100c;
  static CONNECTION_TYPE_FLAGS = 0x100d;
  static CREDENTIAL = 0x100e;
  static DEVICE_NAME = 0x1011;
  static DEVICE_PASSWORD_ID = 0x1012;
  static E_HASH1 = 0x1014;
  static E_HASH2 = 0x1015;
  static E_SNONCE1 = 0x1016;
  static E_SNONCE2 = 0x1017;
  static ENCRYPTED_SETTINGS = 0x1018;
  static ENCRYPTION_TYPE = 0x100f;
  static ENCRYPTION_TYPE_FLAGS = 0x1010;
  static ENROLLEE_NONCE = 0x101a;
  static FEATURE_ID = 0x101b;
  static IDENTITY = 0x101c;
  static INDENTITY_PROOF = 0x101d;
  static KEY_WRAP_AUTHENTICATOR = 0x101e;
  static KEY_IDENTIFIER = 0x101f;
  static MAC_ADDRESS = 0x1020;
  static MANUFACTURER = 0x1021;
  static MESSAGE_TYPE = 0x1022;
  static MODEL_NAME = 0x1023;
  static MODEL_NUMBER = 0x1024;
  static NETWORK_INDEX = 0x1026;
  static NETWORK_KEY = 0x1027;
  static NETWORK_KEY_INDEX = 0x1028;
  static NEW_DEVICE_NAME = 0x1029;
  static NEW_PASSWORD = 0x102a;
  static OOB_DEVICE_PASSWORD = 0x102c;
  static OS_VERSION = 0x102d;
  static POWER_LEVEL = 0x102f;
  static PSK_CURRENT = 0x1030;
  static PSK_MAX = 0x1031;
  static PUBLIC_KEY = 0x1032;
  static RADIO_ENABLED = 0x1033;
  static REBOOT = 0x1034;
  static REGISTRAR_CURRENT = 0x1035;
  static REGISTRAR_ESTABLISHED = 0x1036;
  static REGISTRAR_LIST = 0x1037;
  static REGISTRAR_MAX = 0x1038;
  static REGISTRAR_NONCE = 0x1039;
  static REQUEST_TYPE = 0x103a;
  static RESPONSE_TYPE = 0x103b;
  static RF_BANDS = 0x103c;
  static R_HASH1 = 0x103d;
  static R_HASH2 = 0x103e;
  static R_SNONCE1 = 0x103f;
  static R_SNONCE2 = 0x1040;
  static SELECTED_REGISTRAR = 0x1041;
  static SERIAL_NUMBER = 0x1042;
  static WPS_STATE = 0x1044;
  static SSID = 0x1045;
  static TOTAL_NETWORKS = 0x1046;
  static UUID_E = 0x1047;
  static UUID_R = 0x1048;
  static VENDOR_EXTENSION = 0x1049;
  static VERSION = 0x104a;
  static X_509_CERTIFICATE_REQUEST = 0x104b;
  static X_509_CERTIFICATE = 0x104c;
  static EAP_IDENTITY = 0x104d;
  static MESSAGE_COUNTER = 0x104e;
  static PUBLIC_KEY_HASH = 0x104f;
  static REKEY_KEY = 0x1050;
  static KEY_LIFETIME = 0x1051;
  static PERMITTED_CONFIG_METHODS = 0x1052;
  static SELECTED_REGISTRAR_CONFIG_METHODS = 0x1053;
  static PRIMARY_DEVICE_TYPE = 0x1054;
  static SECONDARY_DEVICE_TYPE_LIST = 0x1055;
  static PORTABLE_DEVICE = 0x1056;
  static AP_SETUP_LOCKED = 0x1057;
  static APPLICATION_EXTENSION = 0x1058;
  static EAP_TYPE = 0x1059;
  static INITIALIZATION_VECTOR = 0x1060;
  static KEY_PROVIDED_AUTOMATICALLY = 0x1061;
  static _802_1X_ENABLED = 0x1062;
  static APP_SESSION_KEY = 0x1063;
  static WEP_TRANSMIT_KEY = 0x1064;
}

export class MessageType {
  static BEACON = 0x01;
  static PROBE_REQUEST = 0x02;
  static PROBE_RESPONSE = 0x03;
  static M1 = 0x04;
  static M2 = 0x05;
  static M2D = 0x06;
  static M3 = 0x07;
  static M4 = 0x08;
  static M5 = 0x09;
  static M6 = 0x0a;
  static M7 = 0x0b;
  static M8 = 0x0c;
  static WSC_ACK = 0x0d;
  static WSC_NACK = 0x0e;
  static WSC_DONE = 0x0f;
}

export class AuthTypeFlag {
  static OPEN = 0x0001;
  static WPAPSK = 0x0002;
  static SHARED = 0x0004;
  static WPA = 0x0008;
  static WPA2 = 0x0010;
  static WPA2PSK = 0x0020;
}

export const AuthTypeFlag_ALL =
  AuthTypeFlag.OPEN |
  AuthTypeFlag.WPAPSK |
  AuthTypeFlag.SHARED |
  AuthTypeFlag.WPA |
  AuthTypeFlag.WPA2 |
  AuthTypeFlag.WPA2PSK;

export class EncryptionTypeFlag {
  static NONE = 0x0001;
  static WEP = 0x0002;
  static TKIP = 0x0004;
  static AES = 0x0008;
}

export const EncryptionTypeFlag_ALL =
  EncryptionTypeFlag.NONE |
  EncryptionTypeFlag.WEP |
  EncryptionTypeFlag.TKIP |
  EncryptionTypeFlag.AES;

export class ConnectionTypeFlag {
  static ESS = 0x01;
  static IBSS = 0x02;
}

export class ConfigMethod {
  static USBA = 0x0001;
  static ETHERNET = 0x0002;
  static LABEL = 0x0004;
  static DISPLAY = 0x0008;
  static EXT_NFC_TOKEN = 0x0010;
  static INT_NFC_TOKEN = 0x0020;
  static NFC_INTERFACE = 0x0040;
  static PUSHBUTTON = 0x0080;
  static KEYPAD = 0x0100;
}

export class OpCode {
  static WSC_START = 0x01;
  static WSC_ACK = 0x02;
  static WSC_NACK = 0x03;
  static WSC_MSG = 0x04;
  static WSC_DONE = 0x05;
  static WSC_FRAG_ACK = 0x06;
}

export class AssocState {
  static NOT_ASSOC = 0;
  static CONN_SUCCESS = 1;
  static CFG_FAILURE = 2;
  static FAILURE = 3;
  static IP_FAILURE = 4;
}

export class ConfigError {
  static NO_ERROR = 0;
  static OOB_IFACE_READ_ERROR = 1;
  static DECRYPTION_CRC_FAILURE = 2;
  static _24_CHAN_NOT_SUPPORTED = 3;
  static _50_CHAN_NOT_SUPPORTED = 4;
  static SIGNAL_TOO_WEAK = 5;
  static NETWORK_AUTH_FAILURE = 6;
  static NETWORK_ASSOC_FAILURE = 7;
  static NO_DHCP_RESPONSE = 8;
  static FAILED_DHCP_CONFIG = 9;
  static IP_ADDR_CONFLICT = 10;
  static NO_CONN_TO_REGISTRAR = 11;
  static MULTIPLE_PBC_DETECTED = 12;
  static ROGUE_SUSPECTED = 13;
  static DEVICE_BUSY = 14;
  static SETUP_LOCKED = 15;
  static MSG_TIMEOUT = 16;
  static REG_SESS_TIMEOUT = 17;
  static DEV_PASSWORD_AUTH_FAILURE = 18;
}

export class DevicePasswordId {
  static DEFAULT = 0x0000;
  static USER_SPECIFIED = 0x0001;
  static MACHINE_SPECIFIED = 0x0002;
  static REKEY = 0x0003;
  static PUSHBUTTON = 0x0004;
  static REGISTRAR_SPECIFIED = 0x0005;
}

export class WpsState {
  static NOT_CONFIGURED = 0x01;
  static CONFIGURED = 0x02;
}

const _scOpCode = new Byte(0);
const _scFlags = new Byte(1);
const _scMoreFragments = new Bit(1, 0);
const _scLengthField = new Bit(1, 1);

export class SimpleConfig extends ProtocolPacket {
  static override headerSize = 2;
  static override tailSize = 0;

  getOpCode(): number { return _scOpCode.getter(this) as number; }
  setOpCode(v: number): void { _scOpCode.setter(this, v); }
  getFlags(): number { return _scFlags.getter(this) as number; }
  setFlags(v: number): void { _scFlags.setter(this, v); }
  getMoreFragments(): boolean { return _scMoreFragments.getter(this) as boolean; }
  setMoreFragments(v = true): void { _scMoreFragments.setter(this, v); }
  getLengthField(): boolean { return _scLengthField.getter(this) as boolean; }
  setLengthField(v = true): void { _scLengthField.setter(this, v); }

  static BUILDERS: Record<number, ValueBuilder> = {
    [SCElem.CONNECTION_TYPE]: new ByteBuilder(),
    [SCElem.CONNECTION_TYPE_FLAGS]: new ByteBuilder(),
    [SCElem.VERSION]: new ByteBuilder(),
    [SCElem.MESSAGE_TYPE]: new ByteBuilder(),
    [SCElem.NETWORK_INDEX]: new ByteBuilder(),
    [SCElem.NETWORK_KEY_INDEX]: new ByteBuilder(),
    [SCElem.POWER_LEVEL]: new ByteBuilder(),
    [SCElem.PSK_CURRENT]: new ByteBuilder(),
    [SCElem.PSK_MAX]: new ByteBuilder(),
    [SCElem.REGISTRAR_CURRENT]: new ByteBuilder(),
    [SCElem.REGISTRAR_MAX]: new ByteBuilder(),
    [SCElem.REQUEST_TYPE]: new ByteBuilder(),
    [SCElem.RESPONSE_TYPE]: new ByteBuilder(),
    [SCElem.RF_BANDS]: new ByteBuilder(),
    [SCElem.WPS_STATE]: new ByteBuilder(),
    [SCElem.TOTAL_NETWORKS]: new ByteBuilder(),
    [SCElem.WEP_TRANSMIT_KEY]: new ByteBuilder(),

    [SCElem.CONFIRMATION_URL4]: new StringBuilder(),
    [SCElem.CONFIRMATION_URL6]: new StringBuilder(),
    [SCElem.DEVICE_NAME]: new StringBuilder(),
    [SCElem.IDENTITY]: new StringBuilder(),
    [SCElem.MANUFACTURER]: new StringBuilder(),
    [SCElem.MODEL_NAME]: new StringBuilder(),
    [SCElem.MODEL_NUMBER]: new StringBuilder(),
    [SCElem.NEW_DEVICE_NAME]: new StringBuilder(),
    [SCElem.NEW_PASSWORD]: new StringBuilder(),
    [SCElem.SERIAL_NUMBER]: new StringBuilder(),
    [SCElem.EAP_IDENTITY]: new StringBuilder(),
    [SCElem.NETWORK_KEY]: new StringBuilder(),

    [SCElem.AP_CHANNEL]: new NumBuilder(2),
    [SCElem.ASSOCIATION_STATE]: new NumBuilder(2),
    [SCElem.AUTHENTICATION_TYPE]: new NumBuilder(2),
    [SCElem.AUTHENTICATION_TYPE_FLAGS]: new NumBuilder(2),
    [SCElem.CONFIG_METHODS]: new NumBuilder(2),
    [SCElem.CONFIGURATION_ERROR]: new NumBuilder(2),
    [SCElem.DEVICE_PASSWORD_ID]: new NumBuilder(2),
    [SCElem.ENCRYPTION_TYPE]: new NumBuilder(2),
    [SCElem.ENCRYPTION_TYPE_FLAGS]: new NumBuilder(2),
    [SCElem.MESSAGE_COUNTER]: new NumBuilder(8),
    [SCElem.KEY_LIFETIME]: new NumBuilder(4),
    [SCElem.PERMITTED_CONFIG_METHODS]: new NumBuilder(2),
    [SCElem.SELECTED_REGISTRAR_CONFIG_METHODS]: new NumBuilder(2),
    [SCElem.PUBLIC_KEY]: new NumBuilder(192),
  };

  static buildTlvContainer(): TLVContainer {
    const descs: Record<number, string> = {};
    for (const [name, val] of Object.entries(SCElem)) {
      if (typeof val === 'number') {
        descs[val] = name;
      }
    }
    return new TLVContainer(SimpleConfig.BUILDERS, new ArrayBuilder(), descs);
  }
}

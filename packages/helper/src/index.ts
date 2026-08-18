import { PacketBuffer, ProtocolPacket as BaseProtocolPacket } from '@impacket/impact';
import { Buffer } from 'node:buffer';

export abstract class Field {
  constructor(public index: number) {}

  abstract getter(o: ProtocolPacket): unknown;
  abstract setter(o: ProtocolPacket, value: unknown): void;
}

export class Bit extends Field {
  private mask: number;
  private offMask: number;

  constructor(index: number, bitNumber: number) {
    super(index);
    this.mask = 2 ** bitNumber;
    this.offMask = ~this.mask & 0xff;
  }

  getter(o: ProtocolPacket): boolean {
    return (o.header.getByte(this.index) & this.mask) !== 0;
  }

  setter(o: ProtocolPacket, value: unknown = true): void {
    let b = o.header.getByte(this.index);
    if (value) {
      b |= this.mask;
    } else {
      b &= this.offMask;
    }
    o.header.setByte(this.index, b);
  }
}

export class Byte extends Field {
  getter(o: ProtocolPacket): number {
    return o.header.getByte(this.index);
  }

  setter(o: ProtocolPacket, value: unknown): void {
    o.header.setByte(this.index, value as number);
  }
}

export class Word extends Field {
  private order: string;

  constructor(index: number, order = '!') {
    super(index);
    this.order = order;
  }

  getter(o: ProtocolPacket): number {
    return o.header.getWord(this.index, this.order);
  }

  setter(o: ProtocolPacket, value: unknown): void {
    o.header.setWord(this.index, value as number, this.order);
  }
}

export class Long extends Field {
  private order: string;

  constructor(index: number, order = '!') {
    super(index);
    this.order = order;
  }

  getter(o: ProtocolPacket): number {
    return o.header.getLong(this.index, this.order);
  }

  setter(o: ProtocolPacket, value: unknown): void {
    o.header.setLong(this.index, value as number, this.order);
  }
}

export class ThreeBytesBigEndian extends Field {
  getter(o: ProtocolPacket): number {
    const bytes = o.header.getBytes().subarray(this.index, this.index + 3);
    const padded = Buffer.concat([Buffer.from([0x00]), bytes]);
    return padded.readUInt32BE(0);
  }

  setter(o: ProtocolPacket, value: unknown): void {
    const mask = (~0xffffff00) & 0xff;
    const masked = o.header.getLong(this.index, '>') & mask;
    const nb = masked | (((value as number) & 0x00ffffff) << 8);
    o.header.setLong(this.index, nb, '>');
  }
}

export class ProtocolPacket extends BaseProtocolPacket {
  static headerSize = 0;
  static tailSize = 0;

  constructor(buff?: Buffer) {
    const ctor = new.target as typeof ProtocolPacket;
    super(ctor.headerSize, ctor.tailSize);
    if (buff) {
      this.loadPacket(buff);
    }
  }

  getField(field: Field): unknown {
    return field.getter(this);
  }

  setField(field: Field, value: unknown): void {
    field.setter(this, value);
  }
}

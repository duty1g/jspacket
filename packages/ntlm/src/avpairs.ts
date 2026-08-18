/** @impacket/ntlm - AV_PAIRS ([MS-NLMP] 2.2.2.1). */

import { Buffer } from 'node:buffer';
import { NTLMSSP_AV_EOL } from './constants.js';

export class AV_PAIRS {
  fields: Map<number, [number, Buffer]> = new Map();

  constructor(data: Buffer | null = null) {
    this.fields = new Map();
    if (data != null) this.fromString(data);
  }

  set(key: number, value: Buffer): void {
    this.fields.set(key, [value.length, value]);
  }

  get(key: number): [number, Buffer] | undefined {
    return this.fields.get(key);
  }

  has(key: number): boolean {
    return this.fields.has(key);
  }

  delete(key: number): void {
    this.fields.delete(key);
  }

  keys(): number[] {
    return [...this.fields.keys()];
  }

  get length(): number {
    return this.getData().length;
  }

  fromString(data: Buffer): void {
    let tInfo = data;
    let fType = 0xff;
    while (fType !== NTLMSSP_AV_EOL) {
      fType = tInfo.readUInt16LE(0);
      tInfo = tInfo.subarray(2);
      const length = tInfo.readUInt16LE(0);
      tInfo = tInfo.subarray(2);
      const content = tInfo.subarray(0, length);
      this.fields.set(fType, [length, content]);
      tInfo = tInfo.subarray(length);
    }
  }

  getData(): Buffer {
    if (this.fields.has(NTLMSSP_AV_EOL)) this.fields.delete(NTLMSSP_AV_EOL);
    let ans = Buffer.alloc(0);
    for (const [i, [len, value]] of this.fields) {
      const hdr = Buffer.alloc(4);
      hdr.writeUInt16LE(i, 0);
      hdr.writeUInt16LE(len, 2);
      ans = Buffer.concat([ans, hdr, value]);
    }
    const eol = Buffer.alloc(4, 0);
    return Buffer.concat([ans, eol]);
  }

  dump(): void {
    for (const [i, [, value]] of this.fields) {
      // eslint-disable-next-line no-console
      console.log(`${i}: {${String(value)}}`);
    }
  }
}

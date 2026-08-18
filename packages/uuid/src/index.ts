/**
 * @impacket/uuid - TypeScript port of impacket/uuid.py
 *
 * UUID generation and conversion. Matches the impacket mixed-endian layout
 * (first three components little-endian, last two big-endian) used by DCE/RPC.
 */

import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';

export const EMPTY_UUID = Buffer.alloc(16, 0);

/** Generate a random 16-byte UUID (binary). */
export function generate(): Buffer {
  const top = 0x7fffffff;
  const r = () => randomBytes(4).readUInt32LE(0) & top;
  const buf = Buffer.alloc(16);
  buf.writeUInt32LE(r(), 0);
  buf.writeUInt32LE(r(), 4);
  buf.writeUInt32LE(r(), 8);
  buf.writeUInt32LE(r(), 12);
  return buf;
}

/** Binary UUID -> canonical string form (mixed-endian, uppercase). */
export function binToString(uuid: Buffer): string {
  const uuid1 = uuid.readUInt32LE(0);
  const uuid2 = uuid.readUInt16LE(4);
  const uuid3 = uuid.readUInt16LE(6);
  const uuid4 = uuid.readUInt16BE(8);
  const uuid5 = uuid.readUInt16BE(10);
  const uuid6 = uuid.readUInt32BE(12);
  return (
    `${uuid1.toString(16).padStart(8, '0').toUpperCase()}-` +
    `${uuid2.toString(16).padStart(4, '0').toUpperCase()}-` +
    `${uuid3.toString(16).padStart(4, '0').toUpperCase()}-` +
    `${uuid4.toString(16).padStart(4, '0').toUpperCase()}-` +
    `${uuid5.toString(16).padStart(4, '0').toUpperCase()}` +
    `${uuid6.toString(16).padStart(8, '0').toUpperCase()}`
  );
}

/** Canonical string form -> binary UUID. Accepts dashed or 32-hex forms. */
export function stringToBin(uuid: string): Buffer {
  if (!uuid.includes('-')) return Buffer.from(uuid, 'hex');
  const m =
    /^([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})$/.exec(
      uuid,
    );
  if (!m) throw new Error(`Invalid UUID string: ${uuid}`);
  const [, u1, u2, u3, u4, u5, u6] = m;
  const out = Buffer.alloc(16);
  out.writeUInt32LE(parseInt(u1!, 16), 0);
  out.writeUInt16LE(parseInt(u2!, 16), 4);
  out.writeUInt16LE(parseInt(u3!, 16), 6);
  out.writeUInt16BE(parseInt(u4!, 16), 8);
  out.writeUInt16BE(parseInt(u5!, 16), 10);
  out.writeUInt32BE(parseInt(u6!, 16), 12);
  return out;
}

/** "maj.min" -> 4-byte LE buffer (version part of an interface UUID tuple). */
export function stringverToBin(s: string): Buffer {
  const [maj, min] = s.split('.');
  const buf = Buffer.alloc(4);
  buf.writeUInt16LE(parseInt(maj!, 10) || 0, 0);
  buf.writeUInt16LE(parseInt(min!, 10) || 0, 2);
  return buf;
}

/** (uuidString, versionString) -> 20-byte buffer. */
export function uuidtupToBin(tup: [string, string]): Buffer | undefined {
  if (tup.length !== 2) return undefined;
  return Buffer.concat([stringToBin(tup[0]), stringverToBin(tup[1])]);
}

/** 20-byte buffer -> (uuidString, versionString). */
export function binToUuidtup(bin: Buffer): [string, string] {
  if (bin.length !== 20) throw new Error(`Expected 20 bytes, got ${bin.length}`);
  const uuidstr = binToString(bin.subarray(0, 16));
  const maj = bin.readUInt16LE(16);
  const min = bin.readUInt16LE(18);
  return [uuidstr, `${maj}.${min}`];
}

/** Parse a textual "uuid version x.y" form, defaulting to "1.0". */
export function stringToUuidtup(s: string): [string, string] | undefined {
  const g =
    /([A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}).*?([0-9]{1,5}\.[0-9]{1,5})/.exec(
      `${s} 1.0`,
    );
  if (g) return [g[1]!, g[2]!];
  return undefined;
}

/** (uuidString, [maj, min]) -> "uuid vMaj.Min" string. */
export function uuidtupToString(tup: [string, [number, number]]): string {
  return `${tup[0]} v${tup[1][0]}.${tup[1][1]}`;
}

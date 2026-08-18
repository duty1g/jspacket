import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  NETBIOS_SESSION_KEEP_ALIVE,
  NETBIOS_SESSION_MESSAGE,
  NETBIOS_SESSION_REQUEST,
  NetBIOSError,
  NetBIOSSessionPacket,
  TYPE_SERVER,
  TYPE_WORKSTATION,
  decode_name,
  encode_name,
} from '../src/index.js';

describe('encode_name / decode_name', () => {
  it('encodes a simple name with type', () => {
    const encoded = encode_name('WORKSTATION', TYPE_WORKSTATION, '');
    expect(encoded[0]).toBe(32);
    expect(encoded.length).toBe(34);
    expect(encoded[33]).toBe(0);
  });

  it('encodes wildcard name (*)', () => {
    const encoded = encode_name('*', 0, '');
    expect(encoded[0]).toBe(32);
    expect(encoded[1]).toBe('C'.charCodeAt(0));
    expect(encoded[2]).toBe('K'.charCodeAt(0));
  });

  it('encodes with scope', () => {
    const encoded = encode_name('SERVER', TYPE_SERVER, 'scope.dom');
    expect(encoded[0]).toBe(32);
    const scopePart = encoded.subarray(33);
    expect(scopePart[0]).toBe(5);
    expect(scopePart.toString('utf8', 1, 6)).toBe('scope');
  });

  it('round-trips encode -> decode', () => {
    const encoded = encode_name('SERVER', TYPE_SERVER, '');
    const [offset, name, scope] = decode_name(encoded);
    expect(offset).toBe(34);
    expect(name.charCodeAt(15)).toBe(TYPE_SERVER);
    expect(name.slice(0, 6)).toBe('SERVER');
    expect(scope).toBe('');
  });

  it('round-trips with scope', () => {
    const encoded = encode_name('SERVER', TYPE_SERVER, 'dom');
    const [_offset, _name, scope] = decode_name(encoded);
    expect(scope).toBe('.dom');
  });
});

describe('NetBIOSSessionPacket', () => {
  it('parses a MESSAGE packet', () => {
    const data = Buffer.alloc(8);
    data[0] = NETBIOS_SESSION_MESSAGE;
    data[1] = 0;
    data.writeUInt16BE(4, 2);
    Buffer.from('test').copy(data, 4);

    const pkt = new NetBIOSSessionPacket(data);
    expect(pkt.get_type()).toBe(NETBIOS_SESSION_MESSAGE);
    expect(pkt.get_length()).toBe(4);
    expect(pkt.get_trailer().toString('utf8')).toBe('test');
  });

  it('parses a MESSAGE packet with > 64KB length', () => {
    const data = Buffer.alloc(4);
    data[0] = NETBIOS_SESSION_MESSAGE;
    data[1] = 0x01;
    data.writeUInt16BE(0x0000, 2);

    const pkt = new NetBIOSSessionPacket(data);
    expect(pkt.get_type()).toBe(NETBIOS_SESSION_MESSAGE);
    expect(pkt.get_length()).toBe(0x10000);
  });

  it('parses a REQUEST packet', () => {
    const data = Buffer.alloc(6);
    data[0] = NETBIOS_SESSION_REQUEST;
    data[1] = 0;
    data.writeUInt16BE(2, 2);
    data[4] = 0x41;
    data[5] = 0x42;

    const pkt = new NetBIOSSessionPacket(data);
    expect(pkt.get_type()).toBe(NETBIOS_SESSION_REQUEST);
    expect(pkt.get_length()).toBe(2);
  });

  it('builds and round-trips a MESSAGE packet', () => {
    const pkt = new NetBIOSSessionPacket();
    pkt.set_type(NETBIOS_SESSION_MESSAGE);
    pkt.set_trailer(Buffer.from('hello world', 'utf8'));
    const raw = pkt.rawData();
    expect(raw[0]).toBe(NETBIOS_SESSION_MESSAGE);
    expect(raw.readUInt16BE(2)).toBe(11);

    const parsed = new NetBIOSSessionPacket(raw);
    expect(parsed.get_type()).toBe(NETBIOS_SESSION_MESSAGE);
    expect(parsed.get_trailer().toString('utf8')).toBe('hello world');
  });

  it('builds and round-trips a KEEP_ALIVE packet', () => {
    const pkt = new NetBIOSSessionPacket();
    pkt.set_type(NETBIOS_SESSION_KEEP_ALIVE);
    const raw = pkt.rawData();
    expect(raw[0]).toBe(NETBIOS_SESSION_KEEP_ALIVE);
    const parsed = new NetBIOSSessionPacket(raw);
    expect(parsed.get_type()).toBe(NETBIOS_SESSION_KEEP_ALIVE);
  });

  it('handles large message (> 64KB)', () => {
    const payload = Buffer.alloc(70000, 0x41);
    const pkt = new NetBIOSSessionPacket();
    pkt.set_type(NETBIOS_SESSION_MESSAGE);
    pkt.set_trailer(payload);
    const raw = pkt.rawData();
    expect(raw[0]).toBe(NETBIOS_SESSION_MESSAGE);
    expect(raw[1]).toBe(Math.floor(payload.length / 65536));
    expect(raw.readUInt16BE(2)).toBe(payload.length & 0xffff);

    const parsed = new NetBIOSSessionPacket(raw);
    expect(parsed.get_type()).toBe(NETBIOS_SESSION_MESSAGE);
    expect(parsed.get_length()).toBe(payload.length);
  });
});

describe('NetBIOSError', () => {
  it('stores error message and class', () => {
    const err = new NetBIOSError('test error', 0xf0, 0x80);
    expect(err.error_msg).toBe('test error');
    expect(err.get_error_class()).toBe(0xf0);
    expect(err.get_error_code()).toBe(0x80);
  });

  it('toString produces readable output', () => {
    const err = new NetBIOSError('connection failed');
    expect(err.toString()).toContain('connection failed');
  });
});

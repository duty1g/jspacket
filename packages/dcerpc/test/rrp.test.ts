import { describe, it, expect } from 'vitest';
import { Buffer } from 'node:buffer';
import {
  RPC_HKEY,
  RVALENT,
  RPC_SECURITY_DESCRIPTOR,
  RPC_SECURITY_ATTRIBUTES,
  OpenClassesRoot,
  BaseRegCloseKey,
  BaseRegOpenKey,
  BaseRegQueryInfoKey,
  BaseRegQueryValue,
  BaseRegEnumKey,
  BaseRegEnumValue,
  BaseRegCreateKey,
  BaseRegDeleteKey,
  BaseRegSetValue,
  BaseRegGetVersion,
  BaseRegDeleteKeyEx,
  MSRPC_UUID_RRP,
  RRP_OPNUMS,
  KEY_READ,
  REG_SZ,
  REG_DWORD,
  rrpCheckNullString,
  packValue,
  unpackValue,
} from '../src/rrp';

describe('rrp', () => {
  it('MSRPC_UUID_RRP is 20 bytes', () => {
    expect(MSRPC_UUID_RRP.length).toBe(20);
  });

  it('RRP_OPNUMS has 31 entries', () => {
    expect(Object.keys(RRP_OPNUMS).length).toBe(31);
  });

  it('RPC_HKEY is null by default', () => {
    const h = new RPC_HKEY();
    expect(h.isNull()).toBe(true);
  });

  it('RPC_HKEY is not null after set', () => {
    const h = new RPC_HKEY();
    h.set('context_handle_uuid', Buffer.alloc(16, 0x42));
    expect(h.isNull()).toBe(false);
  });

  it('OpenClassesRoot produces non-empty data', () => {
    const req = new OpenClassesRoot();
    req.set('samDesired', KEY_READ);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('BaseRegCloseKey produces non-empty data', () => {
    const hKey = new RPC_HKEY();
    hKey.set('context_handle_uuid', Buffer.alloc(16, 0x41));
    const req = new BaseRegCloseKey();
    req.set('hKey', hKey);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('BaseRegOpenKey produces non-empty data', () => {
    const hKey = new RPC_HKEY();
    hKey.set('context_handle_uuid', Buffer.alloc(16, 0x42));
    const req = new BaseRegOpenKey();
    req.set('hKey', hKey);
    req.set('lpSubKey', rrpCheckNullString('SECURITY'));
    req.set('dwOptions', 0x00000001);
    req.set('samDesired', KEY_READ);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('BaseRegQueryInfoKey produces non-empty data', () => {
    const hKey = new RPC_HKEY();
    hKey.set('context_handle_uuid', Buffer.alloc(16, 0x43));
    const req = new BaseRegQueryInfoKey();
    req.set('hKey', hKey);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('BaseRegQueryValue produces non-empty data', () => {
    const hKey = new RPC_HKEY();
    hKey.set('context_handle_uuid', Buffer.alloc(16, 0x44));
    const req = new BaseRegQueryValue();
    req.set('hKey', hKey);
    req.set('lpValueName', rrpCheckNullString('DefaultPassword'));
    req.set('lpData', Buffer.alloc(512, 0x20));
    req.set('lpcbData', 512);
    req.set('lpcbLen', 512);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('BaseRegCreateKey produces non-empty data', () => {
    const hKey = new RPC_HKEY();
    hKey.set('context_handle_uuid', Buffer.alloc(16, 0x45));
    const req = new BaseRegCreateKey();
    req.set('hKey', hKey);
    req.set('lpSubKey', rrpCheckNullString('TestKey'));
    req.set('lpClass', rrpCheckNullString('TestClass'));
    req.set('dwOptions', 0x00000001);
    req.set('samDesired', KEY_READ);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('BaseRegSetValue produces non-empty data', () => {
    const hKey = new RPC_HKEY();
    hKey.set('context_handle_uuid', Buffer.alloc(16, 0x46));
    const req = new BaseRegSetValue();
    req.set('hKey', hKey);
    req.set('lpValueName', rrpCheckNullString('TestValue'));
    req.set('dwType', REG_SZ);
    const packed = packValue(REG_SZ, 'test');
    req.set('lpData', Array.from(packed));
    req.set('cbData', packed.length);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('BaseRegGetVersion produces non-empty data', () => {
    const hKey = new RPC_HKEY();
    hKey.set('context_handle_uuid', Buffer.alloc(16, 0x47));
    const req = new BaseRegGetVersion();
    req.set('hKey', hKey);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('BaseRegDeleteKeyEx produces non-empty data', () => {
    const hKey = new RPC_HKEY();
    hKey.set('context_handle_uuid', Buffer.alloc(16, 0x48));
    const req = new BaseRegDeleteKeyEx();
    req.set('hKey', hKey);
    req.set('lpSubKey', rrpCheckNullString('TestKey'));
    req.set('AccessMask', KEY_READ);
    req.set('Reserved', 0);
    const data = req.getData();
    expect(data.length).toBeGreaterThan(0);
  });

  it('rrpCheckNullString appends null terminator', () => {
    expect(rrpCheckNullString('test')).toBe('test\x00');
    expect(rrpCheckNullString('test\x00')).toBe('test\x00');
  });

  it('packValue REG_DWORD', () => {
    const buf = packValue(REG_DWORD, 0x12345678);
    expect(buf.length).toBe(4);
    expect(buf.readUInt32LE(0)).toBe(0x12345678);
  });

  it('packValue REG_SZ', () => {
    const buf = packValue(REG_SZ, 'test');
    expect(buf.toString('utf16le').replace(/\x00$/, '')).toBe('test');
  });

  it('unpackValue REG_DWORD', () => {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(0x12345678, 0);
    const val = unpackValue(REG_DWORD, buf) as number;
    expect(val).toBe(0x12345678);
  });

  it('unpackValue REG_SZ', () => {
    const buf = Buffer.from('test\x00', 'utf16le');
    const val = unpackValue(REG_SZ, buf) as string;
    expect(val).toContain('test');
  });
});
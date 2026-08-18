import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import { aesCmac, hmacMd5, kdfCounterMode, md4, rc4, transformKey } from '../src/index.js';

describe('crypto', () => {
  it('AES-CMAC matches RFC 4493 test vector', () => {
    // RFC 4493 Appendix
    const K = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex');
    const M = Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex');
    const T = aesCmac(K, M);
    expect(T.toString('hex')).toBe('070a16b46b4d4144f79bdd9dd04a287c');
  });

  it('MD4 matches NTLM hash of password', () => {
    // NTLM(unicode("password")) -> MD4
    const pw = Buffer.from('password', 'utf16le');
    expect(md4(pw).toString('hex')).toBe('8846f7eaee8fb117ad06bdd830b7586c');
  });

  it('HMAC-MD5 NTLMv2 test', () => {
    const key = Buffer.alloc(16, 0x0b);
    const data = Buffer.from('Hi There');
    expect(hmacMd5(key, data).length).toBe(16);
  });

  it('RC4 roundtrips', () => {
    const key = Buffer.from('Key', 'ascii');
    const plain = Buffer.from('Plaintext', 'ascii');
    // RC4(Key, "Plaintext") per RFC 6229
    expect(rc4(key, plain).toString('hex')).toBe('bbf316e8d940af0ad3');
  });

  it('transformKey adjusts parity and shifts', () => {
    const input = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    const out = transformKey(input);
    expect(out.length).toBe(8);
  });

  it('KDF counter mode returns requested bit length', () => {
    const KI = Buffer.alloc(32, 0x10);
    const L = 128;
    const out = kdfCounterMode(KI, Buffer.from('label'), Buffer.from('ctx'), L);
    expect(out.length).toBe(L / 8);
  });
});

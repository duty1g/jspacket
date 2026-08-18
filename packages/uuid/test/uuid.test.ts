import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import { binToString, generate, stringToBin } from '../src/index.js';

describe('uuid', () => {
  it('round-trips a known UUID', () => {
    const known = '12345678-1234-1234-1234-123456789abc';
    const bin = stringToBin(known);
    expect(bin.length).toBe(16);
    expect(binToString(bin).toLowerCase()).toBe(known);
  });

  it('generates 16-byte UUIDs', () => {
    const u = generate();
    expect(u.length).toBe(16);
  });
});

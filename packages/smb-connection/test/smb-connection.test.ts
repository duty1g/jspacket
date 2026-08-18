import { describe, expect, it } from 'vitest';
import { SMBConnection, SessionError } from '../src/index.js';

describe('SessionError', () => {
  it('can be constructed', () => {
    const err = new SessionError(0xc000006d);
    expect(err.getErrorCode()).toBe(0xc000006d);
    expect(err.message).toContain('c000006d');
  });

  it('stores packet', () => {
    const packet = { foo: 1 };
    const err = new SessionError(0x01, packet);
    expect(err.getErrorPacket()).toBe(packet);
  });
});

describe('SMBConnection', () => {
  it('SessionError is a subclass of Error', () => {
    const err = new SessionError();
    expect(err).toBeInstanceOf(Error);
  });

  it('SMBConnection class can be referenced', () => {
    expect(SMBConnection).toBeDefined();
  });
});

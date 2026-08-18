import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import { Structure, hexdump } from '../src/index.js';

describe('Structure basics', () => {
  it('packs and unpacks a simple struct', () => {
    class Foo extends Structure {
      static commonHdr: [string, string][] = [
        ['A', '<L'],
        ['B', '<H'],
      ];
    }
    const f = new Foo();
    f.set('A', 0x01020304);
    f.set('B', 0x0a0b);
    const data = f.getData();
    expect(data.toString('hex')).toBe('040302010b0a');
    const back = new Foo(data);
    expect(back.get('A')).toBe(0x01020304);
    expect(back.get('B')).toBe(0x0a0b);
  });

  it('handles asciiz (z) and unicode (u) fields', () => {
    class Bar extends Structure {
      static structure: [string, string][] = [
        ['Name', 'z'],
        ['Name2', 'u'],
      ];
    }
    const b = new Bar();
    b.set('Name', 'hi');
    b.set('Name2', Buffer.from('hi', 'latin1'));
    const data = b.getData();
    // 'z' -> "hi\x00" (3 bytes); 'u' -> "hi\x00\x00" (4 bytes)
    expect(data.toString('hex')).toBe('686900' + '68690000');
    const back = new Bar(data);
    expect(back.get('Name')).toBe('hi');
  });

  it('handles NDR conformant string (w)', () => {
    class W extends Structure {
      static structure: [string, string][] = [['S', 'w']];
    }
    const w = new W();
    w.set('S', Buffer.from('AB', 'latin1'));
    const data = w.getData();
    // length=1 (LE), length=1, max=0, off=0, 'AB'
    expect(data.toString('hex')).toBe('0100000001000000000000004142');
  });

  it('hexdump produces output', () => {
    const out = hexdump(Buffer.from([0x41, 0x42, 0x43, 0x44]));
    expect(out).toContain('41');
  });
});

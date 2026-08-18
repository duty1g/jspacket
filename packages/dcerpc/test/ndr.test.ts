import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  NDR,
  NDRSMALL,
  NDRUSMALL,
  NDRSHORT,
  NDRUSHORT,
  NDRLONG,
  NDRULONG,
  NDRHYPER,
  NDRUHYPER,
  NDRUniFixedArray,
  NDRUniConformantArray,
  NDRUniVaryingArray,
  NDRUniConformantVaryingArray,
  NDRSTRUCT,
  NDRPOINTER,
  NDRPOINTERNULL,
  NDRUNION,
  NDRCALL,
  NULL,
  type NDRField,
} from '../src/ndr';

describe('NDR Primitives', () => {
  it('packs and unpacks NDRULONG', () => {
    const v = new NDRULONG();
    v.set('Data', 0x12345678);
    const data = v.getData();
    expect(data.readUInt32LE(0)).toBe(0x12345678);
    expect(data.length).toBe(4);

    const parsed = new NDRULONG(data);
    expect(parsed.get('Data')).toBe(0x12345678);
  });

  it('packs and unpacks NDRUSHORT', () => {
    const v = new NDRUSHORT();
    v.set('Data', 0xabcd);
    const data = v.getData();
    expect(data.readUInt16LE(0)).toBe(0xabcd);
    const parsed = new NDRUSHORT(data);
    expect(parsed.get('Data')).toBe(0xabcd);
  });

  it('packs and unpacks NDRHYPER', () => {
    const v = new NDRHYPER();
    v.set('Data', 0x123456789abcdef0n);
    const data = v.getData();
    expect(data.readBigInt64LE(0)).toBe(0x123456789abcdef0n);
    const parsed = new NDRHYPER(data);
    expect(parsed.get('Data')).toBe(0x123456789abcdef0n);
  });

  it('packs and unpacks NDRSMALL', () => {
    const v = new NDRSMALL();
    v.set('Data', -42);
    const data = v.getData();
    expect(data.readInt8(0)).toBe(-42);
    const parsed = new NDRSMALL(data);
    expect(parsed.get('Data')).toBe(-42);
  });
});

describe('NDR Structures', () => {
  it('round-trips a simple NDRSTRUCT', () => {
    class TestStruct extends NDRSTRUCT {
      static structure: NDRField[] = [
        ['Field1', NDRULONG],
        ['Field2', NDRUSHORT],
      ];
    }

    const s = new TestStruct();
    s.set('Field1', 100);
    s.set('Field2', 200);

    const data = s.getData();
    expect(data.length).toBe(6);

    const parsed = new TestStruct(data);
    expect(parsed.get('Field1')).toBe(100);
    expect(parsed.get('Field2')).toBe(200);
  });

  it('aligns fields to 4 bytes', () => {
    class TestStruct extends NDRSTRUCT {
      static structure: NDRField[] = [
        ['Short', NDRUSHORT],
        ['Long', NDRULONG],
      ];
    }

    const s = new TestStruct();
    s.set('Short', 1);
    s.set('Long', 2);

    const data = s.getData();
    expect(data.length).toBe(8);
    expect(data.readUInt16LE(0)).toBe(1);
    expect(data.readUInt32LE(4)).toBe(2);

    const parsed = new TestStruct(data);
    expect(parsed.get('Short')).toBe(1);
    expect(parsed.get('Long')).toBe(2);
  });
});

describe('NDR Pointers', () => {
  it('packs a null pointer as 4 zero bytes', () => {
    class PULONG extends NDRPOINTER {
      static referent: NDRField[] = [['Data', NDRULONG]];
    }

    const p = new PULONG();
    p.set('ReferentID', 0);
    const data = p.getData();
    expect(data.length).toBe(4);
    expect(data.equals(Buffer.alloc(4))).toBe(true);
  });

  it('round-trips a non-null pointer', () => {
    class PULONG extends NDRPOINTER {
      static referent: NDRField[] = [['Data', NDRULONG]];
    }

    const p = new PULONG();
    p.fields['ReferentID'] = 0x1234;
    p.set('Data', 42);

    const data = Buffer.concat([p.getData(), p.getDataReferent()]);
    expect(data.readUInt32LE(0)).toBe(0x1234);
    expect(data.readUInt32LE(4)).toBe(42);

    const parsed = new PULONG(data);
    expect(parsed.get('ReferentID')).toBe(0x1234);
    parsed.fromStringReferent(data, 4);
    expect(parsed.get('Data')).toBe(42);
  });

  it('NULL constant serializes as zero', () => {
    expect(NULL instanceof NDRPOINTERNULL).toBe(true);
    const data = NULL.getData();
    expect(data.length).toBe(4);
    expect(data.equals(Buffer.alloc(4))).toBe(true);
  });
});

describe('NDR Conformant Arrays', () => {
  it('round-trips a conformant array of ULONGs', () => {
    class ULONGArray extends NDRUniConformantArray {
      static item = NDRULONG;
    }

    const arr = new ULONGArray();
    const items = [new NDRULONG(), new NDRULONG(), new NDRULONG()];
    items[0]!.set('Data', 10);
    items[1]!.set('Data', 20);
    items[2]!.set('Data', 30);
    arr.fields['Data'] = items;

    const data = arr.getData();
    expect(data.length).toBe(12);

    const parsed = new ULONGArray();
    parsed.setArraySize(3);
    parsed.fromString(data);

    const parsedItems = parsed.fields['Data'] as NDR[];
    expect(parsedItems.length).toBe(3);
    expect(parsedItems[0]!.get('Data')).toBe(10);
    expect(parsedItems[1]!.get('Data')).toBe(20);
    expect(parsedItems[2]!.get('Data')).toBe(30);
  });

  it('round-trips a conformant byte array', () => {
    class ByteArray extends NDRUniConformantArray {
      static item = 'B';
    }

    const arr = new ByteArray();
    arr.fields['Data'] = [1, 2, 3, 4, 5];

    const data = arr.getData();
    expect(data.length).toBe(5);

    const parsed = new ByteArray();
    parsed.setArraySize(5);
    parsed.fromString(data);
    const items = parsed.fields['Data'] as number[];
    expect(items.length).toBe(5);
    expect(items[0]).toBe(1);
    expect(items[4]).toBe(5);
  });
});

describe('NDR Unions', () => {
  it('round-trips a union with tag selection', () => {
    class TestUnion extends NDRUNION {
      static union = {
        1: ['Arm1', NDRULONG] as NDRField,
        2: ['Arm2', NDRUSHORT] as NDRField,
      };
    }

    const u = new TestUnion();
    u.set('tag', 1);
    u.set('Arm1', 0xdeadbeef);

    const data = u.getData();
    const parsed = new TestUnion(data);
    expect(parsed.get('Arm1')).toBe(0xdeadbeef);

    const u2 = new TestUnion();
    u2.set('tag', 2);
    u2.set('Arm2', 0xabcd);

    const data2 = u2.getData();
    const parsed2 = new TestUnion(data2);
    expect(parsed2.get('Arm2')).toBe(0xabcd);
  });
});

describe('NDRCALL', () => {
  it('round-trips a top-level call with pointer', () => {
    class PULONG extends NDRPOINTER {
      static referent: NDRField[] = [['Data', NDRULONG]];
    }

    class TestCall extends NDRCALL {
      static structure: NDRField[] = [
        ['Value', NDRULONG],
        ['Ptr', PULONG],
      ];
    }

    const call = new TestCall();
    call.set('Value', 100);
    const ptr = call.fields['Ptr'] as PULONG;
    ptr.set('Data', 200);

    const data = call.getData();
    expect(data.readUInt32LE(0)).toBe(100);
    expect(data.readUInt32LE(4)).toBe(ptr.fields['ReferentID']);
    expect(data.readUInt32LE(8)).toBe(200);

    const parsed = new TestCall(data);
    expect(parsed.get('Value')).toBe(100);
    const parsedPtr = parsed.fields['Ptr'] as PULONG;
    expect(parsedPtr.get('Data')).toBe(200);
  });

  it('round-trips a call with null pointer', () => {
    class PULONG extends NDRPOINTER {
      static referent: NDRField[] = [['Data', NDRULONG]];
    }

    class TestCall extends NDRCALL {
      static structure: NDRField[] = [
        ['Value', NDRULONG],
        ['Ptr', PULONG],
      ];
    }

    const call = new TestCall();
    call.set('Value', 42);
    call.set('Ptr', NULL);

    const data = call.getData();
    expect(data.readUInt32LE(0)).toBe(42);
    expect(data.readUInt32LE(4)).toBe(0);

    const parsed = new TestCall(data);
    expect(parsed.get('Value')).toBe(42);
  });

  it('round-trips a call with embedded pointer', () => {
    class PULONG extends NDRPOINTER {
      static referent: NDRField[] = [['Data', NDRULONG]];
    }

    class InnerStruct extends NDRSTRUCT {
      static structure: NDRField[] = [
        ['Count', NDRULONG],
        ['Ptr', PULONG],
      ];
    }

    class TestCall extends NDRCALL {
      static structure: NDRField[] = [
        ['Inner', InnerStruct],
      ];
    }

    const call = new TestCall();
    const inner = call.fields['Inner'] as InnerStruct;
    inner.set('Count', 5);
    const ptr = inner.fields['Ptr'] as PULONG;
    ptr.set('Data', 999);

    const data = call.getData();

    const parsed = new TestCall(data);
    const parsedInner = parsed.fields['Inner'] as InnerStruct;
    expect(parsedInner.get('Count')).toBe(5);
    const parsedPtr = parsedInner.fields['Ptr'] as PULONG;
    expect(parsedPtr.get('Data')).toBe(999);
  });

  it('round-trips a call with conformant array', () => {
    class ULongArray extends NDRUniConformantArray {
      static item = NDRULONG;
    }

    class TestCall extends NDRCALL {
      static structure: NDRField[] = [
        ['Count', NDRULONG],
        ['Array', ULongArray],
      ];
    }

    const call = new TestCall();
    call.set('Count', 3);
    const arr = call.fields['Array'] as ULongArray;
    const items = [new NDRULONG(), new NDRULONG(), new NDRULONG()];
    items[0]!.set('Data', 10);
    items[1]!.set('Data', 20);
    items[2]!.set('Data', 30);
    arr.fields['Data'] = items;

    const data = call.getData();

    const parsed = new TestCall(data);
    expect(parsed.get('Count')).toBe(3);
    const parsedArr = parsed.fields['Array'] as ULongArray;
    const parsedItems = parsedArr.fields['Data'] as NDR[];
    expect(parsedItems.length).toBe(3);
    expect(parsedItems[0]!.get('Data')).toBe(10);
    expect(parsedItems[1]!.get('Data')).toBe(20);
    expect(parsedItems[2]!.get('Data')).toBe(30);
  });
});

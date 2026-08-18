import { Buffer } from 'node:buffer';
import { randomInt } from 'node:crypto';
import { calcsize, calcalign, evalExpr, structPack, structUnpack, type PackValue } from '@impacket/structure';

export type NDRFieldType = string | NDRConstructor;
export type NDRField = [string, NDRFieldType] | [string, NDRFieldType, string | NDRConstructor];
export type NDRConstructor = new (data?: Buffer | null, isNDR64?: boolean, topLevel?: boolean) => NDR;

function pySplit(s: string, sep: string): string[] {
  return s.split(sep);
}

export class NDR {
  static commonHdr: NDRField[] = [];
  static commonHdr64: NDRField[] = [];
  static structure: NDRField[] = [];
  static structure64: NDRField[] = [];
  static referent: NDRField[] = [];
  static align = 4;
  static align64?: number;
  static item: NDRFieldType | null = null;

  _isNDR64 = false;
  fields: Record<string, unknown> = {};
  commonHdr: NDRField[];
  structure: NDRField[];
  referent: NDRField[];
  align: number;
  item: NDRFieldType | null;

  constructor(data?: Buffer | null, isNDR64 = false) {
    const cls = this.constructor as typeof NDR;
    this._isNDR64 = isNDR64;
    this.fields = {};

    this.commonHdr = isNDR64 && cls.commonHdr64.length > 0 ? [...cls.commonHdr64] : [...cls.commonHdr];
    this.structure = isNDR64 && cls.structure64.length > 0 ? [...cls.structure64] : [...cls.structure];
    this.referent = [...cls.referent];
    this.align = isNDR64 && cls.align64 ? cls.align64 : cls.align;
    this.item = cls.item;

    for (const [fieldName, fieldTypeOrClass] of [...this.commonHdr, ...this.structure, ...this.referent]) {
      if (NDR.isNDR(fieldTypeOrClass)) {
        const ctor = fieldTypeOrClass as NDRConstructor;
        if (NDRCONSTRUCTEDTYPE.isPointer(fieldTypeOrClass)) {
          this.fields[fieldName] = new ctor(null, this._isNDR64, false);
        } else if (NDRCONSTRUCTEDTYPE.isUnion(fieldTypeOrClass)) {
          this.fields[fieldName] = new ctor(null, this._isNDR64, false);
        } else {
          this.fields[fieldName] = new ctor(null, this._isNDR64);
        }
      } else if (fieldTypeOrClass === ':') {
        this.fields[fieldName] = Buffer.alloc(0);
      } else if (typeof fieldTypeOrClass === 'string' && pySplit(fieldTypeOrClass, '=').length === 2) {
        const expr = pySplit(fieldTypeOrClass, '=')[1]!;
        try {
          this.fields[fieldName] = evalExpr(expr, {});
        } catch {
          this.fields[fieldName] = null;
        }
      } else {
        this.fields[fieldName] = [];
      }
    }

    if (data) {
      this.fromString(data);
    }
  }

  changeTransferSyntax(newSyntax: Buffer): void {
    const NDR64Syntax = Buffer.from('71710533beba49378319b5dbef9ccc36', 'hex');
    if (newSyntax.equals(NDR64Syntax)) {
      if (this._isNDR64 === false) {
        this._isNDR64 = true;
        for (const fieldName of Object.keys(this.fields)) {
          if (this.fields[fieldName] instanceof NDR) {
            (this.fields[fieldName] as NDR).changeTransferSyntax(newSyntax);
          }
        }
        const cls = this.constructor as typeof NDR;
        if (cls.commonHdr64.length > 0) this.commonHdr = [...cls.commonHdr64];
        if (cls.structure64.length > 0) this.structure = [...cls.structure64];
        if (cls.align64) this.align = cls.align64;
        for (const [fieldName, fieldTypeOrClass] of [...this.commonHdr, ...this.structure, ...this.referent]) {
          if (this.fields[fieldName] instanceof NDR) {
            const ctor = fieldTypeOrClass as NDRConstructor;
            if (ctor && !(this.fields[fieldName] instanceof NDRPOINTERNULL)) {
              if (ctor !== (this.fields[fieldName] as NDR).constructor) {
                const backupData = this.get(fieldName);
                this.fields[fieldName] = new ctor(null, this._isNDR64);
                if ('Data' in (this.fields[fieldName] as NDR).fields) {
                  (this.fields[fieldName] as NDR).fields['Data'] = backupData;
                } else {
                  this.set(fieldName, backupData);
                }
              }
            }
          }
        }
      }
    } else {
      if (this._isNDR64 === true) {
        throw new Error("Shouldn't be here");
      }
    }
  }

  set(key: string, value: unknown): void {
    if (value instanceof NDRPOINTERNULL) {
      const nullInst = new NDRPOINTERNULL(null, this._isNDR64);
      if (this.fields[key] instanceof NDRPOINTER) {
        this.fields[key] = nullInst;
      } else if (
        this.fields[key] instanceof NDR &&
        'Data' in (this.fields[key] as NDR).fields
      ) {
        if ((this.fields[key] as NDR).fields['Data'] instanceof NDRPOINTER) {
          (this.fields[key] as NDR).fields['Data'] = nullInst;
        }
      }
    } else if (value instanceof NDR) {
      const existing = this.fields[key];
      if (existing instanceof NDR && existing.constructor.name === value.constructor.name) {
        this.fields[key] = value;
      } else if (existing instanceof NDR && 'Data' in existing.fields && existing.fields['Data'] instanceof NDR) {
        const innerData = existing.fields['Data'] as NDR;
        if (innerData.constructor.name === value.constructor.name) {
          existing.fields['Data'] = value;
        }
      }
    } else if (this.fields[key] instanceof NDR) {
      const ndr = this.fields[key] as NDR;
      if ('Data' in ndr.fields) {
        ndr.set('Data', value);
      } else {
        this.fields[key] = value;
      }
    } else {
      this.fields[key] = value;
    }
  }

  get(key: string): unknown {
    const val = this.fields[key];
    if (val instanceof NDR && 'Data' in val.fields) {
      let cur: NDR = val as NDR;
      while (true) {
        const next = cur.fields['Data'];
        if (next instanceof NDR && 'Data' in next.fields) {
          cur = next;
          continue;
        }
        return cur.get('Data');
      }
    }
    return val;
  }

  getDataLen(data: Buffer, offset = 0): number {
    return data.length - offset;
  }

  static isNDR(field: NDRFieldType | null | undefined): boolean {
    return typeof field === 'function';
  }

  static calculatePad(fieldType: NDRFieldType | null | undefined, soFar: number): number {
    if (typeof fieldType === 'string') {
      try {
        const alignment = calcalign(pySplit(fieldType, '=')[0]!);
        if (alignment > 0) {
          return (alignment - (soFar % alignment)) % alignment;
        }
      } catch {
        // ignore
      }
    }
    return 0;
  }

  getAlignment(): number {
    return this.align;
  }

  getData(soFar = 0): Buffer {
    let data = Buffer.alloc(0);
    for (const [fieldName, fieldTypeOrClass] of [...this.commonHdr, ...this.structure]) {
      try {
        const pad = NDR.calculatePad(fieldTypeOrClass, soFar);
        if (pad > 0) {
          soFar += pad;
          data = Buffer.concat([data, Buffer.alloc(pad)]);
        }
        const res = this.pack(fieldName, fieldTypeOrClass, soFar);
        data = Buffer.concat([data, res]);
        soFar += res.length;
      } catch (e) {
        throw new Error(
          `Error packing field '${fieldName} | ${fieldTypeOrClass}' in ${this.constructor.name}: ${(e as Error).message}`,
        );
      }
    }
    return data;
  }

  fromString(data: Buffer, offset = 0): number {
    const offset0 = offset;
    for (const [fieldName, fieldTypeOrClass] of [...this.commonHdr, ...this.structure]) {
      try {
        offset += NDR.calculatePad(fieldTypeOrClass, offset);
        offset += this.unpack(fieldName, fieldTypeOrClass, data, offset);
      } catch (e) {
        throw new Error(
          `Error unpacking field '${fieldName} | ${fieldTypeOrClass}': ${(e as Error).message}`,
        );
      }
    }
    return offset - offset0;
  }

  pack(fieldName: string, fieldTypeOrClass: NDRFieldType, soFar = 0): Buffer {
    if (this.fields[fieldName] instanceof NDR) {
      return (this.fields[fieldName] as NDR).getData(soFar);
    }

    let data = this.fields[fieldName] as PackValue;

    if (typeof fieldTypeOrClass === 'string' && fieldTypeOrClass.startsWith('_')) {
      return Buffer.alloc(0);
    }

    if (typeof fieldTypeOrClass === 'string') {
      const two = pySplit(fieldTypeOrClass, '=');
      if (two.length >= 2) {
        try {
          return this.pack(fieldName, two[0]!, soFar);
        } catch {
          this.fields[fieldName] = evalExpr(two[1]!, this.fields);
          data = this.fields[fieldName] as unknown as PackValue;
          return this.pack(fieldName, two[0]!, soFar);
        }
      }
    }

    if (data == null) {
      throw new Error('Trying to pack None');
    }

    if (typeof fieldTypeOrClass === 'string' && fieldTypeOrClass.startsWith(':')) {
      if (typeof data === 'object' && data !== null && 'getData' in data) {
        return (data as { getData: () => Buffer }).getData();
      }
      if (Buffer.isBuffer(data)) return data;
      if (typeof data === 'string') return Buffer.from(data);
      return Buffer.alloc(0);
    }

    return structPack(fieldTypeOrClass as string, data);
  }

  unpack(fieldName: string, fieldTypeOrClass: NDRFieldType, data: Buffer, offset = 0): number {
    if (this.fields[fieldName] instanceof NDR) {
      return (this.fields[fieldName] as NDR).fromString(data, offset);
    }

    if (typeof fieldTypeOrClass === 'string') {
      const two = pySplit(fieldTypeOrClass, '=');
      if (two.length >= 2) {
        return this.unpack(fieldName, two[0]!, data, offset);
      }

      if (fieldTypeOrClass === ':') {
        const dataLen = this.getDataLen(data, offset);
        this.fields[fieldName] = data.subarray(offset, offset + dataLen);
        return dataLen;
      }

      const val = structUnpack(fieldTypeOrClass, data.subarray(offset));
      this.fields[fieldName] = val;
      return calcsize(fieldTypeOrClass);
    }

    return data.length - offset;
  }

  calcPackSize(fieldTypeOrClass: NDRFieldType, data: unknown): number {
    if (typeof fieldTypeOrClass !== 'string') {
      return (data as { length?: number })?.length ?? 0;
    }

    const two = pySplit(fieldTypeOrClass, '=');
    if (two.length >= 2) {
      return this.calcPackSize(two[0]!, data);
    }

    if (fieldTypeOrClass.startsWith(':')) {
      if (Buffer.isBuffer(data)) return data.length;
      if (typeof data === 'string') return data.length;
      return 0;
    }

    return calcsize(fieldTypeOrClass);
  }

  calcUnPackSize(fieldTypeOrClass: NDRFieldType, data: Buffer, offset = 0): number {
    if (typeof fieldTypeOrClass !== 'string') {
      return data.length - offset;
    }

    const two = pySplit(fieldTypeOrClass, '=');
    if (two.length >= 2) {
      return this.calcUnPackSize(two[0]!, data, offset);
    }

    const starParts = pySplit(fieldTypeOrClass, '*');
    if (starParts.length === 2) {
      return data.length - offset;
    }

    if (fieldTypeOrClass.startsWith(':')) {
      return data.length - offset;
    }

    return calcsize(fieldTypeOrClass);
  }
}

export class NDRSMALL extends NDR {
  static align = 1;
  static structure: NDRField[] = [['Data', 'b=0']];
}

export class NDRUSMALL extends NDR {
  static align = 1;
  static structure: NDRField[] = [['Data', 'B=0']];
}

export class NDRBOOLEAN extends NDRSMALL {}

export class NDRCHAR extends NDR {
  static align = 1;
  static structure: NDRField[] = [['Data', 'c']];
}

export class NDRSHORT extends NDR {
  static align = 2;
  static structure: NDRField[] = [['Data', '<h=0']];
}

export class NDRUSHORT extends NDR {
  static align = 2;
  static structure: NDRField[] = [['Data', '<H=0']];
}

export class NDRLONG extends NDR {
  static align = 4;
  static structure: NDRField[] = [['Data', '<l=0']];
}

export class NDRULONG extends NDR {
  static align = 4;
  static structure: NDRField[] = [['Data', '<L=0']];
}

export class NDRHYPER extends NDR {
  static align = 8;
  static structure: NDRField[] = [['Data', '<q=0']];
}

export class NDRUHYPER extends NDR {
  static align = 8;
  static structure: NDRField[] = [['Data', '<Q=0']];
}

export class NDRFLOAT extends NDR {
  static align = 4;
  static structure: NDRField[] = [['Data', '<f=0']];
}

export class NDRDOUBLEFLOAT extends NDR {
  static align = 8;
  static structure: NDRField[] = [['Data', '<d=0']];
}

export class NDRENUM extends NDR {
  static align = 2;
  static align64 = 4;
  static structure: NDRField[] = [['Data', '<H']];
  static structure64: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {};
  static enumValues: Record<string, number> = {};

  set(key: string, value: unknown): void {
    if (key === 'Data' && typeof value === 'string') {
      const cls = this.constructor as typeof NDRENUM;
      const val = cls.enumValues[value];
      if (val !== undefined) {
        super.set(key, val);
        return;
      }
    }
    super.set(key, value);
  }

  get enumName(): string {
    const cls = this.constructor as typeof NDRENUM;
    const data = this.fields['Data'] as number;
    return cls.enumItems[data] ?? `UNKNOWN(${data})`;
  }
}

export class NDRCONSTRUCTEDTYPE extends NDR {
  static isPointer(field: NDRFieldType | null | undefined): boolean {
    if (typeof field !== 'function') return false;
    return (field as unknown as { prototype?: unknown }).prototype instanceof NDRPOINTER;
  }

  static isUnion(field: NDRFieldType | null | undefined): boolean {
    if (typeof field !== 'function') return false;
    return (field as unknown as { prototype?: unknown }).prototype instanceof NDRUNION;
  }

  getDataReferents(soFar = 0): Buffer {
    let data = Buffer.alloc(0);
    for (const [fieldName] of [...this.commonHdr, ...this.structure]) {
      if (this.fields[fieldName] instanceof NDRCONSTRUCTEDTYPE) {
        const child = this.fields[fieldName] as NDRCONSTRUCTEDTYPE;
        data = Buffer.concat([data, child.getDataReferents(data.length + soFar)]);
        data = Buffer.concat([data, child.getDataReferent(data.length + soFar)]);
      }
    }
    return data;
  }

  getDataReferent(soFar = 0): Buffer {
    let data = Buffer.alloc(0);
    const soFar0 = soFar;

    if (this.referent.length === 0) {
      return data;
    }

    if ('ReferentID' in this.fields) {
      if (this.get('ReferentID') === 0) {
        return data;
      }
    }

    for (const [fieldName, fieldTypeOrClass] of this.referent) {
      try {
        if (
          this.fields[fieldName] instanceof NDRUniConformantArray ||
          this.fields[fieldName] instanceof NDRUniConformantVaryingArray
        ) {
          const arrayItemSize = this._isNDR64 ? 8 : 4;
          const arrayPackStr = this._isNDR64 ? '<Q' : '<L';

          const pad0 = (arrayItemSize - (soFar % arrayItemSize)) % arrayItemSize;
          if (pad0 > 0) {
            soFar += pad0;
          }
          soFar += arrayItemSize;

          const childArr = this.fields[fieldName] as NDRUniConformantArray | NDRUniConformantVaryingArray;
          const arrData = childArr.getData(soFar);
          const maxSize = this.getArrayMaximumSize(fieldName);
          data = Buffer.concat([Buffer.alloc(pad0), structPack(arrayPackStr, maxSize), arrData]);
        } else {
          const pad = NDR.calculatePad(fieldTypeOrClass, soFar);
          if (pad > 0) {
            soFar += pad;
            data = Buffer.concat([data, Buffer.alloc(pad)]);
          }
          data = Buffer.concat([data, this.pack(fieldName, fieldTypeOrClass, soFar)]);
        }

        if (this.fields[fieldName] instanceof NDRCONSTRUCTEDTYPE) {
          const child = this.fields[fieldName] as NDRCONSTRUCTEDTYPE;
          data = Buffer.concat([data, child.getDataReferents(soFar0 + data.length)]);
          data = Buffer.concat([data, child.getDataReferent(soFar0 + data.length)]);
        }
        soFar = soFar0 + data.length;
      } catch (e) {
        throw new Error(
          `Error packing referent field '${fieldName} | ${fieldTypeOrClass}' in ${this.constructor.name}: ${(e as Error).message}`,
        );
      }
    }

    return data;
  }

  getArrayMaximumSize(fieldName: string): number {
    const arr = this.fields[fieldName] as NDRUniConformantArray | NDRUniConformantVaryingArray;
    const maxCount = arr.fields['MaximumCount'] as number | null;
    if (maxCount != null && maxCount > 0) {
      return maxCount;
    }
    return arr.getStoredArraySize();
  }

  getArraySize(fieldName: string, data: Buffer, offset = 0): [number, number] {
    const arrayItemSize = this._isNDR64 ? 8 : 4;
    const arrayUnPackStr = this._isNDR64 ? '<Q' : '<L';

    const pad = (arrayItemSize - (offset % arrayItemSize)) % arrayItemSize;
    offset += pad;

    const arr = this.fields[fieldName] as NDRArray;
    if (arr instanceof NDRUniConformantArray) {
      const arraySize = structUnpack(arrayUnPackStr, data.subarray(offset)) as number;
      return [arraySize, arrayItemSize + pad];
    }
    if (arr instanceof NDRUniConformantVaryingArray) {
      const maximumCount = structUnpack(arrayUnPackStr, data.subarray(offset)) as number;
      arr.fields['MaximumCount'] = maximumCount;
      const arraySize = structUnpack(arrayUnPackStr, data.subarray(offset + arrayItemSize * 2)) as number;
      return [arraySize, arrayItemSize + pad];
    }
    // NDRUniVaryingArray
    const arraySize = structUnpack(arrayUnPackStr, data.subarray(offset + arrayItemSize)) as number;
    return [arraySize, arrayItemSize + pad];
  }

  fromStringReferents(data: Buffer, offset = 0): number {
    const offset0 = offset;
    for (const [fieldName] of [...this.commonHdr, ...this.structure]) {
      if (this.fields[fieldName] instanceof NDRCONSTRUCTEDTYPE) {
        const child = this.fields[fieldName] as NDRCONSTRUCTEDTYPE;
        offset += child.fromStringReferents(data, offset);
        offset += child.fromStringReferent(data, offset);
      }
    }
    return offset - offset0;
  }

  fromStringReferent(data: Buffer, offset = 0): number {
    if (this.referent.length === 0) {
      return 0;
    }

    const offset0 = offset;

    if ('ReferentID' in this.fields) {
      if (this.get('ReferentID') === 0) {
        return 0;
      }
    }

    for (const [fieldName, fieldTypeOrClass] of this.referent) {
      try {
        if (
          this.fields[fieldName] instanceof NDRUniConformantArray ||
          this.fields[fieldName] instanceof NDRUniConformantVaryingArray
        ) {
          const [arraySize, advanceStream] = this.getArraySize(fieldName, data, offset);
          offset += advanceStream;
          (this.fields[fieldName] as NDRArray).setArraySize(arraySize);
          const size = (this.fields[fieldName] as NDR).fromString(data, offset);
          offset += size;
        } else {
          offset += NDR.calculatePad(fieldTypeOrClass, offset);
          const size = this.unpack(fieldName, fieldTypeOrClass, data, offset);
          offset += size;
        }

        if (this.fields[fieldName] instanceof NDRCONSTRUCTEDTYPE) {
          const child = this.fields[fieldName] as NDRCONSTRUCTEDTYPE;
          offset += child.fromStringReferents(data, offset);
          offset += child.fromStringReferent(data, offset);
        }
      } catch (e) {
        throw new Error(
          `Error unpacking referent field '${fieldName} | ${fieldTypeOrClass}': ${(e as Error).message}`,
        );
      }
    }

    return offset - offset0;
  }

  calcPackSize(fieldTypeOrClass: NDRFieldType, data: unknown): number {
    if (typeof fieldTypeOrClass !== 'string') {
      return (data as { length?: number })?.length ?? 0;
    }

    const starParts = pySplit(fieldTypeOrClass, '*');
    if (starParts.length === 2) {
      let answer = 0;
      const arr = data as unknown[];
      for (const each of arr) {
        if (NDR.isNDR(this.item)) {
          answer += this.calcPackSize(':', each);
        } else {
          answer += this.calcPackSize(this.item ?? 'c', each);
        }
      }
      return answer;
    }
    return NDR.prototype.calcPackSize.call(this, fieldTypeOrClass, data);
  }

  calcUnPackSize(fieldTypeOrClass: NDRFieldType, data: Buffer, offset = 0): number {
    if (typeof fieldTypeOrClass !== 'string') {
      return data.length - offset;
    }

    const starParts = pySplit(fieldTypeOrClass, '*');
    if (starParts.length === 2) {
      return data.length - offset;
    }
    return NDR.prototype.calcUnPackSize.call(this, fieldTypeOrClass, data, offset);
  }
}

export class NDRArray extends NDRCONSTRUCTEDTYPE {
  arraySize = 0;

  setArraySize(size: number): void {
    this.arraySize = size;
  }

  getStoredArraySize(): number {
    return this.arraySize;
  }

  changeTransferSyntax(newSyntax: Buffer): void {
    if (this.item != null && NDR.isNDR(this.item)) {
      const arr = this.fields['Data'];
      if (Array.isArray(arr)) {
        for (const item of arr) {
          if (item instanceof NDR) {
            item.changeTransferSyntax(newSyntax);
          }
        }
      }
    }
    super.changeTransferSyntax(newSyntax);
  }

  getAlignment(): number {
    let align = 0;
    if (this.item != null) {
      if (NDR.isNDR(this.item)) {
        const ctor = this.item as NDRConstructor;
        const tmp = new ctor(null, this._isNDR64);
        align = tmp.getAlignment();
      } else {
        align = this.calcPackSize(this.item as string, Buffer.alloc(0));
      }
    }
    return align;
  }

  getData(soFar = 0): Buffer {
    let data = Buffer.alloc(0);
    const soFar0 = soFar;
    for (const [fieldName, fieldTypeOrClass] of this.structure) {
      try {
        if (!NDR.isNDR(fieldTypeOrClass)) {
          const pad = NDR.calculatePad(fieldTypeOrClass, soFar);
          if (pad > 0) {
            soFar += pad;
            data = Buffer.concat([data, Buffer.alloc(pad)]);
          }
        }
        const res = this.pack(fieldName, fieldTypeOrClass, soFar);
        data = Buffer.concat([data, res]);
        soFar = soFar0 + data.length;
      } catch (e) {
        throw new Error(
          `Error packing field '${fieldName} | ${fieldTypeOrClass}' in ${this.constructor.name}: ${(e as Error).message}`,
        );
      }
    }
    return data;
  }

  pack(fieldName: string, fieldTypeOrClass: NDRFieldType, soFar = 0): Buffer {
    if (typeof fieldTypeOrClass === 'string') {
      const two = pySplit(fieldTypeOrClass, '*');
      if (two.length === 2) {
        let answer = Buffer.alloc(0);
        let dataClass: NDRConstructor | null = null;
        let itemFmt: string;

        if (this.item != null && NDR.isNDR(this.item)) {
          itemFmt = ':';
          dataClass = this.item as NDRConstructor;
        } else {
          itemFmt = (this.item as string) ?? 'c';
        }

        const items = (this.fields[fieldName] ?? []) as unknown[];
        for (const each of items) {
          const pad = NDR.calculatePad(this.item ?? 'c', answer.length + soFar);
          if (pad > 0) {
            answer = Buffer.concat([answer, Buffer.alloc(pad)]);
          }
          if (dataClass) {
            if (each instanceof NDR) {
              answer = Buffer.concat([answer, each.getData(answer.length + soFar)]);
            } else {
              const inst = new dataClass();
              inst.fields['Data'] = each;
              answer = Buffer.concat([answer, inst.getData(answer.length + soFar)]);
            }
          } else {
            if (itemFmt === 'c' && typeof each === 'number') {
              answer = Buffer.concat([answer, Buffer.from([each & 0xff])]);
            } else {
              answer = Buffer.concat([answer, structPack(itemFmt, each as unknown as PackValue)]);
            }
          }
        }

        if (dataClass) {
          for (const each of items) {
            if (each instanceof NDRCONSTRUCTEDTYPE) {
              answer = Buffer.concat([answer, each.getDataReferents(answer.length + soFar)]);
              answer = Buffer.concat([answer, each.getDataReferent(answer.length + soFar)]);
            }
          }
        }

        if (this instanceof NDRUniConformantArray || this instanceof NDRUniConformantVaryingArray) {
          this.setArraySize(items.length);
        } else {
          this.fields[two[1]!] = items.length;
        }

        return answer;
      }
    }
    return NDRCONSTRUCTEDTYPE.prototype.pack.call(this, fieldName, fieldTypeOrClass, soFar);
  }

  fromString(data: Buffer, offset = 0): number {
    const offset0 = offset;
    for (const [fieldName, fieldTypeOrClass] of [...this.commonHdr, ...this.structure]) {
      try {
        if (!NDR.isNDR(fieldTypeOrClass)) {
          offset += NDR.calculatePad(fieldTypeOrClass, offset);
        }
        const size = this.unpack(fieldName, fieldTypeOrClass, data, offset);
        offset += size;
      } catch (e) {
        throw new Error(
          `Error unpacking field '${fieldName} | ${fieldTypeOrClass}': ${(e as Error).message}`,
        );
      }
    }
    return offset - offset0;
  }

  unpack(fieldName: string, fieldTypeOrClass: NDRFieldType, data: Buffer, offset = 0): number {
    if (typeof fieldTypeOrClass === 'string') {
      const two = pySplit(fieldTypeOrClass, '*');
      if (two.length === 2) {
        const answer: unknown[] = [];
        let soFarItems = 0;
        const offset0 = offset;

        let numItems: number;
        if (this instanceof NDRUniConformantArray) {
          numItems = this.getStoredArraySize();
        } else {
          numItems = this.get(two[1]!) as number;
        }

        let dataClass: NDRConstructor | null = null;
        let itemFmt: string;

        if (this.item != null && NDR.isNDR(this.item)) {
          itemFmt = ':';
          dataClass = this.item as NDRConstructor;
        } else {
          itemFmt = (this.item as string) ?? 'c';
        }

        let nsofar = 0;
        while (numItems > 0 && soFarItems < data.length - offset) {
          const pad = NDR.calculatePad(this.item ?? 'c', soFarItems + offset);
          if (pad > 0) {
            soFarItems += pad;
          }
          if (dataClass === null) {
            nsofar = soFarItems + calcsize(itemFmt);
            const val = structUnpack(itemFmt, data.subarray(offset + soFarItems));
            answer.push(val);
          } else {
            const itemn = new dataClass(null, this._isNDR64);
            const size = itemn.fromString(data, offset + soFarItems);
            answer.push(itemn);
            nsofar += size + pad;
          }
          numItems--;
          soFarItems = nsofar;
        }

        if (dataClass !== null) {
          const tmpCtor = dataClass;
          const isConstructed = Object.prototype.isPrototypeOf.call(
            NDRCONSTRUCTEDTYPE.prototype,
            tmpCtor.prototype,
          );
          if (isConstructed) {
            const answer2: unknown[] = [];
            for (const itemn of answer as NDRCONSTRUCTEDTYPE[]) {
              const size1 = itemn.fromStringReferents(data, soFarItems + offset);
              soFarItems += size1;
              const size2 = itemn.fromStringReferent(data, soFarItems + offset);
              soFarItems += size2;
              answer2.push(itemn);
            }
            answer.length = 0;
            answer.push(...answer2);
          }
        }

        this.fields[fieldName] = answer;
        return soFarItems + offset - offset0;
      }
    }
    return NDRCONSTRUCTEDTYPE.prototype.unpack.call(this, fieldName, fieldTypeOrClass, data, offset);
  }
}

export class NDRUniFixedArray extends NDRArray {
  static structure: NDRField[] = [['Data', ':']];
}

export class NDRUniConformantArray extends NDRArray {
  static item: NDRFieldType = 'c';
  static structure: NDRField[] = [['Data', '*MaximumCount']];
  static structure64: NDRField[] = [['Data', '*MaximumCount']];

  constructor(data?: Buffer | null, isNDR64 = false) {
    super(data, isNDR64);
    this.fields['MaximumCount'] = 0;
  }

  set(key: string, value: unknown): void {
    this.fields['MaximumCount'] = null;
    super.set(key, value);
  }
}

export class NDRUniVaryingArray extends NDRArray {
  static item: NDRFieldType = 'c';
  static structure: NDRField[] = [
    ['Offset', '<L=0'],
    ['ActualCount', '<L=len(Data)'],
    ['Data', '*ActualCount'],
  ];
  static structure64: NDRField[] = [
    ['Offset', '<Q=0'],
    ['ActualCount', '<Q=len(Data)'],
    ['Data', '*ActualCount'],
  ];

  set(key: string, value: unknown): void {
    this.fields['ActualCount'] = null;
    super.set(key, value);
  }
}

export class NDRUniConformantVaryingArray extends NDRArray {
  static item: NDRFieldType = 'c';
  static commonHdr: NDRField[] = [
    ['Offset', '<L=0'],
    ['ActualCount', '<L=len(Data)'],
  ];
  static commonHdr64: NDRField[] = [
    ['Offset', '<Q=0'],
    ['ActualCount', '<Q=len(Data)'],
  ];
  static structure: NDRField[] = [['Data', '*ActualCount']];

  constructor(data?: Buffer | null, isNDR64 = false) {
    super(data, isNDR64);
    this.fields['MaximumCount'] = 0;
  }

  set(key: string, value: unknown): void {
    this.fields['MaximumCount'] = null;
    this.fields['ActualCount'] = null;
    super.set(key, value);
  }

  getData(soFar = 0): Buffer {
    let data = Buffer.alloc(0);
    const soFar0 = soFar;
    for (const [fieldName, fieldTypeOrClass] of [...this.commonHdr, ...this.structure]) {
      try {
        const pad = NDR.calculatePad(fieldTypeOrClass, soFar);
        if (pad > 0) {
          soFar += pad;
          data = Buffer.concat([data, Buffer.alloc(pad)]);
        }
        const res = this.pack(fieldName, fieldTypeOrClass, soFar);
        data = Buffer.concat([data, res]);
        soFar = soFar0 + data.length;
      } catch (e) {
        throw new Error(
          `Error packing field '${fieldName} | ${fieldTypeOrClass}' in ${this.constructor.name}: ${(e as Error).message}`,
        );
      }
    }
    return data;
  }
}

export class NDRVaryingString extends NDRUniVaryingArray {
  getData(soFar = 0): Buffer {
    const data = this.get('Data');
    if (Buffer.isBuffer(data)) {
      if (data[data.length - 1] !== 0) {
        this.set('Data', Buffer.concat([data, Buffer.from([0])]));
      }
    }
    return super.getData(soFar);
  }

  fromString(data: Buffer, offset = 0): number {
    const ret = super.fromString(data, offset);
    const d = this.get('Data');
    if (Buffer.isBuffer(d)) {
      this.set('Data', d.subarray(0, d.length - 1));
    } else if (Array.isArray(d)) {
      this.set('Data', (d as unknown[]).slice(0, -1));
    }
    return ret;
  }
}

export class NDRConformantVaryingString extends NDRUniConformantVaryingArray {}

export class NDRSTRUCT extends NDRCONSTRUCTEDTYPE {
  getData(soFar = 0): Buffer {
    let data = Buffer.alloc(0);
    let arrayPadding = Buffer.alloc(0);
    const soFar0 = soFar;

    const allFields = [...this.commonHdr, ...this.structure];
    const lastItem = allFields[allFields.length - 1]?.[0];
    let arrayItemSize = 0;
    let arrayPackStr = '<L';

    if (
      lastItem &&
      (this.fields[lastItem] instanceof NDRUniConformantArray ||
        this.fields[lastItem] instanceof NDRUniConformantVaryingArray)
    ) {
      arrayItemSize = this._isNDR64 ? 8 : 4;
      arrayPackStr = this._isNDR64 ? '<Q' : '<L';

      const pad0 = (arrayItemSize - (soFar % arrayItemSize)) % arrayItemSize;
      if (pad0 > 0) {
        soFar += pad0;
        arrayPadding = Buffer.alloc(pad0);
      }
      soFar += arrayItemSize;
    }

    const alignment = this.getAlignment();
    if (alignment > 0) {
      const pad = (alignment - (soFar % alignment)) % alignment;
      if (pad > 0) {
        soFar += pad;
        data = Buffer.concat([data, Buffer.alloc(pad)]);
      }
    }

    for (const [fieldName, fieldTypeOrClass] of [...this.commonHdr, ...this.structure]) {
      try {
        let res: Buffer;
        if (
          this.fields[fieldName] instanceof NDRUniConformantArray ||
          this.fields[fieldName] instanceof NDRUniConformantVaryingArray
        ) {
          res = (this.fields[fieldName] as NDR).getData(soFar);
          if (this instanceof NDRPOINTER) {
            const pointerData = data.subarray(0, arrayItemSize);
            data = data.subarray(arrayItemSize);
            data = Buffer.concat([
              pointerData,
              arrayPadding,
              structPack(arrayPackStr, this.getArrayMaximumSize(fieldName)),
              data,
            ]);
          } else {
            data = Buffer.concat([
              arrayPadding,
              structPack(arrayPackStr, this.getArrayMaximumSize(fieldName)),
              data,
            ]);
          }
          arrayPadding = Buffer.alloc(0);
          arrayItemSize = 0;
        } else {
          res = this.pack(fieldName, fieldTypeOrClass, soFar);
        }
        data = Buffer.concat([data, res]);
        soFar = soFar0 + data.length + arrayPadding.length + arrayItemSize;
      } catch (e) {
        throw new Error(
          `Error packing field '${fieldName} | ${fieldTypeOrClass}' in ${this.constructor.name}: ${(e as Error).message}`,
        );
      }
    }

    return data;
  }

  fromString(data: Buffer, offset = 0): number {
    const offset0 = offset;
    const allFields = [...this.commonHdr, ...this.structure];
    const lastItem = allFields[allFields.length - 1]?.[0];

    let structureFields: NDRField[];
    if (this instanceof NDRPOINTER) {
      structureFields = this.structure;
      const alignment = this.getAlignment();
      if (alignment > 0) {
        offset += (alignment - (offset % alignment)) % alignment;
      }
      for (const [fieldName, fieldTypeOrClass] of this.commonHdr) {
        offset += this.unpack(fieldName, fieldTypeOrClass, data, offset);
      }
    } else {
      structureFields = [...this.commonHdr, ...this.structure];
    }

    if (
      lastItem &&
      (this.fields[lastItem] instanceof NDRUniConformantArray ||
        this.fields[lastItem] instanceof NDRUniConformantVaryingArray)
    ) {
      const arrayItemSize = this._isNDR64 ? 8 : 4;
      const arrayUnPackStr = this._isNDR64 ? '<Q' : '<L';

      offset += (arrayItemSize - (offset % arrayItemSize)) % arrayItemSize;

      if (this.fields[lastItem] instanceof NDRUniConformantArray) {
        const arraySize = structUnpack(arrayUnPackStr, data.subarray(offset)) as number;
        (this.fields[lastItem] as NDRUniConformantArray).setArraySize(arraySize);
      } else {
        const maximumCount = structUnpack(arrayUnPackStr, data.subarray(offset)) as number;
        (this.fields[lastItem] as NDRUniConformantVaryingArray).fields['MaximumCount'] = maximumCount;
      }
      offset += arrayItemSize;
    }

    const alignment = this.getAlignment();
    if (alignment > 0) {
      offset += (alignment - (offset % alignment)) % alignment;
    }

    for (const [fieldName, fieldTypeOrClass] of structureFields) {
      try {
        offset += this.unpack(fieldName, fieldTypeOrClass, data, offset);
      } catch (e) {
        throw new Error(
          `Error unpacking field '${fieldName} | ${fieldTypeOrClass}': ${(e as Error).message}`,
        );
      }
    }

    return offset - offset0;
  }

  getAlignment(): number {
    let align = 0;
    for (const [fieldName, fieldTypeOrClass] of [...this.commonHdr, ...this.structure, ...this.referent]) {
      if (this.fields[fieldName] instanceof NDR) {
        const tmp = (this.fields[fieldName] as NDR).getAlignment();
        if (tmp > align) align = tmp;
      } else {
        const tmp = this.calcPackSize(fieldTypeOrClass, Buffer.alloc(0));
        if (tmp > align) align = tmp;
      }
    }
    return align;
  }
}

export class NDRUNION extends NDRCONSTRUCTEDTYPE {
  static commonHdr: NDRField[] = [['tag', NDRUSHORT]];
  static commonHdr64: NDRField[] = [['tag', NDRULONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {};

  topLevel = false;

  constructor(data?: Buffer | null, isNDR64 = false, topLevel = false) {
    super(null, isNDR64);
    this.topLevel = topLevel;
    this.fields = {};

    const cls = this.constructor as typeof NDRUNION;
    if (isNDR64) {
      if (cls.commonHdr64.length > 0) this.commonHdr = [...cls.commonHdr64];
      if (cls.structure64.length > 0) this.structure = [...cls.structure64];
      if (cls.align64) this.align = cls.align64;
    }

    for (const [fieldName, fieldTypeOrClass] of [...this.commonHdr, ...this.structure, ...this.referent]) {
      if (NDR.isNDR(fieldTypeOrClass)) {
        const ctor = fieldTypeOrClass as NDRConstructor;
        if (NDRCONSTRUCTEDTYPE.isPointer(fieldTypeOrClass)) {
          this.fields[fieldName] = new ctor(null, this._isNDR64, topLevel);
        } else if (NDRCONSTRUCTEDTYPE.isUnion(fieldTypeOrClass)) {
          this.fields[fieldName] = new ctor(null, this._isNDR64, topLevel);
        } else {
          this.fields[fieldName] = new ctor(null, this._isNDR64);
        }
      } else if (fieldTypeOrClass === ':') {
        this.fields[fieldName] = null;
      } else if (typeof fieldTypeOrClass === 'string' && pySplit(fieldTypeOrClass, '=').length === 2) {
        const expr = pySplit(fieldTypeOrClass, '=')[1]!;
        try {
          this.fields[fieldName] = evalExpr(expr, {});
        } catch {
          this.fields[fieldName] = null;
        }
      } else {
        this.fields[fieldName] = 0;
      }
    }

    if (data) {
      this.fromString(data);
    }
  }

  set(key: string, value: unknown): void {
    if (key === 'tag') {
      this.structure = [];
      const cls = this.constructor as typeof NDRUNION;
      const tagVal = value as number;
      if (tagVal in cls.union) {
        const arm = cls.union[tagVal];
        if (arm) {
          this.structure = [arm];
        }
        this.reInit();
        (this.fields['tag'] as NDR).fields['Data'] = value;
      } else if ('default' in cls.union) {
        const def = cls.union['default'];
        if (def === null) {
          this.structure = [];
        } else {
          this.structure = [def!];
        }
        this.reInit();
        (this.fields['tag'] as NDR).fields['Data'] = 0xffff;
      } else {
        throw new Error(`Unknown tag ${tagVal} for union!`);
      }
    } else {
      super.set(key, value);
    }
  }

  protected reInit(): void {
    const cls = this.constructor as typeof NDRUNION;
    for (const [fieldName, fieldTypeOrClass] of [...this.commonHdr, ...this.structure, ...this.referent]) {
      if (NDR.isNDR(fieldTypeOrClass)) {
        const ctor = fieldTypeOrClass as NDRConstructor;
        if (NDRCONSTRUCTEDTYPE.isPointer(fieldTypeOrClass)) {
          this.fields[fieldName] = new ctor(null, this._isNDR64, this.topLevel);
        } else if (NDRCONSTRUCTEDTYPE.isUnion(fieldTypeOrClass)) {
          this.fields[fieldName] = new ctor(null, this._isNDR64, this.topLevel);
        } else {
          this.fields[fieldName] = new ctor(null, this._isNDR64);
        }
      } else if (fieldTypeOrClass === ':') {
        this.fields[fieldName] = null;
      } else if (typeof fieldTypeOrClass === 'string' && pySplit(fieldTypeOrClass, '=').length === 2) {
        const expr = pySplit(fieldTypeOrClass, '=')[1]!;
        try {
          this.fields[fieldName] = evalExpr(expr, {});
        } catch {
          this.fields[fieldName] = null;
        }
      } else {
        this.fields[fieldName] = 0;
      }
    }
  }

  getData(soFar = 0): Buffer {
    let data = Buffer.alloc(0);
    const soFar0 = soFar;

    const alignment = this.getAlignment();
    if (alignment > 0) {
      const pad = (alignment - (soFar % alignment)) % alignment;
      if (pad > 0) {
        soFar += pad;
        data = Buffer.concat([data, Buffer.alloc(pad)]);
      }
    }

    for (const [fieldName, fieldTypeOrClass] of this.commonHdr) {
      try {
        const pad = NDR.calculatePad(fieldTypeOrClass, soFar);
        if (pad > 0) {
          soFar += pad;
          data = Buffer.concat([data, Buffer.alloc(pad)]);
        }
        const res = this.pack(fieldName, fieldTypeOrClass, soFar);
        data = Buffer.concat([data, res]);
        soFar = soFar0 + data.length;
      } catch (e) {
        throw new Error(
          `Error packing field '${fieldName} | ${fieldTypeOrClass}' in ${this.constructor.name}: ${(e as Error).message}`,
        );
      }
    }

    const cls = this.constructor as typeof NDRUNION;
    const align = this._isNDR64 ? 8 : ('notAlign' in cls ? 1 : 4);
    const pad = (align - (soFar % align)) % align;
    if (pad > 0) {
      data = Buffer.concat([data, Buffer.alloc(pad)]);
      soFar += pad;
    }

    if (this.structure.length === 0) {
      return data;
    }

    for (const [fieldName, fieldTypeOrClass] of this.structure) {
      try {
        const pad2 = NDR.calculatePad(fieldTypeOrClass, soFar);
        if (pad2 > 0) {
          soFar += pad2;
          data = Buffer.concat([data, Buffer.alloc(pad2)]);
        }
        const res = this.pack(fieldName, fieldTypeOrClass, soFar);
        data = Buffer.concat([data, res]);
        soFar = soFar0 + data.length;
      } catch (e) {
        throw new Error(
          `Error packing field '${fieldName} | ${fieldTypeOrClass}' in ${this.constructor.name}: ${(e as Error).message}`,
        );
      }
    }

    return data;
  }

  fromString(data: Buffer, offset = 0): number {
    const offset0 = offset;
    const alignment = this.getAlignment();
    if (alignment > 0) {
      offset += (alignment - (offset % alignment)) % alignment;
    }

    const cls = this.constructor as typeof NDRUNION;
    if (data.length - offset > 4) {
      const tagFieldType = this.commonHdr[0]![1];
      let tagFmt: string;
      if (typeof tagFieldType === 'string') {
        tagFmt = pySplit(tagFieldType, '=')[0]!;
      } else {
        const tagCtor = tagFieldType as typeof NDR;
        tagFmt = pySplit(tagCtor.structure[0]![1] as string, '=')[0]!;
      }
      const tag = structUnpack(tagFmt, data.subarray(offset)) as number;
      if (tag in cls.union) {
        const arm = cls.union[tag];
        this.structure = arm ? [arm] : [];
        this.reInit();
      } else if ('default' in cls.union) {
        const def = cls.union['default'];
        this.structure = def ? [def!] : [];
        this.reInit();
        (this.fields['tag'] as NDR).fields['Data'] = 0xffff;
      } else {
        throw new Error(`Unknown tag ${tag} for union!`);
      }
    }

    for (const [fieldName, fieldTypeOrClass] of this.commonHdr) {
      try {
        offset += NDR.calculatePad(fieldTypeOrClass, offset);
        offset += this.unpack(fieldName, fieldTypeOrClass, data, offset);
      } catch (e) {
        throw new Error(
          `Error unpacking field '${fieldName} | ${fieldTypeOrClass}': ${(e as Error).message}`,
        );
      }
    }

    const align = this._isNDR64 ? 8 : ('notAlign' in cls ? 1 : 4);
    offset += (align - (offset % align)) % align;

    if (this.structure.length === 0) {
      return offset - offset0;
    }

    for (const [fieldName, fieldTypeOrClass] of this.structure) {
      try {
        offset += NDR.calculatePad(fieldTypeOrClass, offset);
        offset += this.unpack(fieldName, fieldTypeOrClass, data, offset);
      } catch (e) {
        throw new Error(
          `Error unpacking field '${fieldName} | ${fieldTypeOrClass}': ${(e as Error).message}`,
        );
      }
    }

    return offset - offset0;
  }

  getAlignment(): number {
    let align = 0;
    const fields = this._isNDR64 ? [...this.commonHdr, ...this.structure] : [...this.commonHdr];
    for (const [fieldName, fieldTypeOrClass] of fields) {
      if (this.fields[fieldName] instanceof NDR) {
        const tmp = (this.fields[fieldName] as NDR).getAlignment();
        if (tmp > align) align = tmp;
      } else {
        const tmp = this.calcPackSize(fieldTypeOrClass, Buffer.alloc(0));
        if (tmp > align) align = tmp;
      }
    }
    return align;
  }
}

export class NDRPOINTERNULL extends NDR {
  static align = 4;
  static align64 = 8;
  static structure: NDRField[] = [['Data', '<L=0']];
  static structure64: NDRField[] = [['Data', '<Q=0']];
}

export const NULL = new NDRPOINTERNULL();

export class NDRPOINTER extends NDRSTRUCT {
  static align = 4;
  static align64 = 8;
  static commonHdr: NDRField[] = [['ReferentID', '<L=0xff']];
  static commonHdr64: NDRField[] = [['ReferentID', '<Q=0xff']];
  static referent: NDRField[] = [['Data', ':']];

  topLevel = false;

  constructor(data?: Buffer | null, isNDR64 = false, topLevel = false) {
    super(null, isNDR64);
    this.topLevel = topLevel;

    if (topLevel) {
      this.structure = [...this.referent];
      this.referent = [];
      for (const [fieldName, fieldTypeOrClass] of this.structure) {
        if (NDR.isNDR(fieldTypeOrClass)) {
          const ctor = fieldTypeOrClass as NDRConstructor;
          this.fields[fieldName] = new ctor(null, this._isNDR64, false);
        } else if (fieldTypeOrClass === ':') {
          this.fields[fieldName] = Buffer.alloc(0);
        } else if (typeof fieldTypeOrClass === 'string' && pySplit(fieldTypeOrClass, '=').length === 2) {
          const expr = pySplit(fieldTypeOrClass, '=')[1]!;
          try {
            this.fields[fieldName] = evalExpr(expr, {});
          } catch {
            this.fields[fieldName] = null;
          }
        } else {
          this.fields[fieldName] = 0;
        }
      }
    }

    if (data == null) {
      this.fields['ReferentID'] = randomInt(1, 65536);
    } else {
      this.fromString(data);
    }
  }

  set(key: string, value: unknown): void {
    if (!(key in this.fields)) {
      const dataField = this.fields['Data'] as NDR;
      dataField.set(key, value);
    } else {
      super.set(key, value);
    }
  }

  get(key: string): unknown {
    if (key in this.fields) {
      const val = this.fields[key];
      if (val instanceof NDR && 'Data' in (val as NDR).fields) {
        let cur: NDR = val as NDR;
        while (true) {
          const next = cur.fields['Data'];
          if (next instanceof NDR && 'Data' in next.fields) {
            cur = next;
            continue;
          }
          return cur.get('Data');
        }
      }
      return val;
    }
    const dataField = this.fields['Data'] as NDR;
    return dataField.get(key);
  }

  getData(soFar = 0): Buffer {
    let data = Buffer.alloc(0);
    const pad = NDR.calculatePad(this.commonHdr[0]![1]!, soFar);
    if (pad > 0) {
      soFar += pad;
      data = Buffer.alloc(pad);
    }

    if (this.fields['ReferentID'] === 0) {
      if (this.referent.length > 0) {
        this.fields['Data'] = Buffer.alloc(0);
      } else {
        return Buffer.concat([data, Buffer.alloc(this._isNDR64 ? 8 : 4, 0)]);
      }
    }

    return Buffer.concat([data, super.getData(soFar)]);
  }

  fromString(data: Buffer, offset = 0): number {
    const pad = NDR.calculatePad(this.commonHdr[0]![1]!, offset);
    offset += pad;

    const unpackStr = this._isNDR64 ? '<Q' : '<L';
    const refId = structUnpack(unpackStr, data.subarray(offset)) as number;
    if (refId === 0) {
      this.set('ReferentID', 0);
      this.fields['Data'] = Buffer.alloc(0);
      return pad + (this._isNDR64 ? 8 : 4);
    }

    const retVal = super.fromString(data, offset);
    return retVal + pad;
  }

  getAlignment(): number {
    return this._isNDR64 ? 8 : 4;
  }
}

export class PNDRUniConformantVaryingArray extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NDRUniConformantVaryingArray]];
}

export class PNDRUniConformantArray extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NDRUniConformantArray]];
}

export class NDRCALL extends NDRCONSTRUCTEDTYPE {
  static align = 4;

  constructor(data?: Buffer | null, isNDR64 = false) {
    super(null, isNDR64);
    this._isNDR64 = isNDR64;
    this.fields = {};

    const cls = this.constructor as typeof NDR;
    if (isNDR64) {
      if (cls.commonHdr64.length > 0) this.commonHdr = [...cls.commonHdr64];
      if (cls.structure64.length > 0) this.structure = [...cls.structure64];
      if (cls.align64) this.align = cls.align64;
    }

    for (const [fieldName, fieldTypeOrClass] of [...this.commonHdr, ...this.structure, ...this.referent]) {
      if (NDR.isNDR(fieldTypeOrClass)) {
        const ctor = fieldTypeOrClass as NDRConstructor;
        if (NDRCONSTRUCTEDTYPE.isPointer(fieldTypeOrClass)) {
          this.fields[fieldName] = new ctor(null, this._isNDR64, true);
        } else if (NDRCONSTRUCTEDTYPE.isUnion(fieldTypeOrClass)) {
          this.fields[fieldName] = new ctor(null, this._isNDR64, true);
        } else {
          this.fields[fieldName] = new ctor(null, this._isNDR64);
        }
      } else if (fieldTypeOrClass === ':') {
        this.fields[fieldName] = null;
      } else if (typeof fieldTypeOrClass === 'string' && pySplit(fieldTypeOrClass, '=').length === 2) {
        const expr = pySplit(fieldTypeOrClass, '=')[1]!;
        try {
          this.fields[fieldName] = evalExpr(expr, {});
        } catch {
          this.fields[fieldName] = null;
        }
      } else {
        this.fields[fieldName] = 0;
      }
    }

    if (data) {
      this.fromString(data);
    }
  }

  getData(soFar = 0): Buffer {
    let data = Buffer.alloc(0);
    const soFar0 = soFar;
    for (const [fieldName, fieldTypeOrClass] of [...this.commonHdr, ...this.structure]) {
      try {
        const pad = NDR.calculatePad(fieldTypeOrClass, soFar);
        if (pad > 0) {
          soFar += pad;
          data = Buffer.concat([data, Buffer.alloc(pad)]);
        }

        if (
          this.fields[fieldName] instanceof NDRUniConformantArray ||
          this.fields[fieldName] instanceof NDRUniConformantVaryingArray
        ) {
          const padSize = this._isNDR64
            ? (8 - (soFar % 8)) % 8
            : (4 - (soFar % 4)) % 4;
          const res = this.pack(fieldName, fieldTypeOrClass, soFar + padSize);
          const arraySize = this.getArrayMaximumSize(fieldName);
          const packStr = this._isNDR64 ? '<Q' : '<L';
          data = Buffer.concat([data, Buffer.alloc(padSize), structPack(packStr, arraySize), res]);
        } else {
          data = Buffer.concat([data, this.pack(fieldName, fieldTypeOrClass, soFar)]);
        }

        soFar = soFar0 + data.length;

        if (this.fields[fieldName] instanceof NDRCONSTRUCTEDTYPE) {
          const child = this.fields[fieldName] as NDRCONSTRUCTEDTYPE;
          data = Buffer.concat([data, child.getDataReferents(soFar)]);
          soFar = soFar0 + data.length;
          data = Buffer.concat([data, child.getDataReferent(soFar)]);
          soFar = soFar0 + data.length;
        }
      } catch (e) {
        throw new Error(
          `Error packing field '${fieldName} | ${fieldTypeOrClass}' in ${this.constructor.name}: ${(e as Error).message}`,
        );
      }
    }
    return data;
  }

  fromString(data: Buffer, offset = 0): number {
    const offset0 = offset;
    for (const [fieldName, fieldTypeOrClass] of [...this.commonHdr, ...this.structure]) {
      try {
        if (
          this.fields[fieldName] instanceof NDRUniConformantArray ||
          this.fields[fieldName] instanceof NDRUniConformantVaryingArray
        ) {
          const [arraySize, advanceStream] = this.getArraySize(fieldName, data, offset);
          (this.fields[fieldName] as NDRArray).setArraySize(arraySize);
          offset += advanceStream;
        }

        let size = this.unpack(fieldName, fieldTypeOrClass, data, offset);

        if (this.fields[fieldName] instanceof NDRCONSTRUCTEDTYPE) {
          const child = this.fields[fieldName] as NDRCONSTRUCTEDTYPE;
          size += child.fromStringReferents(data, offset + size);
          size += child.fromStringReferent(data, offset + size);
        }
        offset += size;
      } catch (e) {
        throw new Error(
          `Error unpacking field '${fieldName} | ${fieldTypeOrClass}': ${(e as Error).message}`,
        );
      }
    }
    return offset - offset0;
  }
}

export type NDRTLSTRUCT = NDRCALL;

export class UNKNOWNDATA extends NDR {
  static align = 1;
  static structure: NDRField[] = [['Data', ':']];
}

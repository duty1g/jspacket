// Impacket - Collection of TypeScript classes for working with network protocols.
//
// Copyright Fortra, LLC and its affiliated companies
//
// All rights reserved.
//
// Description:
//   [MS-WMI]/[MS-WMIO] : Windows Management Instrumentation Remote Protocol.
//   Partial implementation.
//
//   Port of impacket/dcerpc/v5/dcom/wmi.py to TypeScript.

import { Buffer } from 'node:buffer';
import { stringToBin, uuidtupToBin } from '@impacket/uuid';
import { Structure, type FieldDescriptor, calcsize, structPack, structUnpack, hexdump } from '@impacket/structure';
import {
  NDRSTRUCT,
  NDRUniConformantArray,
  NDRUniConformantVaryingArray,
  NDRPOINTER,
  NDRUNION,
  NDRENUM,
  NDRCALL,
  NULL,
  type NDRField,
} from '../ndr';
import {
  DCOMCALL,
  DCOMANSWER,
  IRemUnknown,
  PMInterfacePointer,
  PMInterfacePointer_ARRAY,
  PPMInterfacePointer,
  INTERFACE,
  OBJREF_CUSTOM,
} from '../dcomrt';
import {
  ULONG,
  DWORD,
  LPWSTR,
  LONG,
  HRESULT,
  PGUID,
  LPCSTR,
  GUID,
} from '../dtypes';
import { DCERPCException } from '../rpcrt';
import { FLAGGED_WORD_BLOB } from './oaut';

// ============================================================================
// Utility
// ============================================================================
function formatStructure(d: unknown, level = 0): string {
  let x = '';
  if (d && typeof d === 'object' && !Array.isArray(d) && !(d instanceof Buffer)) {
    const entries = Object.entries(d as Record<string, unknown>);
    const lenk = entries.length > 0 ? Math.max(...entries.map(([k]) => k.length)) : 0;
    for (const [k, v] of entries) {
      const keyText = '\n' + ' '.repeat(level) + ' '.repeat(lenk - k.length) + k;
      x += keyText + ': ' + formatStructure(v, level + lenk);
    }
  } else if (Array.isArray(d)) {
    for (const e of d) {
      x += '\n' + ' '.repeat(level) + '- ' + formatStructure(e, level + 4);
    }
  } else {
    x = String(d);
  }
  return x;
}

// ============================================================================
// DCERPCSessionError (module-private per collision rules)
// ============================================================================
class DCERPCSessionError extends DCERPCException {
  constructor(errorString?: string | null, errorCode?: number | null, packet?: unknown) {
    super(errorString, errorCode, packet);
  }

  toString(): string {
    const code = this.error_code ?? 0;
    return `WMI SessionError: unknown error code: 0x${code.toString(16)}`;
  }
}

// ============================================================================
// WMIO Structures and Constants
// ============================================================================
export const WBEM_FLAVOR_FLAG_PROPAGATE_O_INSTANCE = 0x01;
export const WBEM_FLAVOR_FLAG_PROPAGATE_O_DERIVED_CLASS = 0x02;
export const WBEM_FLAVOR_NOT_OVERRIDABLE = 0x10;
export const WBEM_FLAVOR_ORIGIN_PROPAGATED = 0x20;
export const WBEM_FLAVOR_ORIGIN_SYSTEM = 0x40;
export const WBEM_FLAVOR_AMENDED = 0x80;

// 2.2.6 ObjectFlags
const OBJECT_FLAGS = 'B=0';

// 2.2.77 Signature
const SIGNATURE = '<L=0x12345678';

// 2.2.4 ObjectEncodingLength
const OBJECT_ENCODING_LENGTH = '<L=0';

// 2.2.73 EncodingLength
const ENCODING_LENGTH = '<L=0';

// 2.2.78 Encoded-String
const ENCODED_STRING_FLAG = 'B=0';

// 2.2.76 ReservedOctet
const RESERVED_OCTET = 'B=0';

// 2.2.28 NdTableValueTableLength
const NDTABLE_VALUE_TABLE_LENGTH = '<L=0';

// 2.2.80 DictionaryReference
export const DICTIONARY_REFERENCE: Record<number, string> = {
  0: '"',
  1: 'key',
  2: 'NADA',
  3: 'read',
  4: 'write',
  5: 'volatile',
  6: 'provider',
  7: 'dynamic',
  8: 'cimwin32',
  9: 'DWORD',
  10: 'CIMTYPE',
};

// 2.2.78 Encoded-String
export class ENCODED_STRING extends Structure {
  static commonHdr: FieldDescriptor[] = [
    ['Encoded_String_Flag', ENCODED_STRING_FLAG],
  ];

  static tascii: FieldDescriptor[] = [
    ['Character', 'z'],
  ];

  static tunicode: FieldDescriptor[] = [
    ['Character', 'u'],
  ];

  isUnicode = false;

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    if (data != null) {
      this.fromString(data);
      this.structure = [];
      this.isUnicode = false;
      if (data.length > 1) {
        if ((this as any)['Encoded_String_Flag'] === 0) {
          this.structure = [...(this.constructor as typeof ENCODED_STRING).tascii];
          // Search for end of string
          const idx = data.subarray(1).indexOf(0);
          if (idx >= 0) {
            data = data.subarray(0, idx + 1 + 1);
          }
        } else {
          this.structure = [...(this.constructor as typeof ENCODED_STRING).tunicode];
          this.isUnicode = true;
        }
        this.fromString(data);
      }
    } else {
      this.structure = [...(this.constructor as typeof ENCODED_STRING).tascii];
      this.data = null;
    }
  }

  getItem(key: string): unknown {
    if (key === 'Character' && this.isUnicode) {
      const val = this.fields['Character'];
      if (Buffer.isBuffer(val)) {
        return val.toString('utf16le');
      }
      return val;
    }
    return this.fields[key];
  }
}

// 2.2.8 DecServerName
const DEC_SERVER_NAME = ENCODED_STRING;

// 2.2.9 DecNamespaceName
const DEC_NAMESPACE_NAME = ENCODED_STRING;

// 2.2.7 Decoration
export class DECORATION extends Structure {
  static structure: FieldDescriptor[] = [
    ['DecServerName', ':', DEC_SERVER_NAME],
    ['DecNamespaceName', ':', DEC_NAMESPACE_NAME],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
  }
}

// 2.2.69 HeapRef
const HEAPREF = '<L=0';

// 2.2.68 HeapStringRef
const HEAP_STRING_REF = HEAPREF;

// 2.2.19 ClassNameRef
const CLASS_NAME_REF = HEAP_STRING_REF;

// 2.2.16 ClassHeader
export class CLASS_HEADER extends Structure {
  static structure: FieldDescriptor[] = [
    ['EncodingLength', ENCODING_LENGTH],
    ['ReservedOctet', RESERVED_OCTET],
    ['ClassNameRef', CLASS_NAME_REF],
    ['NdTableValueTableLength', NDTABLE_VALUE_TABLE_LENGTH],
  ];
}

// 2.2.17 DerivationList
export class DERIVATION_LIST extends Structure {
  static structure: FieldDescriptor[] = [
    ['EncodingLength', ENCODING_LENGTH],
    ['_ClassNameEncoding', '_-ClassNameEncoding', 'self["EncodingLength"]-4'],
    ['ClassNameEncoding', ':'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
  }
}

// 2.2.82 CimType
const CIM_TYPE = '<L=0';
export const CIM_ARRAY_FLAG = 0x2000;

// CIM_TYPE_ENUM - using plain numeric constants instead of Python's Enum
export const CIM_TYPE_ENUM = {
  CIM_TYPE_SINT8: 16,
  CIM_TYPE_UINT8: 17,
  CIM_TYPE_SINT16: 2,
  CIM_TYPE_UINT16: 18,
  CIM_TYPE_SINT32: 3,
  CIM_TYPE_UINT32: 19,
  CIM_TYPE_SINT64: 20,
  CIM_TYPE_UINT64: 21,
  CIM_TYPE_REAL32: 4,
  CIM_TYPE_REAL64: 5,
  CIM_TYPE_BOOLEAN: 11,
  CIM_TYPE_STRING: 8,
  CIM_TYPE_DATETIME: 101,
  CIM_TYPE_REFERENCE: 102,
  CIM_TYPE_CHAR16: 103,
  CIM_TYPE_OBJECT: 13,
  CIM_ARRAY_SINT8: 8208,
  CIM_ARRAY_UINT8: 8209,
  CIM_ARRAY_SINT16: 8194,
  CIM_ARRAY_UINT16: 8210,
  CIM_ARRAY_SINT32: 8195,
  CIM_ARRAY_UINT32: 8201,
  CIM_ARRAY_SINT64: 8202,
  CIM_ARRAY_UINT64: 8203,
  CIM_ARRAY_REAL32: 8196,
  CIM_ARRAY_REAL64: 8197,
  CIM_ARRAY_BOOLEAN: 8203,
  CIM_ARRAY_STRING: 8200,
  CIM_ARRAY_DATETIME: 8293,
  CIM_ARRAY_REFERENCE: 8294,
  CIM_ARRAY_CHAR16: 8295,
  CIM_ARRAY_OBJECT: 8205,
} as const;

export const CIM_TYPES_REF: Record<number, string> = {
  [CIM_TYPE_ENUM.CIM_TYPE_SINT8]: 'b=0',
  [CIM_TYPE_ENUM.CIM_TYPE_UINT8]: 'B=0',
  [CIM_TYPE_ENUM.CIM_TYPE_SINT16]: '<h=0',
  [CIM_TYPE_ENUM.CIM_TYPE_UINT16]: '<H=0',
  [CIM_TYPE_ENUM.CIM_TYPE_SINT32]: '<l=0',
  [CIM_TYPE_ENUM.CIM_TYPE_UINT32]: '<L=0',
  [CIM_TYPE_ENUM.CIM_TYPE_SINT64]: '<q=0',
  [CIM_TYPE_ENUM.CIM_TYPE_UINT64]: '<Q=0',
  [CIM_TYPE_ENUM.CIM_TYPE_REAL32]: '<f=0',
  [CIM_TYPE_ENUM.CIM_TYPE_REAL64]: '<d=0',
  [CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN]: '<H=0',
  [CIM_TYPE_ENUM.CIM_TYPE_STRING]: HEAPREF,
  [CIM_TYPE_ENUM.CIM_TYPE_DATETIME]: HEAPREF,
  [CIM_TYPE_ENUM.CIM_TYPE_REFERENCE]: HEAPREF,
  [CIM_TYPE_ENUM.CIM_TYPE_CHAR16]: '<H=0',
  [CIM_TYPE_ENUM.CIM_TYPE_OBJECT]: HEAPREF,
};

export const CIM_TYPE_TO_NAME: Record<number, string> = {
  [CIM_TYPE_ENUM.CIM_TYPE_SINT8]: 'sint8',
  [CIM_TYPE_ENUM.CIM_TYPE_UINT8]: 'uint8',
  [CIM_TYPE_ENUM.CIM_TYPE_SINT16]: 'sint16',
  [CIM_TYPE_ENUM.CIM_TYPE_UINT16]: 'uint16',
  [CIM_TYPE_ENUM.CIM_TYPE_SINT32]: 'sint32',
  [CIM_TYPE_ENUM.CIM_TYPE_UINT32]: 'uint32',
  [CIM_TYPE_ENUM.CIM_TYPE_SINT64]: 'sint64',
  [CIM_TYPE_ENUM.CIM_TYPE_UINT64]: 'uint64',
  [CIM_TYPE_ENUM.CIM_TYPE_REAL32]: 'real32',
  [CIM_TYPE_ENUM.CIM_TYPE_REAL64]: 'real64',
  [CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN]: 'bool',
  [CIM_TYPE_ENUM.CIM_TYPE_STRING]: 'string',
  [CIM_TYPE_ENUM.CIM_TYPE_DATETIME]: 'datetime',
  [CIM_TYPE_ENUM.CIM_TYPE_REFERENCE]: 'reference',
  [CIM_TYPE_ENUM.CIM_TYPE_CHAR16]: 'char16',
  [CIM_TYPE_ENUM.CIM_TYPE_OBJECT]: 'object',
};

export const CIM_NUMBER_TYPES: number[] = [
  CIM_TYPE_ENUM.CIM_TYPE_CHAR16,
  CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN,
  CIM_TYPE_ENUM.CIM_TYPE_SINT8,
  CIM_TYPE_ENUM.CIM_TYPE_UINT8,
  CIM_TYPE_ENUM.CIM_TYPE_SINT16,
  CIM_TYPE_ENUM.CIM_TYPE_UINT16,
  CIM_TYPE_ENUM.CIM_TYPE_SINT32,
  CIM_TYPE_ENUM.CIM_TYPE_UINT32,
  CIM_TYPE_ENUM.CIM_TYPE_SINT64,
  CIM_TYPE_ENUM.CIM_TYPE_UINT64,
  CIM_TYPE_ENUM.CIM_TYPE_REAL32,
  CIM_TYPE_ENUM.CIM_TYPE_REAL64,
];

// 2.2.61 QualifierName
const QUALIFIER_NAME = HEAP_STRING_REF;

// 2.2.62 QualifierFlavor
const QUALIFIER_FLAVOR = 'B=0';

// 2.2.63 QualifierType
const QUALIFIER_TYPE = CIM_TYPE;

// 2.2.32 Inherited
export const Inherited = 0x4000;

// 2.2.71 EncodedValue
export class ENCODED_VALUE extends Structure {
  static structure: FieldDescriptor[] = [
    ['QualifierName', QUALIFIER_NAME],
  ];

  static getValue(cimType: number, entry: number | bigint, heap: Buffer): unknown {
    const pType = cimType & (~(CIM_ARRAY_FLAG | Inherited));
    cimType = cimType & (~Inherited);
    // eslint-disable-next-line eqeqeq
    if (entry != 0xffffffff) {
      const entryNum = Number(entry);
      let heapData = heap.subarray(entryNum);
      if (cimType & CIM_ARRAY_FLAG) {
        const dataSize = calcsize(HEAPREF.replace(/=.*$/, ''));
        const numItems = (structUnpack(HEAPREF.replace(/=.*$/, ''), heapData.subarray(0, dataSize)) as number);
        heapData = heapData.subarray(dataSize);
        const array: unknown[] = [];
        const unpackStrArray = CIM_TYPES_REF[pType]!.replace(/=.*$/, '');
        const dataSizeArray = calcsize(unpackStrArray);
        if (cimType === CIM_TYPE_ENUM.CIM_ARRAY_STRING) {
          // Array of strings - skip DWORD pointers
          heapData = heapData.subarray(4 * numItems);
          for (let i = 0; i < numItems; i++) {
            const item = new ENCODED_STRING(heapData);
            array.push(item.getItem('Character'));
            heapData = heapData.subarray(item.getData().length);
          }
        } else if (cimType === CIM_TYPE_ENUM.CIM_ARRAY_OBJECT) {
          heapData = heapData.subarray(dataSize * numItems);
          for (let i = 0; i < numItems; i++) {
            const msb = new METHOD_SIGNATURE_BLOCK(heapData);
            const unit = new ENCODING_UNIT();
            (unit as any)['ObjectEncodingLength'] = (msb as any)['EncodingLength'];
            (unit as any)['ObjectBlock'] = (msb as any)['ObjectBlock'];
            array.push(unit);
            heapData = heapData.subarray(((msb as any)['EncodingLength'] as number) + 4);
          }
        } else {
          for (let i = 0; i < numItems; i++) {
            array.push(structUnpack(unpackStrArray, heapData.subarray(0, dataSizeArray)));
            heapData = heapData.subarray(dataSizeArray);
          }
        }
        return array;
      } else if (pType === CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN) {
        // eslint-disable-next-line eqeqeq
        if (entry == 0xffff) {
          return 'True';
        } else {
          return 'False';
        }
      } else if (pType === CIM_TYPE_ENUM.CIM_TYPE_OBJECT) {
        const msb = new METHOD_SIGNATURE_BLOCK(heapData);
        const unit = new ENCODING_UNIT();
        (unit as any)['ObjectEncodingLength'] = (msb as any)['EncodingLength'];
        (unit as any)['ObjectBlock'] = (msb as any)['ObjectBlock'];
        return unit;
      } else if (
        pType !== CIM_TYPE_ENUM.CIM_TYPE_STRING &&
        pType !== CIM_TYPE_ENUM.CIM_TYPE_DATETIME &&
        pType !== CIM_TYPE_ENUM.CIM_TYPE_REFERENCE
      ) {
        return entry;
      } else {
        return new ENCODED_STRING(heapData).getItem('Character');
      }
    }
    return null;
  }
}

// 2.2.64 QualifierValue
const QUALIFIER_VALUE = ENCODED_VALUE;

// 2.2.60 Qualifier
export class QUALIFIER extends Structure {
  static commonHdr: FieldDescriptor[] = [
    ['QualifierName', QUALIFIER_NAME],
    ['QualifierFlavor', QUALIFIER_FLAVOR],
    ['QualifierType', QUALIFIER_TYPE],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    if (data != null) {
      this.fromString(data);
      const qType = (this as any)['QualifierType'] as number;
      this.structure = [['QualifierValue', CIM_TYPES_REF[qType & (~CIM_ARRAY_FLAG)]!]];
      this.fromString(data);
    } else {
      this.data = null;
    }
  }
}

// 2.2.59 QualifierSet
export class QUALIFIER_SET extends Structure {
  static structure: FieldDescriptor[] = [
    ['EncodingLength', ENCODING_LENGTH],
    ['_Qualifier', '_-Qualifier', 'self["EncodingLength"]-4'],
    ['Qualifier', ':'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
  }

  getQualifiers(heap: Buffer): Record<string, unknown> {
    let data = (this as any)['Qualifier'] as Buffer;
    const qualifiers: Record<string, unknown> = {};
    while (data.length > 0) {
      const itemn = new QUALIFIER(data);
      let qName: string;
      const nameRef = (itemn as any)['QualifierName'] as number;
      if (nameRef === 0xffffffff) {
        qName = '';
      } else if (nameRef & 0x80000000) {
        qName = DICTIONARY_REFERENCE[nameRef & 0x7fffffff] ?? '';
      } else {
        qName = new ENCODED_STRING(heap.subarray(nameRef)).getItem('Character') as string;
      }
      const value = ENCODED_VALUE.getValue(
        (itemn as any)['QualifierType'] as number,
        (itemn as any)['QualifierValue'] as number,
        heap,
      );
      qualifiers[qName] = value;
      data = data.subarray(itemn.getData().length);
    }
    return qualifiers;
  }
}

// 2.2.20 ClassQualifierSet
const CLASS_QUALIFIER_SET = QUALIFIER_SET;

// 2.2.22 PropertyCount
const PROPERTY_COUNT = '<L=0';

// 2.2.24 PropertyNameRef
const PROPERTY_NAME_REF = HEAP_STRING_REF;

// 2.2.25 PropertyInfoRef
const PROPERTY_INFO_REF = HEAPREF;

// 2.2.23 PropertyLookup
export class PropertyLookup extends Structure {
  static structure: FieldDescriptor[] = [
    ['PropertyNameRef', PROPERTY_NAME_REF],
    ['PropertyInfoRef', PROPERTY_INFO_REF],
  ];
}

// 2.2.31 PropertyType
const PROPERTY_TYPE = '<L=0';

// 2.2.33 DeclarationOrder
const DECLARATION_ORDER = '<H=0';

// 2.2.34 ValueTableOffset
const VALUE_TABLE_OFFSET = '<L=0';

// 2.2.35 ClassOfOrigin
const CLASS_OF_ORIGIN = '<L=0';

// 2.2.36 PropertyQualifierSet
const PROPERTY_QUALIFIER_SET = QUALIFIER_SET;

// 2.2.30 PropertyInfo
export class PROPERTY_INFO extends Structure {
  static structure: FieldDescriptor[] = [
    ['PropertyType', PROPERTY_TYPE],
    ['DeclarationOrder', DECLARATION_ORDER],
    ['ValueTableOffset', VALUE_TABLE_OFFSET],
    ['ClassOfOrigin', CLASS_OF_ORIGIN],
    ['PropertyQualifierSet', ':', PROPERTY_QUALIFIER_SET],
  ];
}

// Property item dict type
export interface PropertyItem {
  stype: string;
  name: string;
  type: number;
  order: number;
  inherited: number;
  value: unknown;
  qualifiers: Record<string, unknown>;
  null_default?: boolean;
  inherited_default?: boolean;
}

// 2.2.21 PropertyLookupTable
export class PROPERTY_LOOKUP_TABLE extends Structure {
  static PropertyLookupSize = new PropertyLookup().getData().length;

  static structure: FieldDescriptor[] = [
    ['PropertyCount', PROPERTY_COUNT],
    ['_PropertyLookup', '_-PropertyLookup', `self["PropertyCount"]*${PROPERTY_LOOKUP_TABLE.PropertyLookupSize}`],
    ['PropertyLookup', ':'],
  ];

  getProperties(heap: Buffer): Record<string, PropertyItem> {
    let propTable = (this as any)['PropertyLookup'] as Buffer;
    const properties: Record<string, PropertyItem> = {};
    const propCount = (this as any)['PropertyCount'] as number;
    for (let i = 0; i < propCount; i++) {
      const propItem = new PropertyLookup(propTable);
      let propName: string;
      const nameRef = (propItem as any)['PropertyNameRef'] as number;
      if (nameRef & 0x80000000) {
        propName = DICTIONARY_REFERENCE[nameRef & 0x7fffffff] ?? '';
      } else {
        propName = new ENCODED_STRING(heap.subarray(nameRef)).getItem('Character') as string;
      }
      const propInfo = new PROPERTY_INFO(heap.subarray((propItem as any)['PropertyInfoRef'] as number));
      let pType = (propInfo as any)['PropertyType'] as number;
      pType &= ~CIM_ARRAY_FLAG;
      pType &= ~Inherited;
      const sType = CIM_TYPE_TO_NAME[pType] ?? 'unknown';

      const propTypeNum = (propInfo as any)['PropertyType'] as number;
      const propItemDict: PropertyItem = {
        stype: sType,
        name: propName,
        type: propTypeNum,
        order: (propInfo as any)['DeclarationOrder'] as number,
        inherited: propTypeNum & Inherited,
        value: null,
        qualifiers: {},
      };
      propItemDict.inherited = propTypeNum & Inherited;

      const qualifiers: Record<string, unknown> = {};
      let qualifiersBuf = ((propInfo as any)['PropertyQualifierSet'] as any)['Qualifier'] as Buffer;
      while (qualifiersBuf.length > 0) {
        const record = new QUALIFIER(qualifiersBuf);
        let qualifierName: string;
        const qNameRef = (record as any)['QualifierName'] as number;
        if (qNameRef & 0x80000000) {
          qualifierName = DICTIONARY_REFERENCE[qNameRef & 0x7fffffff] ?? '';
        } else {
          qualifierName = new ENCODED_STRING(heap.subarray(qNameRef)).getItem('Character') as string;
        }
        const qualifierValue = ENCODED_VALUE.getValue(
          (record as any)['QualifierType'] as number,
          (record as any)['QualifierValue'] as number,
          heap,
        );
        qualifiersBuf = qualifiersBuf.subarray(record.getData().length);
        qualifiers[qualifierName] = qualifierValue;
      }
      propItemDict.qualifiers = qualifiers;
      properties[propName] = propItemDict;
      propTable = propTable.subarray(PROPERTY_LOOKUP_TABLE.PropertyLookupSize);
    }

    // Sort by order
    const sorted = Object.entries(properties).sort((a, b) => a[1].order - b[1].order);
    const result: Record<string, PropertyItem> = {};
    for (const [k, v] of sorted) {
      result[k] = v;
    }
    return result;
  }
}

// 2.2.66 Heap
const HEAP_LENGTH = '<L=0';

export class HEAP extends Structure {
  static structure: FieldDescriptor[] = [
    ['HeapLength', HEAP_LENGTH],
    ['_HeapItem', '_-HeapItem', 'self["HeapLength"]&0x7fffffff'],
    ['HeapItem', ':'],
  ];
}

// 2.2.37 ClassHeap
const CLASS_HEAP = HEAP;

// 2.2.15 ClassPart
export class CLASS_PART extends Structure {
  static commonHdr: FieldDescriptor[] = [
    ['ClassHeader', ':', CLASS_HEADER],
    ['DerivationList', ':', DERIVATION_LIST],
    ['ClassQualifierSet', ':', CLASS_QUALIFIER_SET],
    ['PropertyLookupTable', ':', PROPERTY_LOOKUP_TABLE],
    ['_NdTable_ValueTable', '_-NdTable_ValueTable', 'self["ClassHeader"]["NdTableValueTableLength"]'],
    ['NdTable_ValueTable', ':'],
    ['ClassHeap', ':', CLASS_HEAP],
    ['_Garbage', '_-Garbage', 'self["ClassHeader"]["EncodingLength"]-len(self)'],
    ['Garbage', ':=b""'],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
  }

  getQualifiers(): Record<string, unknown> {
    return ((this as any)['ClassQualifierSet'] as QUALIFIER_SET).getQualifiers(
      ((this as any)['ClassHeap'] as any)['HeapItem'] as Buffer,
    );
  }

  getProperties(): Record<string, PropertyItem> {
    const heap = ((this as any)['ClassHeap'] as any)['HeapItem'] as Buffer;
    const properties = ((this as any)['PropertyLookupTable'] as PROPERTY_LOOKUP_TABLE).getProperties(heap);
    const sortedProps = Object.keys(properties).sort((a, b) => properties[a]!.order - properties[b]!.order);
    const valueTableOff = Math.floor((Object.keys(properties).length - 1) / 4) + 1;
    let valueTable = ((this as any)['NdTable_ValueTable'] as Buffer).subarray(valueTableOff);

    for (const key of sortedProps) {
      const pType = properties[key]!.type & (~(CIM_ARRAY_FLAG | Inherited));
      let unpackStr: string;
      if (properties[key]!.type & CIM_ARRAY_FLAG) {
        unpackStr = HEAPREF.replace(/=.*$/, '');
      } else {
        unpackStr = CIM_TYPES_REF[pType]!.replace(/=.*$/, '');
      }
      const dataSize = calcsize(unpackStr);
      let itemValue: number | bigint;
      try {
        itemValue = structUnpack(unpackStr, valueTable.subarray(0, dataSize)) as number | bigint;
      } catch {
        itemValue = 0xffffffff;
      }

      // eslint-disable-next-line eqeqeq
      if (itemValue != 0xffffffff && itemValue > 0) {
        const value = ENCODED_VALUE.getValue(properties[key]!.type, itemValue, heap);
        properties[key]!.value = `${value}`;
      }
      valueTable = valueTable.subarray(dataSize);
    }
    return properties;
  }
}

// 2.2.39 MethodCount
const METHOD_COUNT = '<H=0';

// 2.2.40 MethodCountPadding
const METHOD_COUNT_PADDING = '<H=0';

// 2.2.42 MethodName
const METHOD_NAME = HEAP_STRING_REF;

// 2.2.43 MethodFlags
const METHOD_FLAGS = 'B=0';

// 2.2.44 MethodPadding
const METHOD_PADDING = "3s=b''";

// 2.2.45 MethodOrigin
const METHOD_ORIGIN = '<L=0';

// 2.2.47 HeapQualifierSetRef
const HEAP_QUALIFIER_SET_REF = HEAPREF;

// 2.2.46 MethodQualifiers
const METHOD_QUALIFIERS = HEAP_QUALIFIER_SET_REF;

// 2.2.51 HeapMethodSignatureBlockRef
const HEAP_METHOD_SIGNATURE_BLOCK_REF = HEAPREF;

// 2.2.50 MethodSignature
const METHOD_SIGNATURE = HEAP_METHOD_SIGNATURE_BLOCK_REF;

// 2.2.48 InputSignature
const INPUT_SIGNATURE = METHOD_SIGNATURE;

// 2.2.49 OutputSignature
const OUTPUT_SIGNATURE = METHOD_SIGNATURE;

// 2.2.52 MethodHeap
const METHOD_HEAP = HEAP;

// 2.2.41 MethodDescription
export class METHOD_DESCRIPTION extends Structure {
  static structure: FieldDescriptor[] = [
    ['MethodName', METHOD_NAME],
    ['MethodFlags', METHOD_FLAGS],
    ['MethodPadding', METHOD_PADDING],
    ['MethodOrigin', METHOD_ORIGIN],
    ['MethodQualifiers', METHOD_QUALIFIERS],
    ['InputSignature', INPUT_SIGNATURE],
    ['OutputSignature', OUTPUT_SIGNATURE],
  ];
}

// Method dict type
export interface MethodItem {
  name: string;
  origin: number;
  qualifiers?: Record<string, unknown>;
  InParams?: Record<string, PropertyItem> | null;
  InParamsRaw?: OBJECT_BLOCK | null;
  OutParams?: Record<string, PropertyItem> | null;
  OutParamsRaw?: OBJECT_BLOCK | null;
}

// 2.2.38 MethodsPart
export class METHODS_PART extends Structure {
  static MethodDescriptionSize = new METHOD_DESCRIPTION().getData().length;

  static structure: FieldDescriptor[] = [
    ['EncodingLength', ENCODING_LENGTH],
    ['MethodCount', METHOD_COUNT],
    ['MethodCountPadding', METHOD_COUNT_PADDING],
    ['_MethodDescription', '_-MethodDescription', `self["MethodCount"]*${METHODS_PART.MethodDescriptionSize}`],
    ['MethodDescription', ':'],
    ['MethodHeap', ':', METHOD_HEAP],
  ];

  getMethods(): Record<string, MethodItem> {
    const methods: Record<string, MethodItem> = {};
    let data = (this as any)['MethodDescription'] as Buffer;
    const heap = ((this as any)['MethodHeap'] as any)['HeapItem'] as Buffer;
    const methodCount = (this as any)['MethodCount'] as number;

    for (let i = 0; i < methodCount; i++) {
      const itemn = new METHOD_DESCRIPTION(data);
      const methodDict: MethodItem = {
        name: '',
        origin: 0,
      };

      methodDict.name = new ENCODED_STRING(heap.subarray((itemn as any)['MethodName'] as number)).getItem('Character') as string;
      methodDict.origin = (itemn as any)['MethodOrigin'] as number;

      if ((itemn as any)['MethodQualifiers'] !== 0xffffffff) {
        const qualifiersSet = new QUALIFIER_SET(heap.subarray((itemn as any)['MethodQualifiers'] as number));
        methodDict.qualifiers = qualifiersSet.getQualifiers(heap);
      }

      if ((itemn as any)['InputSignature'] !== 0xffffffff) {
        const inputSignature = new METHOD_SIGNATURE_BLOCK(heap.subarray((itemn as any)['InputSignature'] as number));
        if (((inputSignature as any)['EncodingLength'] as number) > 0) {
          methodDict.InParams = (((inputSignature as any)['ObjectBlock'] as OBJECT_BLOCK).fields['ClassType'] as any)['CurrentClass'].getProperties();
          methodDict.InParamsRaw = (inputSignature as any)['ObjectBlock'] as OBJECT_BLOCK;
        } else {
          methodDict.InParams = null;
        }
      }

      if ((itemn as any)['OutputSignature'] !== 0xffffffff) {
        const outputSignature = new METHOD_SIGNATURE_BLOCK(heap.subarray((itemn as any)['OutputSignature'] as number));
        if (((outputSignature as any)['EncodingLength'] as number) > 0) {
          methodDict.OutParams = (((outputSignature as any)['ObjectBlock'] as OBJECT_BLOCK).fields['ClassType'] as any)['CurrentClass'].getProperties();
          methodDict.OutParamsRaw = (outputSignature as any)['ObjectBlock'] as OBJECT_BLOCK;
        } else {
          methodDict.OutParams = null;
        }
      }

      data = data.subarray(itemn.getData().length);
      methods[methodDict.name] = methodDict;
    }
    return methods;
  }
}

// 2.2.14 ClassAndMethodsPart
export class CLASS_AND_METHODS_PART extends Structure {
  static structure: FieldDescriptor[] = [
    ['ClassPart', ':', CLASS_PART],
    ['MethodsPart', ':', METHODS_PART],
  ];

  getClassName(): string {
    const pClassName = ((this as any)['ClassPart'] as any)['ClassHeader']['ClassNameRef'] as number;
    const cHeap = ((this as any)['ClassPart'] as any)['ClassHeap']['HeapItem'] as Buffer;
    if (pClassName === 0xffffffff) {
      return 'None';
    } else {
      let className = new ENCODED_STRING(cHeap.subarray(pClassName)).getItem('Character') as string;
      let derivationList = ((this as any)['ClassPart'] as any)['DerivationList']['ClassNameEncoding'] as Buffer;
      while (derivationList.length > 0) {
        const superClassStr = new ENCODED_STRING(derivationList);
        const superClass = superClassStr.getItem('Character') as string;
        className += ` : ${superClass} `;
        derivationList = derivationList.subarray(superClassStr.getData().length + 4);
      }
      return className;
    }
  }

  getQualifiers(): Record<string, unknown> {
    return ((this as any)['ClassPart'] as CLASS_PART).getQualifiers();
  }

  getProperties(): Record<string, PropertyItem> {
    return ((this as any)['ClassPart'] as CLASS_PART).getProperties();
  }

  getMethods(): Record<string, MethodItem> {
    return ((this as any)['MethodsPart'] as METHODS_PART).getMethods();
  }
}

// 2.2.13 CurrentClass
let CURRENT_CLASS = CLASS_AND_METHODS_PART;

// 2.2.54 InstanceFlags
const INSTANCE_FLAGS = 'B=0';

// 2.2.55 InstanceClassName
const INSTANCE_CLASS_NAME = HEAP_STRING_REF;

// 2.2.27 NullAndDefaultFlag
const NULL_AND_DEFAULT_FLAG = 'B=0';

// 2.2.26 NdTable
const NDTABLE = NULL_AND_DEFAULT_FLAG;

export class CURRENT_CLASS_NO_METHODS extends CLASS_AND_METHODS_PART {
  static structure: FieldDescriptor[] = [
    ['ClassPart', ':', CLASS_PART],
  ];

  override getMethods(): Record<string, MethodItem> {
    return {};
  }
}

// 2.2.65 InstancePropQualifierSet
const INST_PROP_QUAL_SET_FLAG = 'B=0';

export class INSTANCE_PROP_QUALIFIER_SET extends Structure {
  static commonHdr: FieldDescriptor[] = [
    ['InstPropQualSetFlag', INST_PROP_QUAL_SET_FLAG],
  ];

  static tail: FieldDescriptor[] = [
    ['QualifierSet', ':', QUALIFIER_SET],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    this.structure = [];
    if (data != null) {
      this.fromString(data);
      if ((this as any)['InstPropQualSetFlag'] === 2) {
        throw new Error("self['InstPropQualSetFlag'] == 2");
      }
      this.fromString(data);
    } else {
      this.data = null;
    }
  }
}

// 2.2.57 InstanceQualifierSet
export class INSTANCE_QUALIFIER_SET extends Structure {
  static structure: FieldDescriptor[] = [
    ['QualifierSet', ':', QUALIFIER_SET],
    ['InstancePropQualifierSet', ':', INSTANCE_PROP_QUALIFIER_SET],
  ];
}

// 2.2.58 InstanceHeap
const INSTANCE_HEAP = HEAP;

// 2.2.53 InstanceType
export class INSTANCE_TYPE extends Structure {
  NdTableSize = 0;

  static commonHdr: FieldDescriptor[] = [
    ['CurrentClass', ':', CURRENT_CLASS_NO_METHODS],
    ['EncodingLength', ENCODING_LENGTH],
    ['InstanceFlags', INSTANCE_FLAGS],
    ['InstanceClassName', INSTANCE_CLASS_NAME],
    ['_NdTable_ValueTable', '_-NdTable_ValueTable',
      'self["CurrentClass"]["ClassPart"]["ClassHeader"]["NdTableValueTableLength"]'],
    ['NdTable_ValueTable', ':'],
    ['InstanceQualifierSet', ':', INSTANCE_QUALIFIER_SET],
    ['InstanceHeap', ':', INSTANCE_HEAP],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    this.structure = [];
    if (data != null) {
      this.fromString(data);
      this.NdTableSize = Math.floor(
        (((this as any)['CurrentClass'] as any)['ClassPart']['PropertyLookupTable']['PropertyCount'] as number - 1) / 4
      ) + 1;
      this.fromString(data);
    } else {
      this.data = null;
    }
  }

  private __processNdTable(properties: Record<string, PropertyItem>): number {
    const propCount = Object.keys(properties).length;
    const octetCount = Math.floor((propCount - 1) / 4) + 1;
    const packedNdTable = ((this as any)['NdTable_ValueTable'] as Buffer).subarray(0, octetCount);
    const unpackedNdTable: number[] = [];
    for (let i = 0; i < packedNdTable.length; i++) {
      const byte = packedNdTable[i]!;
      for (const shift of [0, 2, 4, 6]) {
        unpackedNdTable.push((byte >> shift) & 0b11);
      }
    }
    for (const key of Object.keys(properties)) {
      const ndEntry = unpackedNdTable[properties[key]!.order]!;
      properties[key]!.null_default = !!(ndEntry & 0b01);
      properties[key]!.inherited_default = !!(ndEntry & 0b10);
    }
    return octetCount;
  }

  private static __isNonNullNumber(prop: PropertyItem): boolean {
    return CIM_NUMBER_TYPES.includes(prop.type & ~Inherited) && !prop.null_default;
  }

  getValues(properties: Record<string, PropertyItem>): Record<string, PropertyItem> {
    const heap = ((this as any)['InstanceHeap'] as any)['HeapItem'] as Buffer;
    const valueTableOff = this.__processNdTable(properties);
    let valueTable = ((this as any)['NdTable_ValueTable'] as Buffer).subarray(valueTableOff);
    const sortedProps = Object.keys(properties).sort((a, b) => properties[a]!.order - properties[b]!.order);

    for (const key of sortedProps) {
      const pType = properties[key]!.type & (~(CIM_ARRAY_FLAG | Inherited));
      let unpackStr: string;
      if (properties[key]!.type & CIM_ARRAY_FLAG) {
        unpackStr = HEAPREF.replace(/=.*$/, '');
      } else {
        unpackStr = CIM_TYPES_REF[pType]!.replace(/=.*$/, '');
      }
      const dataSize = calcsize(unpackStr);
      let itemValue: number | bigint;
      try {
        itemValue = structUnpack(unpackStr, valueTable.subarray(0, dataSize)) as number | bigint;
      } catch {
        itemValue = 0xffffffff;
      }

      // eslint-disable-next-line eqeqeq
      if (itemValue != 0 || INSTANCE_TYPE.__isNonNullNumber(properties[key]!)) {
        const value = ENCODED_VALUE.getValue(properties[key]!.type, itemValue, heap);
        properties[key]!.value = value;
      } else if (properties[key]!.inherited === 0) {
        properties[key]!.value = null;
      }
      valueTable = valueTable.subarray(dataSize);
    }
    return properties;
  }
}

// 2.2.12 ParentClass
const PARENT_CLASS = CLASS_AND_METHODS_PART;

// Re-assign CurrentClass
CURRENT_CLASS = CLASS_AND_METHODS_PART;

export class CLASS_TYPE extends Structure {
  static structure: FieldDescriptor[] = [
    ['ParentClass', ':', PARENT_CLASS],
    ['CurrentClass', ':', CURRENT_CLASS],
  ];
}

// Parsed class dict
export interface ParsedClass {
  name: string;
  qualifiers: Record<string, unknown>;
  properties: Record<string, PropertyItem>;
  methods: Record<string, MethodItem>;
  values: Record<string, PropertyItem> | null;
}

// 2.2.5 ObjectBlock
export class OBJECT_BLOCK extends Structure {
  static commonHdr: FieldDescriptor[] = [
    ['ObjectFlags', OBJECT_FLAGS],
  ];

  static decoration: FieldDescriptor[] = [
    ['Decoration', ':', DECORATION],
  ];

  static instanceType: FieldDescriptor[] = [
    ['InstanceType', ':', INSTANCE_TYPE],
  ];

  static classType: FieldDescriptor[] = [
    ['ClassType', ':', CLASS_TYPE],
  ];

  ctParent: ParsedClass | null = null;
  ctCurrent: ParsedClass | null = null;

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    if (data != null) {
      this.structure = [];
      const flags = data[0]!;
      if (flags & 0x04) {
        this.structure = [...this.structure, ...OBJECT_BLOCK.decoration];
      }
      if (flags & 0x01) {
        this.structure = [...this.structure, ...OBJECT_BLOCK.classType];
      } else {
        this.structure = [...this.structure, ...OBJECT_BLOCK.instanceType];
      }
      this.fromString(data);
    } else {
      this.data = null;
    }
  }

  isInstance(): boolean {
    if ((this as any)['ObjectFlags'] & 0x01) {
      return false;
    }
    return true;
  }

  parseObject(): void {
    if (((this as any)['ObjectFlags'] & 0x01) === 0) {
      // instance
      const ctCurrent = (this as any)['InstanceType']['CurrentClass'] as CLASS_AND_METHODS_PART;
      const currentName = ctCurrent.getClassName();
      if (currentName != null) {
        this.ctCurrent = this.parseClass(ctCurrent, (this as any)['InstanceType'] as INSTANCE_TYPE);
      }
    } else {
      const ctParent = ((this as any)['ClassType'] as any)['ParentClass'] as CLASS_AND_METHODS_PART;
      const ctCurrent = ((this as any)['ClassType'] as any)['CurrentClass'] as CLASS_AND_METHODS_PART;

      const parentName = ctParent.getClassName();
      if (parentName != null) {
        this.ctParent = this.parseClass(ctParent);
      }

      const currentName = ctCurrent.getClassName();
      if (currentName != null) {
        this.ctCurrent = this.parseClass(ctCurrent);
      }
    }
  }

  marshalMe(): void {
    if (((this as any)['ObjectFlags'] & 0x01) !== 0) {
      const ct = this.fields['ClassType'] as Structure;
      const currentClass = ct.fields['CurrentClass'] as CLASS_AND_METHODS_PART;
      this.marshalClassPart(currentClass, this.ctCurrent);
      this.data = null;
      ct.data = null;
      currentClass.data = null;
      const classPart = currentClass.fields['ClassPart'] as Structure;
      if (classPart) classPart.data = null;
    }
  }

  private marshalClassPart(pClass: CLASS_AND_METHODS_PART, parsed: ParsedClass | null): void {
    if (!parsed) return;
    const classPart = (pClass as any).fields['ClassPart'] as Structure;
    const properties = parsed.properties;
    const propCount = Object.keys(properties).length;
    if (propCount === 0) return;

    const sortedProps = Object.keys(properties).sort((a, b) => properties[a]!.order - properties[b]!.order);
    const ndTableSize = Math.floor((propCount - 1) / 4) + 1;
    const ndTable = Buffer.alloc(ndTableSize);

    const valueParts: Buffer[] = [];
    let heapBuf = Buffer.alloc(4);
    heapBuf.writeUInt32LE(0, 0);

    for (const key of sortedProps) {
      const prop = properties[key]!;
      const pType = prop.type & (~(CIM_ARRAY_FLAG | Inherited));
      let unpackStr: string;
      if (prop.type & CIM_ARRAY_FLAG) {
        unpackStr = HEAPREF.replace(/=.*$/, '');
      } else {
        unpackStr = CIM_TYPES_REF[pType]!.replace(/=.*$/, '');
      }

      if (prop.value === null || prop.value === undefined) {
        const ndByte = Math.floor(prop.order / 4);
        const ndShift = (prop.order % 4) * 2;
        ndTable[ndByte] = ndTable[ndByte]! | (0b01 << ndShift);
        valueParts.push(Buffer.alloc(calcsize(unpackStr)));
      } else if (
        pType === CIM_TYPE_ENUM.CIM_TYPE_STRING ||
        pType === CIM_TYPE_ENUM.CIM_TYPE_DATETIME ||
        pType === CIM_TYPE_ENUM.CIM_TYPE_REFERENCE
      ) {
        const heapOffset = heapBuf.length;
        const strVal = String(prop.value);
        const encoded = Buffer.alloc(1 + strVal.length + 1);
        encoded[0] = 0;
        encoded.write(strVal, 1, 'ascii');
        encoded[1 + strVal.length] = 0;
        heapBuf = Buffer.concat([heapBuf, encoded]);
        valueParts.push(structPack(unpackStr, heapOffset));
      } else if (pType === CIM_TYPE_ENUM.CIM_TYPE_OBJECT) {
        if (prop.value && typeof prop.value === 'object' && 'getData' in (prop.value as any)) {
          const heapOffset = heapBuf.length;
          const objData = (prop.value as { getData(): Buffer }).getData();
          const lenBuf = Buffer.alloc(4);
          lenBuf.writeUInt32LE(objData.length, 0);
          heapBuf = Buffer.concat([heapBuf, lenBuf, objData]);
          valueParts.push(structPack(unpackStr, heapOffset));
        } else {
          const ndByte = Math.floor(prop.order / 4);
          const ndShift = (prop.order % 4) * 2;
          ndTable[ndByte] = ndTable[ndByte]! | (0b01 << ndShift);
          valueParts.push(Buffer.alloc(calcsize(unpackStr)));
        }
      } else {
        valueParts.push(structPack(unpackStr, Number(prop.value)));
      }
    }

    const newNdValueTable = Buffer.concat([ndTable, ...valueParts]);
    classPart.fields['NdTable_ValueTable'] = newNdValueTable;

    const newHeap = new HEAP();
    newHeap.fields['HeapLength'] = heapBuf.length;
    newHeap.fields['HeapItem'] = heapBuf;
    newHeap.data = null;
    classPart.fields['ClassHeap'] = newHeap;

    const ndVtLen = newNdValueTable.length;
    const classHeader = classPart.fields['ClassHeader'] as Structure;
    classHeader.fields['NdTableValueTableLength'] = ndVtLen;
    classPart.fields['Garbage'] = Buffer.alloc(0);
    classHeader.data = null;

    const headerLen = classHeader.getData().length;
    const derivLen = (classPart.fields['DerivationList'] as Structure).getData().length;
    const qualSetLen = (classPart.fields['ClassQualifierSet'] as Structure).getData().length;
    const propLookupLen = (classPart.fields['PropertyLookupTable'] as Structure).getData().length;
    const heapLen = newHeap.getData().length;
    const totalLen = headerLen + derivLen + qualSetLen + propLookupLen + ndVtLen + heapLen;
    classHeader.fields['EncodingLength'] = totalLen;
    classHeader.data = null;
  }

  parseClass(pClass: CLASS_AND_METHODS_PART, cInstance?: INSTANCE_TYPE): ParsedClass {
    const classDict: ParsedClass = {
      name: pClass.getClassName(),
      qualifiers: pClass.getQualifiers(),
      properties: pClass.getProperties(),
      methods: pClass.getMethods(),
      values: null,
    };
    if (cInstance) {
      classDict.values = cInstance.getValues(classDict.properties);
    }
    return classDict;
  }

  printInformation(): void {
    if (((this as any)['ObjectFlags'] & 0x01) === 0) {
      const ctCurrent = (this as any)['InstanceType']['CurrentClass'] as CLASS_AND_METHODS_PART;
      const currentName = ctCurrent.getClassName();
      if (currentName != null) {
        this.printClass(ctCurrent, (this as any)['InstanceType'] as INSTANCE_TYPE);
      }
    } else {
      const ctParent = ((this as any)['ClassType'] as any)['ParentClass'] as CLASS_AND_METHODS_PART;
      const ctCurrent = ((this as any)['ClassType'] as any)['CurrentClass'] as CLASS_AND_METHODS_PART;

      const parentName = ctParent.getClassName();
      if (parentName != null) {
        this.printClass(ctParent);
      }

      const currentName = ctCurrent.getClassName();
      if (currentName != null) {
        this.printClass(ctCurrent);
      }
    }
  }

  printClass(pClass: CLASS_AND_METHODS_PART, cInstance?: INSTANCE_TYPE): void {
    const qualifiers = pClass.getQualifiers();
    for (const qualifier of Object.keys(qualifiers)) {
      console.log(`[${qualifier}]`);
    }
    const className = pClass.getClassName();
    console.log(`class ${className} \n{`);
    let properties = pClass.getProperties();
    if (cInstance) {
      properties = cInstance.getValues(properties);
    }
    for (const pName of Object.keys(properties)) {
      const pQualifiers = properties[pName]!.qualifiers;
      for (const qName of Object.keys(pQualifiers)) {
        if (qName !== 'CIMTYPE') {
          console.log(`\t[${qName}(${pQualifiers[qName]})]`);
        }
      }
      const prop = properties[pName]!;
      process.stdout.write(`\t${prop.stype} ${prop.name} `);
      if (prop.value != null) {
        console.log(`= ${prop.value}\n`);
      } else {
        console.log('\n');
      }
    }
    console.log('}');
  }
}

// 2.2.70 MethodSignatureBlock
export class METHOD_SIGNATURE_BLOCK extends Structure {
  static commonHdr: FieldDescriptor[] = [
    ['EncodingLength', ENCODING_LENGTH],
  ];

  static tail: FieldDescriptor[] = [
    ['_ObjectBlock', '_-ObjectBlock', 'self["EncodingLength"]'],
    ['ObjectBlock', ':', OBJECT_BLOCK],
  ];

  constructor(data?: Buffer | null, alignment = 0) {
    super(data, alignment);
    if (data != null) {
      this.fromString(data);
      if (((this as any)['EncodingLength'] as number) > 0) {
        this.structure = [];
        this.structure = [...METHOD_SIGNATURE_BLOCK.tail];
      }
      this.fromString(data);
    } else {
      this.data = null;
    }
  }
}

// 2.2.1 EncodingUnit
export class ENCODING_UNIT extends Structure {
  static structure: FieldDescriptor[] = [
    ['Signature', SIGNATURE],
    ['ObjectEncodingLength', OBJECT_ENCODING_LENGTH],
    ['_ObjectBlock', '_-ObjectBlock', 'self["ObjectEncodingLength"]'],
    ['ObjectBlock', ':', OBJECT_BLOCK],
  ];
}

// ============================================================================
// CONSTANTS
// ============================================================================
// 1.9 Standards Assignments
export const CLSID_WbemLevel1Login = stringToBin('8BC3F05E-D86B-11D0-A075-00C04FB68820');
export const CLSID_WbemBackupRestore = stringToBin('C49E32C6-BC8B-11D2-85D4-00105A1F8304');
export const CLSID_WbemClassObject = stringToBin('4590F812-1D3A-11D0-891F-00AA004B2E24');

export const IID_IWbemLevel1Login = uuidtupToBin(['F309AD18-D86A-11d0-A075-00C04FB68820', '0.0'])!;
export const IID_IWbemLoginClientID = uuidtupToBin(['d4781cd6-e5d3-44df-ad94-930efe48a887', '0.0'])!;
export const IID_IWbemLoginHelper = uuidtupToBin(['541679AB-2E5F-11d3-B34E-00104BCC4B4A', '0.0'])!;
export const IID_IWbemServices = uuidtupToBin(['9556DC99-828C-11CF-A37E-00AA003240C7', '0.0'])!;
export const IID_IWbemBackupRestore = uuidtupToBin(['C49E32C7-BC8B-11d2-85D4-00105A1F8304', '0.0'])!;
export const IID_IWbemBackupRestoreEx = uuidtupToBin(['A359DEC5-E813-4834-8A2A-BA7F1D777D76', '0.0'])!;
export const IID_IWbemClassObject = uuidtupToBin(['DC12A681-737F-11CF-884D-00AA004B2E24', '0.0'])!;
export const IID_IWbemContext = uuidtupToBin(['44aca674-e8fc-11d0-a07c-00c04fb68820', '0.0'])!;
export const IID_IEnumWbemClassObject = uuidtupToBin(['027947e1-d731-11ce-a357-000000000001', '0.0'])!;
export const IID_IWbemCallResult = uuidtupToBin(['44aca675-e8fc-11d0-a07c-00c04fb68820', '0.0'])!;
export const IID_IWbemFetchSmartEnum = uuidtupToBin(['1C1C45EE-4395-11d2-B60B-00104B703EFD', '0.0'])!;
export const IID_IWbemWCOSmartEnum = uuidtupToBin(['423EC01E-2E35-11d2-B604-00104B703EFD', '0.0'])!;

const error_status_t = ULONG;

// lFlags
export const WBEM_FLAG_RETURN_WBEM_COMPLETE = 0x00000000;
export const WBEM_FLAG_UPDATE_ONLY = 0x00000001;
export const WBEM_FLAG_CREATE_ONLY = 0x00000002;
export const WBEM_FLAG_RETURN_IMMEDIATELY = 0x00000010;
export const WBEM_FLAG_UPDATE_SAFE_MODE = 0x00000020;
export const WBEM_FLAG_FORWARD_ONLY = 0x00000020;
export const WBEM_FLAG_NO_ERROR_OBJECT = 0x00000040;
export const WBEM_FLAG_UPDATE_FORCE_MODE = 0x00000040;
export const WBEM_FLAG_SEND_STATUS = 0x00000080;
export const WBEM_FLAG_ENSURE_LOCATABLE = 0x00000100;
export const WBEM_FLAG_DIRECT_READ = 0x00000200;
export const WBEM_MASK_RESERVED_FLAGS = 0x0001F000;
export const WBEM_FLAG_USE_AMENDED_QUALIFIERS = 0x00020000;
export const WBEM_FLAG_STRONG_VALIDATION = 0x00100000;
export const WBEM_FLAG_BACKUP_RESTORE_FORCE_SHUTDOWN = 0x00000001;

export const WBEM_INFINITE = 0xffffffff;

// ============================================================================
// STRUCTURES
// ============================================================================
class UCHAR_ARRAY_CV extends NDRUniConformantVaryingArray {
  static item = 'c' as unknown as typeof NDRSTRUCT;
}

class PUCHAR_ARRAY_CV extends NDRPOINTER {
  static referent: NDRField[] = [['Data', UCHAR_ARRAY_CV]];
}

class PMInterfacePointer_ARRAY_CV extends NDRUniConformantVaryingArray {
  static item = PMInterfacePointer;
}

const REFGUID = PGUID;

class ULONG_ARRAY extends NDRUniConformantArray {
  static item = ULONG;
}

class PULONG_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ULONG_ARRAY]];
}

// BYTE_ARRAY (module-private - not exported from dcomrt)
class BYTE_ARRAY extends NDRUniConformantArray {
  static item = 'c' as unknown as typeof NDRSTRUCT;
}

class BSTR extends NDRPOINTER {
  static override referent: NDRField[] = [['Data', FLAGGED_WORD_BLOB]];

  override set(key: string, value: unknown): void {
    if (key === 'Data' && typeof value === 'string') {
      const fwb = this.fields['Data'] as FLAGGED_WORD_BLOB;
      const withNull = value + '\x00';
      const buf = Buffer.from(withNull, 'utf-16le');
      const ushorts: number[] = [];
      for (let i = 0; i < buf.length; i += 2) {
        ushorts.push(buf.readUInt16LE(i));
      }
      fwb.set('cBytes', buf.length);
      fwb.set('clSize', ushorts.length);
      fwb.set('asData', ushorts);
    } else {
      super.set(key, value);
    }
  }
}

// 2.2.5 WBEM_CHANGE_FLAG_TYPE Enumeration
export class WBEM_CHANGE_FLAG_TYPE extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0x00: 'WBEM_FLAG_CREATE_OR_UPDATE',
    0x01: 'WBEM_FLAG_UPDATE_ONLY',
    0x02: 'WBEM_FLAG_CREATE_ONLY',
    0x20: 'WBEM_FLAG_UPDATE_SAFE_MODE',
    0x40: 'WBEM_FLAG_UPDATE_FORCE_MODE',
  };
  static enumValues: Record<string, number> = {
    WBEM_FLAG_CREATE_OR_UPDATE: 0x00,
    WBEM_FLAG_UPDATE_ONLY: 0x01,
    WBEM_FLAG_CREATE_ONLY: 0x02,
    WBEM_FLAG_UPDATE_SAFE_MODE: 0x20,
    WBEM_FLAG_UPDATE_FORCE_MODE: 0x40,
  };
}

// 2.2.6 WBEM_GENERIC_FLAG_TYPE Enumeration
export class WBEM_GENERIC_FLAG_TYPE extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0x00: 'WBEM_FLAG_RETURN_WBEM_COMPLETE',
    0x10: 'WBEM_FLAG_RETURN_IMMEDIATELY',
    0x20: 'WBEM_FLAG_FORWARD_ONLY',
    0x40: 'WBEM_FLAG_NO_ERROR_OBJECT',
    0x80: 'WBEM_FLAG_SEND_STATUS',
    0x100: 'WBEM_FLAG_ENSURE_LOCATABLE',
    0x200: 'WBEM_FLAG_DIRECT_READ',
    0x1F000: 'WBEM_MASK_RESERVED_FLAGS',
    0x20000: 'WBEM_FLAG_USE_AMENDED_QUALIFIERS',
    0x100000: 'WBEM_FLAG_STRONG_VALIDATION',
  };
  static enumValues: Record<string, number> = {
    WBEM_FLAG_RETURN_WBEM_COMPLETE: 0x00,
    WBEM_FLAG_RETURN_IMMEDIATELY: 0x10,
    WBEM_FLAG_FORWARD_ONLY: 0x20,
    WBEM_FLAG_NO_ERROR_OBJECT: 0x40,
    WBEM_FLAG_SEND_STATUS: 0x80,
    WBEM_FLAG_ENSURE_LOCATABLE: 0x100,
    WBEM_FLAG_DIRECT_READ: 0x200,
    WBEM_MASK_RESERVED_FLAGS: 0x1F000,
    WBEM_FLAG_USE_AMENDED_QUALIFIERS: 0x20000,
    WBEM_FLAG_STRONG_VALIDATION: 0x100000,
  };
}

// 2.2.7 WBEM_STATUS_TYPE Enumeration
export class WBEM_STATUS_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0x00: 'WBEM_STATUS_COMPLETE',
    0x01: 'WBEM_STATUS_REQUIREMENTS',
    0x02: 'WBEM_STATUS_PROGRESS',
  };
  static enumValues: Record<string, number> = {
    WBEM_STATUS_COMPLETE: 0x00,
    WBEM_STATUS_REQUIREMENTS: 0x01,
    WBEM_STATUS_PROGRESS: 0x02,
  };
}

// 2.2.8 WBEM_TIMEOUT_TYPE Enumeration
export class WBEM_TIMEOUT_TYPE extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0x00000000: 'WBEM_NO_WAIT',
    0xFFFFFFFF: 'WBEM_INFINITE',
  };
  static enumValues: Record<string, number> = {
    WBEM_NO_WAIT: 0x00000000,
    WBEM_INFINITE: 0xFFFFFFFF,
  };
}

// 2.2.9 WBEM_QUERY_FLAG_TYPE Enumeration
export class WBEM_QUERY_FLAG_TYPE extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0x00000000: 'WBEM_FLAG_DEEP',
    0x00000001: 'WBEM_FLAG_SHALLOW',
    0x00000002: 'WBEM_FLAG_PROTOTYPE',
  };
  static enumValues: Record<string, number> = {
    WBEM_FLAG_DEEP: 0x00000000,
    WBEM_FLAG_SHALLOW: 0x00000001,
    WBEM_FLAG_PROTOTYPE: 0x00000002,
  };
}

// 2.2.10 WBEM_BACKUP_RESTORE_FLAGS Enumeration
export class WBEM_BACKUP_RESTORE_FLAGS extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0x00000001: 'WBEM_FLAG_BACKUP_RESTORE_FORCE_SHUTDOWN',
  };
  static enumValues: Record<string, number> = {
    WBEM_FLAG_BACKUP_RESTORE_FORCE_SHUTDOWN: 0x00000001,
  };
}

// 2.2.11 WBEMSTATUS Enumeration
export class WBEMSTATUS extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0x00000000: 'WBEM_S_NO_ERROR',
    0x00000001: 'WBEM_S_FALSE',
    0x00040004: 'WBEM_S_TIMEDOUT',
    0x000400FF: 'WBEM_S_NEW_STYLE',
    0x00040010: 'WBEM_S_PARTIAL_RESULTS',
    0x80041001: 'WBEM_E_FAILED',
    0x80041002: 'WBEM_E_NOT_FOUND',
    0x80041003: 'WBEM_E_ACCESS_DENIED',
    0x80041004: 'WBEM_E_PROVIDER_FAILURE',
    0x80041005: 'WBEM_E_TYPE_MISMATCH',
    0x80041006: 'WBEM_E_OUT_OF_MEMORY',
    0x80041007: 'WBEM_E_INVALID_CONTEXT',
    0x80041008: 'WBEM_E_INVALID_PARAMETER',
    0x80041009: 'WBEM_E_NOT_AVAILABLE',
    0x8004100a: 'WBEM_E_CRITICAL_ERROR',
    0x8004100c: 'WBEM_E_NOT_SUPPORTED',
    0x80041011: 'WBEM_E_PROVIDER_NOT_FOUND',
    0x80041012: 'WBEM_E_INVALID_PROVIDER_REGISTRATION',
    0x80041013: 'WBEM_E_PROVIDER_LOAD_FAILURE',
    0x80041014: 'WBEM_E_INITIALIZATION_FAILURE',
    0x80041015: 'WBEM_E_TRANSPORT_FAILURE',
    0x80041016: 'WBEM_E_INVALID_OPERATION',
    0x80041019: 'WBEM_E_ALREADY_EXISTS',
    0x8004101d: 'WBEM_E_UNEXPECTED',
    0x80041020: 'WBEM_E_INCOMPLETE_CLASS',
    0x80041033: 'WBEM_E_SHUTTING_DOWN',
    0x80004001: 'E_NOTIMPL',
    0x8004100D: 'WBEM_E_INVALID_SUPERCLASS',
    0x8004100E: 'WBEM_E_INVALID_NAMESPACE',
    0x8004100F: 'WBEM_E_INVALID_OBJECT',
    0x80041010: 'WBEM_E_INVALID_CLASS',
    0x80041017: 'WBEM_E_INVALID_QUERY',
    0x80041018: 'WBEM_E_INVALID_QUERY_TYPE',
    0x80041024: 'WBEM_E_PROVIDER_NOT_CAPABLE',
    0x80041025: 'WBEM_E_CLASS_HAS_CHILDREN',
    0x80041026: 'WBEM_E_CLASS_HAS_INSTANCES',
    0x80041028: 'WBEM_E_ILLEGAL_NULL',
    0x8004102D: 'WBEM_E_INVALID_CIM_TYPE',
    0x8004102E: 'WBEM_E_INVALID_METHOD',
    0x8004102F: 'WBEM_E_INVALID_METHOD_PARAMETERS',
    0x80041031: 'WBEM_E_INVALID_PROPERTY',
    0x80041032: 'WBEM_E_CALL_CANCELLED',
    0x8004103A: 'WBEM_E_INVALID_OBJECT_PATH',
    0x8004103B: 'WBEM_E_OUT_OF_DISK_SPACE',
    0x8004103D: 'WBEM_E_UNSUPPORTED_PUT_EXTENSION',
    0x8004106c: 'WBEM_E_QUOTA_VIOLATION',
    0x80041045: 'WBEM_E_SERVER_TOO_BUSY',
    0x80041055: 'WBEM_E_METHOD_NOT_IMPLEMENTED',
    0x80041056: 'WBEM_E_METHOD_DISABLED',
    0x80041058: 'WBEM_E_UNPARSABLE_QUERY',
    0x80041059: 'WBEM_E_NOT_EVENT_CLASS',
    0x8004105A: 'WBEM_E_MISSING_GROUP_WITHIN',
    0x8004105B: 'WBEM_E_MISSING_AGGREGATION_LIST',
    0x8004105c: 'WBEM_E_PROPERTY_NOT_AN_OBJECT',
    0x8004105d: 'WBEM_E_AGGREGATING_BY_OBJECT',
    0x80041060: 'WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING',
    0x80041061: 'WBEM_E_QUEUE_OVERFLOW',
    0x80041062: 'WBEM_E_PRIVILEGE_NOT_HELD',
    0x80041063: 'WBEM_E_INVALID_OPERATOR',
    0x80041065: 'WBEM_E_CANNOT_BE_ABSTRACT',
    0x80041066: 'WBEM_E_AMENDED_OBJECT',
    0x8004107A: 'WBEM_E_VETO_PUT',
    0x80041081: 'WBEM_E_PROVIDER_SUSPENDED',
    0x80041087: 'WBEM_E_ENCRYPTED_CONNECTION_REQUIRED',
    0x80041088: 'WBEM_E_PROVIDER_TIMED_OUT',
    0x80041089: 'WBEM_E_NO_KEY',
    0x8004108a: 'WBEM_E_PROVIDER_DISABLED',
    0x80042001: 'WBEM_E_REGISTRATION_TOO_BROAD',
    0x80042002: 'WBEM_E_REGISTRATION_TOO_PRECISE',
  };
  static enumValues: Record<string, number> = {};
}

// Build reverse mapping for WBEMSTATUS
for (const [k, v] of Object.entries(WBEMSTATUS.enumItems)) {
  WBEMSTATUS.enumValues[v] = Number(k);
}

// 2.2.12 WBEM_CONNECT_OPTIONS Enumeration
export class WBEM_CONNECT_OPTIONS extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0x40: 'WBEM_FLAG_CONNECT_REPOSITORY_ONLY',
    0x100: 'WBEM_FLAG_CONNECT_PROVIDERS',
  };
  static enumValues: Record<string, number> = {
    WBEM_FLAG_CONNECT_REPOSITORY_ONLY: 0x40,
    WBEM_FLAG_CONNECT_PROVIDERS: 0x100,
  };
}

// 2.2.14 ObjectArray Structure
export class ObjectArray extends Structure {
  static structure: FieldDescriptor[] = [
    ['dwByteOrdering', '<L=0'],
    ['abSignature', '8s="WBEMDATA"'],
    ['dwSizeOfHeader1', '<L=0x1a'],
    ['dwDataSize1', '<L=0'],
    ['dwFlags', '<L=0'],
    ['bVersion', 'B=1'],
    ['bPacketType', 'B=0'],
    ['dwSizeOfHeader2', '<L=8'],
    ['dwDataSize2', '<L', 'len(self["wbemObjects"])+12'],
    ['dwSizeOfHeader3', '<L=12'],
    ['dwDataSize3', '<L', 'len(self["dwDataSize2"])-12)'],
    ['dwNumObjects', '<L=0'],
    ['_wbemObjects', '_-wbemObjects', 'self["dwDataSize3"]'],
    ['wbemObjects', ':'],
  ];
}

// 2.2.14.1 WBEM_DATAPACKET_OBJECT Structure
export class WBEM_DATAPACKET_OBJECT extends Structure {
  static structure: FieldDescriptor[] = [
    ['dwSizeOfHeader', '<L=9'],
    ['dwSizeOfData', '<L', 'len(self["Object"])'],
    ['bObjectType', 'B=0'],
    ['_Object', '_-Object', 'self["dwSizeOfData"]'],
    ['Object', ':'],
  ];
}

// 2.2.14.2 WBEMOBJECT_CLASS Structure
export class WBEMOBJECT_CLASS extends Structure {
  static structure: FieldDescriptor[] = [
    ['dwSizeOfHeader', '<L=8'],
    ['dwSizeOfData', '<L', 'len(self["ObjectData"])'],
    ['_ObjectData', '_-ObjectData', 'self["dwSizeOfData"]'],
    ['ObjectData', ':'],
  ];
}

// 2.2.14.3 WBEMOBJECT_INSTANCE Structure
export class WBEMOBJECT_INSTANCE extends Structure {
  static structure: FieldDescriptor[] = [
    ['dwSizeOfHeader', '<L=0x18'],
    ['dwSizeOfData', '<L', 'len(self["ObjectData"])'],
    ['classID', '16s=b"\\x00"*16'],
    ['_ObjectData', '_-ObjectData', 'self["dwSizeOfData"]'],
    ['ObjectData', ':'],
  ];
}

// 2.2.14.4 WBEMOBJECT_INSTANCE_NOCLASS Structure
export class WBEMOBJECT_INSTANCE_NOCLASS extends Structure {
  static structure: FieldDescriptor[] = [
    ['dwSizeOfHeader', '<L=0x18'],
    ['dwSizeOfData', '<L', 'len(self["ObjectData"])'],
    ['classID', '16s=b"\\x00"*16'],
    ['_ObjectData', '_-ObjectData', 'self["dwSizeOfData"]'],
    ['ObjectData', ':'],
  ];
}

// 2.2.15 WBEM_REFRESHED_OBJECT Structure
export class WBEM_REFRESHED_OBJECT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['m_lRequestId', LONG],
    ['m_lBlobType', LONG],
    ['m_lBlobLength', LONG],
    ['m_pBlob', BYTE_ARRAY],
  ];
}

export class WBEM_REFRESHED_OBJECT_ARRAY extends NDRUniConformantArray {
  static item = WBEM_REFRESHED_OBJECT;
}

export class PWBEM_REFRESHED_OBJECT_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', WBEM_REFRESHED_OBJECT_ARRAY]];
}

// 2.2.16 WBEM_INSTANCE_BLOB Enumeration
export class WBEM_INSTANCE_BLOB extends Structure {
  static structure: FieldDescriptor[] = [
    ['Version', '<L=0x1'],
    ['numObjects', '<L=0'],
    ['Objects', ':'],
  ];
}

// 2.2.17 WBEM_INSTANCE_BLOB_TYPE Enumeration
export class WBEM_INSTANCE_BLOB_TYPE extends NDRENUM {
  static structure: NDRField[] = [['Data', '<L']];
  static enumItems: Record<number, string> = {
    0x40: 'WBEM_FLAG_CONNECT_REPOSITORY_ONLY',
    0x100: 'WBEM_FLAG_CONNECT_PROVIDERS',
  };
  static enumValues: Record<string, number> = {
    WBEM_FLAG_CONNECT_REPOSITORY_ONLY: 0x40,
    WBEM_FLAG_CONNECT_PROVIDERS: 0x100,
  };
}

// 2.2.26 _WBEM_REFRESH_INFO_NON_HIPERF Structure
export class _WBEM_REFRESH_INFO_NON_HIPERF extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['m_wszNamespace', LPWSTR],
    ['m_pTemplate', PMInterfacePointer],
  ];
}

// 2.2.27 _WBEM_REFRESH_INFO_REMOTE Structure
export class _WBEM_REFRESH_INFO_REMOTE extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['m_pRefresher', PMInterfacePointer],
    ['m_pTemplate', PMInterfacePointer],
    ['m_Guid', GUID],
  ];
}

// 2.2.25 WBEM_REFRESH_TYPE Enumeration
export class WBEM_REFRESH_TYPE extends NDRENUM {
  static enumItems: Record<number, string> = {
    0: 'WBEM_REFRESH_TYPE_INVALID',
    3: 'WBEM_REFRESH_TYPE_REMOTE',
    6: 'WBEM_REFRESH_TYPE_NON_HIPERF',
  };
  static enumValues: Record<string, number> = {
    WBEM_REFRESH_TYPE_INVALID: 0,
    WBEM_REFRESH_TYPE_REMOTE: 3,
    WBEM_REFRESH_TYPE_NON_HIPERF: 6,
  };
  static WBEM_REFRESH_TYPE_INVALID = 0;
  static WBEM_REFRESH_TYPE_REMOTE = 3;
  static WBEM_REFRESH_TYPE_NON_HIPERF = 6;
}

// 2.2.28 _WBEM_REFRESH_INFO_UNION Union
export class _WBEM_REFRESH_INFO_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', LONG]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    [WBEM_REFRESH_TYPE.WBEM_REFRESH_TYPE_REMOTE]: ['m_Remote', _WBEM_REFRESH_INFO_REMOTE],
    [WBEM_REFRESH_TYPE.WBEM_REFRESH_TYPE_NON_HIPERF]: ['m_NonHiPerf', _WBEM_REFRESH_INFO_NON_HIPERF],
    [WBEM_REFRESH_TYPE.WBEM_REFRESH_TYPE_INVALID]: ['m_hres', HRESULT],
  };
}

// 2.2.20 _WBEM_REFRESH_INFO Structure
export class _WBEM_REFRESH_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['m_lType', LONG],
    ['m_Info', _WBEM_REFRESH_INFO_UNION],
    ['m_lCancelId', LONG],
  ];
}

// 2.2.21 _WBEM_REFRESHER_ID Structure
export class _WBEM_REFRESHER_ID extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['m_szMachineName', LPCSTR],
    ['m_dwProcessId', DWORD],
    ['m_guidRefresherId', GUID],
  ];
}

// 2.2.22 _WBEM_RECONNECT_INFO Structure
export class _WBEM_RECONNECT_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['m_lType', LPCSTR],
    ['m_pwcsPath', LPWSTR],
  ];
}

export class _WBEM_RECONNECT_INFO_ARRAY extends NDRUniConformantArray {
  static item = _WBEM_RECONNECT_INFO;
}

// 2.2.23 _WBEM_RECONNECT_RESULTS Structure
export class _WBEM_RECONNECT_RESULTS extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['m_lId', LONG],
    ['m_hr', HRESULT],
  ];
}

export class _WBEM_RECONNECT_RESULTS_ARRAY extends NDRUniConformantArray {
  static item = _WBEM_RECONNECT_INFO;
}

// ============================================================================
// RPC CALLS
// ============================================================================

// 3.1.4.1 IWbemLevel1Login Interface
// 3.1.4.1.1 IWbemLevel1Login::EstablishPosition (Opnum 3)
export class IWbemLevel1Login_EstablishPosition extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['reserved1', LPWSTR],
    ['reserved2', DWORD],
  ];
}

export class IWbemLevel1Login_EstablishPositionResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['LocaleVersion', DWORD],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.1.2 IWbemLevel1Login::RequestChallenge (Opnum 4)
export class IWbemLevel1Login_RequestChallenge extends DCOMCALL {
  static opnum = 4;
  static structure: NDRField[] = [
    ['reserved1', LPWSTR],
    ['reserved2', LPWSTR],
  ];
}

export class IWbemLevel1Login_RequestChallengeResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['reserved3', UCHAR_ARRAY_CV],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.1.3 IWbemLevel1Login::WBEMLogin (Opnum 5)
export class IWbemLevel1Login_WBEMLogin extends DCOMCALL {
  static opnum = 5;
  static structure: NDRField[] = [
    ['reserved1', LPWSTR],
    ['reserved2', PUCHAR_ARRAY_CV],
    ['reserved3', LONG],
    ['reserved4', PMInterfacePointer],
  ];
}

export class IWbemLevel1Login_WBEMLoginResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['reserved5', UCHAR_ARRAY_CV],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.1.4 IWbemLevel1Login::NTLMLogin (Opnum 6)
export class IWbemLevel1Login_NTLMLogin extends DCOMCALL {
  static opnum = 6;
  static structure: NDRField[] = [
    ['wszNetworkResource', LPWSTR],
    ['wszPreferredLocale', LPWSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
  ];
}

export class IWbemLevel1Login_NTLMLoginResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppNamespace', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.2 IWbemObjectSink Interface Server Details
// 3.1.4.2.1 IWbemObjectSink::Indicate (Opnum 3)
export class IWbemObjectSink_Indicate extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['lObjectCount', LONG],
    ['apObjArray', PMInterfacePointer_ARRAY],
  ];
}

export class IWbemObjectSink_IndicateResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.2.2 IWbemObjectSink::SetStatus (Opnum 4)
export class IWbemObjectSink_SetStatus extends DCOMCALL {
  static opnum = 4;
  static structure: NDRField[] = [
    ['lFlags', LONG],
    ['hResult', HRESULT],
    ['strParam', BSTR],
    ['pObjParam', PMInterfacePointer],
  ];
}

export class IWbemObjectSink_SetStatusResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3 IWbemServices Interface
// 3.1.4.3.1 IWbemServices::OpenNamespace (Opnum 3)
export class IWbemServices_OpenNamespace extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['strNamespace', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['ppWorkingNamespace', PMInterfacePointer],
    ['ppResult', PMInterfacePointer],
  ];
}

export class IWbemServices_OpenNamespaceResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppWorkingNamespace', PPMInterfacePointer],
    ['ppResult', PPMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.2 IWbemServices::CancelAsyncCall (Opnum 4)
export class IWbemServices_CancelAsyncCall extends DCOMCALL {
  static opnum = 4;
  static structure: NDRField[] = [
    ['IWbemObjectSink', PMInterfacePointer],
  ];
}

export class IWbemServices_CancelAsyncCallResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.3 IWbemServices::QueryObjectSink (Opnum 5)
export class IWbemServices_QueryObjectSink extends DCOMCALL {
  static opnum = 5;
  static structure: NDRField[] = [
    ['lFlags', LONG],
  ];
}

export class IWbemServices_QueryObjectSinkResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppResponseHandler', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.4 IWbemServices::GetObject (Opnum 6)
export class IWbemServices_GetObject extends DCOMCALL {
  static opnum = 6;
  static structure: NDRField[] = [
    ['strObjectPath', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['ppObject', PMInterfacePointer],
    ['ppCallResult', PMInterfacePointer],
  ];
}

export class IWbemServices_GetObjectResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppObject', PPMInterfacePointer],
    ['ppCallResult', PPMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.5 IWbemServices::GetObjectAsync (Opnum 7)
export class IWbemServices_GetObjectAsync extends DCOMCALL {
  static opnum = 7;
  static structure: NDRField[] = [
    ['strObjectPath', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['pResponseHandler', PMInterfacePointer],
  ];
}

export class IWbemServices_GetObjectAsyncResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.6 IWbemServices::PutClass (Opnum 8)
export class IWbemServices_PutClass extends DCOMCALL {
  static opnum = 8;
  static structure: NDRField[] = [
    ['pObject', PMInterfacePointer],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['pResponseHandler', PMInterfacePointer],
    ['ppCallResult', PMInterfacePointer],
  ];
}

export class IWbemServices_PutClassResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppCallResult', PPMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.7 IWbemServices::PutClassAsync (Opnum 9)
export class IWbemServices_PutClassAsync extends DCOMCALL {
  static opnum = 9;
  static structure: NDRField[] = [
    ['pObject', PMInterfacePointer],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['pResponseHandler', PMInterfacePointer],
  ];
}

export class IWbemServices_PutClassAsyncResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.8 IWbemServices::DeleteClass (Opnum 10)
export class IWbemServices_DeleteClass extends DCOMCALL {
  static opnum = 10;
  static structure: NDRField[] = [
    ['strClass', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['ppCallResult', PMInterfacePointer],
  ];
}

export class IWbemServices_DeleteClassResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppCallResult', PPMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.9 IWbemServices::DeleteClassAsync (Opnum 11)
export class IWbemServices_DeleteClassAsync extends DCOMCALL {
  static opnum = 11;
  static structure: NDRField[] = [
    ['strClass', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['pResponseHandler', PMInterfacePointer],
  ];
}

export class IWbemServices_DeleteClassAsyncResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.10 IWbemServices::CreateClassEnum (Opnum 12)
export class IWbemServices_CreateClassEnum extends DCOMCALL {
  static opnum = 12;
  static structure: NDRField[] = [
    ['strSuperClass', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
  ];
}

export class IWbemServices_CreateClassEnumResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppEnum', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.11 IWbemServices::CreateClassEnumAsync (Opnum 13)
export class IWbemServices_CreateClassEnumAsync extends DCOMCALL {
  static opnum = 13;
  static structure: NDRField[] = [
    ['strSuperClass', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['pResponseHandler', PMInterfacePointer],
  ];
}

export class IWbemServices_CreateClassEnumAsyncResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.12 IWbemServices::PutInstance (Opnum 14)
export class IWbemServices_PutInstance extends DCOMCALL {
  static opnum = 14;
  static structure: NDRField[] = [
    ['pInst', PMInterfacePointer],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['ppCallResult', PMInterfacePointer],
  ];
}

export class IWbemServices_PutInstanceResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppCallResult', PPMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.13 IWbemServices::PutInstanceAsync (Opnum 15)
export class IWbemServices_PutInstanceAsync extends DCOMCALL {
  static opnum = 15;
  static structure: NDRField[] = [
    ['pInst', PMInterfacePointer],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['pResponseHandler', PMInterfacePointer],
  ];
}

export class IWbemServices_PutInstanceAsyncResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.14 IWbemServices::DeleteInstance (Opnum 16)
export class IWbemServices_DeleteInstance extends DCOMCALL {
  static opnum = 16;
  static structure: NDRField[] = [
    ['strObjectPath', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['ppCallResult', PMInterfacePointer],
  ];
}

export class IWbemServices_DeleteInstanceResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppCallResult', PPMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.15 IWbemServices::DeleteInstanceAsync (Opnum 17)
export class IWbemServices_DeleteInstanceAsync extends DCOMCALL {
  static opnum = 17;
  static structure: NDRField[] = [
    ['strObjectPath', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['pResponseHandler', PMInterfacePointer],
  ];
}

export class IWbemServices_DeleteInstanceAsyncResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.16 IWbemServices::CreateInstanceEnum (Opnum 18)
export class IWbemServices_CreateInstanceEnum extends DCOMCALL {
  static opnum = 18;
  static structure: NDRField[] = [
    ['strSuperClass', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
  ];
}

export class IWbemServices_CreateInstanceEnumResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppEnum', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.17 IWbemServices::CreateInstanceEnumAsync (Opnum 19)
export class IWbemServices_CreateInstanceEnumAsync extends DCOMCALL {
  static opnum = 19;
  static structure: NDRField[] = [
    ['strSuperClass', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['pResponseHandler', PMInterfacePointer],
  ];
}

export class IWbemServices_CreateInstanceEnumAsyncResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.18 IWbemServices::ExecQuery (Opnum 20)
export class IWbemServices_ExecQuery extends DCOMCALL {
  static opnum = 20;
  static structure: NDRField[] = [
    ['strQueryLanguage', BSTR],
    ['strQuery', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
  ];
}

export class IWbemServices_ExecQueryResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppEnum', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.19 IWbemServices::ExecQueryAsync (Opnum 21)
export class IWbemServices_ExecQueryAsync extends DCOMCALL {
  static opnum = 21;
  static structure: NDRField[] = [
    ['strQueryLanguage', BSTR],
    ['strQuery', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['pResponseHandler', PMInterfacePointer],
  ];
}

export class IWbemServices_ExecQueryAsyncResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.20 IWbemServices::ExecNotificationQuery (Opnum 22)
export class IWbemServices_ExecNotificationQuery extends DCOMCALL {
  static opnum = 22;
  static structure: NDRField[] = [
    ['strQueryLanguage', BSTR],
    ['strQuery', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
  ];
}

export class IWbemServices_ExecNotificationQueryResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppEnum', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.21 IWbemServices::ExecNotificationQueryAsync (Opnum 23)
export class IWbemServices_ExecNotificationQueryAsync extends DCOMCALL {
  static opnum = 23;
  static structure: NDRField[] = [
    ['strQueryLanguage', BSTR],
    ['strQuery', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['pResponseHandler', PMInterfacePointer],
  ];
}

export class IWbemServices_ExecNotificationQueryAsyncResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.22 IWbemServices::ExecMethod (Opnum 24)
export class IWbemServices_ExecMethod extends DCOMCALL {
  static opnum = 24;
  static structure: NDRField[] = [
    ['strObjectPath', BSTR],
    ['strMethodName', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['pInParams', PMInterfacePointer],
    ['ppOutParams', PPMInterfacePointer],
    ['ppCallResult', PPMInterfacePointer],
  ];
}

export class IWbemServices_ExecMethodResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppOutParams', PPMInterfacePointer],
    ['ppCallResult', PPMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.3.23 IWbemServices::ExecMethodAsync (Opnum 25)
export class IWbemServices_ExecMethodAsync extends DCOMCALL {
  static opnum = 25;
  static structure: NDRField[] = [
    ['strObjectPath', BSTR],
    ['strMethodName', BSTR],
    ['lFlags', LONG],
    ['pCtx', PMInterfacePointer],
    ['pInParams', PMInterfacePointer],
    ['pResponseHandler', PMInterfacePointer],
  ];
}

export class IWbemServices_ExecMethodAsyncResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4 IEnumWbemClassObject Interface
// 3.1.4.4.1 IEnumWbemClassObject::Reset (Opnum 3)
export class IEnumWbemClassObject_Reset extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [];
}

export class IEnumWbemClassObject_ResetResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.2 IEnumWbemClassObject::Next (Opnum 4)
export class IEnumWbemClassObject_Next extends DCOMCALL {
  static opnum = 4;
  static structure: NDRField[] = [
    ['lTimeout', ULONG],
    ['uCount', ULONG],
  ];
}

export class IEnumWbemClassObject_NextResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['apObjects', PMInterfacePointer_ARRAY_CV],
    ['puReturned', ULONG],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.3 IEnumWbemClassObject::NextAsync (Opnum 5)
export class IEnumWbemClassObject_NextAsync extends DCOMCALL {
  static opnum = 5;
  static structure: NDRField[] = [
    ['lTimeout', LONG],
    ['pSink', PMInterfacePointer],
  ];
}

export class IEnumWbemClassObject_NextAsyncResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.4 IEnumWbemClassObject::Clone (Opnum 6)
export class IEnumWbemClassObject_Clone extends DCOMCALL {
  static opnum = 6;
  static structure: NDRField[] = [];
}

export class IEnumWbemClassObject_CloneResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppEnum', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.4.5 IEnumWbemClassObject::Skip (Opnum 7)
export class IEnumWbemClassObject_Skip extends DCOMCALL {
  static opnum = 7;
  static structure: NDRField[] = [
    ['lTimeout', LONG],
    ['uCount', ULONG],
  ];
}

export class IEnumWbemClassObject_SkipResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.5 IWbemCallResult Interface
// 3.1.4.5.1 IWbemCallResult::GetResultObject (Opnum 3)
export class IWbemCallResult_GetResultObject extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['lTimeout', LONG],
  ];
}

export class IWbemCallResult_GetResultObjectResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppResultObject', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.5.2 IWbemCallResult::GetResultString (Opnum 4)
export class IWbemCallResult_GetResultString extends DCOMCALL {
  static opnum = 4;
  static structure: NDRField[] = [
    ['lTimeout', LONG],
  ];
}

export class IWbemCallResult_GetResultStringResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pstrResultString', BSTR],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.5.3 IWbemCallResult::GetResultServices (Opnum 5)
export class IWbemCallResult_GetResultServices extends DCOMCALL {
  static opnum = 5;
  static structure: NDRField[] = [
    ['lTimeout', LONG],
  ];
}

export class IWbemCallResult_GetResultServicesResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppServices', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.5.4 IWbemCallResult::GetCallStatus (Opnum 6)
export class IWbemCallResult_GetCallStatus extends DCOMCALL {
  static opnum = 6;
  static structure: NDRField[] = [
    ['lTimeout', LONG],
  ];
}

export class IWbemCallResult_GetCallStatusResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['plStatus', LONG],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.6 IWbemFetchSmartEnum Interface
// 3.1.4.6.1 IWbemFetchSmartEnum::GetSmartEnum (Opnum 3)
export class IWbemFetchSmartEnum_GetSmartEnum extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [];
}

export class IWbemFetchSmartEnum_GetSmartEnumResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppSmartEnum', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.7 IWbemWCOSmartEnum Interface
// 3.1.4.7.1 IWbemWCOSmartEnum::Next (Opnum 3)
export class IWbemWCOSmartEnum_Next extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['proxyGUID', REFGUID],
    ['lTimeout', LONG],
    ['uCount', ULONG],
  ];
}

export class IWbemWCOSmartEnum_NextResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['puReturned', ULONG],
    ['pdwBuffSize', ULONG],
    ['pBuffer', BYTE_ARRAY],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.8 IWbemLoginClientID Interface
// 3.1.4.8.1 IWbemLoginClientID::SetClientInfo (Opnum 3)
export class IWbemLoginClientID_SetClientInfo extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['wszClientMachine', LPWSTR],
    ['lClientProcId', LONG],
    ['lReserved', LONG],
  ];
}

export class IWbemLoginClientID_SetClientInfoResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.9 IWbemLoginHelper Interface
// 3.1.4.9.1 IWbemLoginHelper::SetEvent (Opnum 3)
export class IWbemLoginHelper_SetEvent extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['sEventToSet', LPCSTR],
  ];
}

export class IWbemLoginHelper_SetEventResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.10 IWbemBackupRestore Interface
// 3.1.4.10.1 IWbemBackupRestore::Backup (Opnum 3)
export class IWbemBackupRestore_Backup extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['strBackupToFile', LPWSTR],
    ['lFlags', LONG],
  ];
}

export class IWbemBackupRestore_BackupResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.10.2 IWbemBackupRestore::Restore (Opnum 4)
export class IWbemBackupRestore_Restore extends DCOMCALL {
  static opnum = 4;
  static structure: NDRField[] = [
    ['strRestoreFromFile', LPWSTR],
    ['lFlags', LONG],
  ];
}

export class IWbemBackupRestore_RestoreResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.11 IWbemBackupRestoreEx Interface
// 3.1.4.11.1 IWbemBackupRestoreEx::Pause (Opnum 5)
export class IWbemBackupRestoreEx_Pause extends DCOMCALL {
  static opnum = 5;
  static structure: NDRField[] = [];
}

export class IWbemBackupRestoreEx_PauseResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.11.2 IWbemBackupRestoreEx::Resume (Opnum 6)
export class IWbemBackupRestoreEx_Resume extends DCOMCALL {
  static opnum = 6;
  static structure: NDRField[] = [];
}

export class IWbemBackupRestoreEx_ResumeResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.12 IWbemRefreshingServices Interface
// 3.1.4.12.1 IWbemRefreshingServices::AddObjectToRefresher (Opnum 3)
export class IWbemRefreshingServices_AddObjectToRefresher extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['pRefresherId', _WBEM_REFRESHER_ID],
    ['wszPath', LPWSTR],
    ['lFlags', LONG],
    ['pContext', PMInterfacePointer],
    ['dwClientRefrVersion', DWORD],
  ];
}

export class IWbemRefreshingServices_AddObjectToRefresherResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pInfo', _WBEM_REFRESH_INFO],
    ['pdwSvrRefrVersion', DWORD],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.12.2 IWbemRefreshingServices::AddObjectToRefresherByTemplate (Opnum 4)
export class IWbemRefreshingServices_AddObjectToRefresherByTemplate extends DCOMCALL {
  static opnum = 4;
  static structure: NDRField[] = [
    ['pRefresherId', _WBEM_REFRESHER_ID],
    ['pTemplate', PMInterfacePointer],
    ['lFlags', LONG],
    ['pContext', PMInterfacePointer],
    ['dwClientRefrVersion', DWORD],
  ];
}

export class IWbemRefreshingServices_AddObjectToRefresherByTemplateResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pInfo', _WBEM_REFRESH_INFO],
    ['pdwSvrRefrVersion', DWORD],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.12.3 IWbemRefreshingServices::AddEnumToRefresher (Opnum 5)
export class IWbemRefreshingServices_AddEnumToRefresher extends DCOMCALL {
  static opnum = 5;
  static structure: NDRField[] = [
    ['pRefresherId', _WBEM_REFRESHER_ID],
    ['wszClass', LPWSTR],
    ['lFlags', LONG],
    ['pContext', PMInterfacePointer],
    ['dwClientRefrVersion', DWORD],
  ];
}

export class IWbemRefreshingServices_AddEnumToRefresherResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pInfo', _WBEM_REFRESH_INFO],
    ['pdwSvrRefrVersion', DWORD],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.12.4 IWbemRefreshingServices::RemoveObjectFromRefresher (Opnum 6)
export class IWbemRefreshingServices_RemoveObjectFromRefresher extends DCOMCALL {
  static opnum = 6;
  static structure: NDRField[] = [
    ['pRefresherId', _WBEM_REFRESHER_ID],
    ['lId', LONG],
    ['lFlags', LONG],
    ['dwClientRefrVersion', DWORD],
  ];
}

export class IWbemRefreshingServices_RemoveObjectFromRefresherResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['pdwSvrRefrVersion', DWORD],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.12.5 IWbemRefreshingServices::GetRemoteRefresher (Opnum 7)
export class IWbemRefreshingServices_GetRemoteRefresher extends DCOMCALL {
  static opnum = 7;
  static structure: NDRField[] = [
    ['pRefresherId', _WBEM_REFRESHER_ID],
    ['lFlags', LONG],
    ['dwClientRefrVersion', DWORD],
  ];
}

export class IWbemRefreshingServices_GetRemoteRefresherResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ppRemRefresher', PMInterfacePointer],
    ['pGuid', GUID],
    ['pdwSvrRefrVersion', DWORD],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.12.6 IWbemRefreshingServices::ReconnectRemoteRefresher (Opnum 8)
export class IWbemRefreshingServices_ReconnectRemoteRefresher extends DCOMCALL {
  static opnum = 8;
  static structure: NDRField[] = [
    ['pRefresherId', _WBEM_REFRESHER_ID],
    ['lFlags', LONG],
    ['lNumObjects', LONG],
    ['dwClientRefrVersion', DWORD],
    ['apReconnectInfo', _WBEM_RECONNECT_INFO_ARRAY],
  ];
}

export class IWbemRefreshingServices_ReconnectRemoteRefresherResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['apReconnectResults', _WBEM_RECONNECT_RESULTS_ARRAY],
    ['pdwSvrRefrVersion', DWORD],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.13 IWbemRemoteRefresher Interface
// 3.1.4.13.1 IWbemRemoteRefresher::RemoteRefresh (Opnum 3)
export class IWbemRemoteRefresher_RemoteRefresh extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['lFlags', LONG],
  ];
}

export class IWbemRemoteRefresher_RemoteRefreshResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['plNumObjects', _WBEM_RECONNECT_RESULTS_ARRAY],
    ['paObjects', PWBEM_REFRESHED_OBJECT_ARRAY],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.13.2 IWbemRemoteRefresher::StopRefreshing (Opnum 4)
export class IWbemRemoteRefresher_StopRefreshing extends DCOMCALL {
  static opnum = 4;
  static structure: NDRField[] = [
    ['lNumIds', LONG],
    ['aplIds', PULONG_ARRAY],
    ['lFlags', LONG],
  ];
}

export class IWbemRemoteRefresher_StopRefreshingResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.14 IWbemShutdown Interface
// 3.1.4.14.1 IWbemShutdown::Shutdown (Opnum 3)
export class IWbemShutdown_Shutdown extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['reserved1', LONG],
    ['reserved2', ULONG],
    ['reserved3', PMInterfacePointer],
  ];
}

export class IWbemShutdown_ShutdownResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.15 IUnsecuredApartment Interface
// 3.1.4.15.1 IUnsecuredApartment::CreateObjectStub (Opnum 3)
export class IUnsecuredApartment_CreateObjectStub extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['reserved1', PMInterfacePointer],
  ];
}

export class IUnsecuredApartment_CreateObjectStubResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['reserved2', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// 3.1.4.16 IWbemUnsecuredApartment Interface
// 3.1.4.16.1 IWbemUnsecuredApartment::CreateSinkStub (Opnum 3)
export class IWbemUnsecuredApartment_CreateSinkStub extends DCOMCALL {
  static opnum = 3;
  static structure: NDRField[] = [
    ['reserved1', PMInterfacePointer],
    ['reserved2', DWORD],
    ['reserved3', LPWSTR],
  ];
}

export class IWbemUnsecuredApartment_CreateSinkStubResponse extends DCOMANSWER {
  static structure: NDRField[] = [
    ['reserved4', PMInterfacePointer],
    ['ErrorCode', error_status_t],
  ];
}

// ============================================================================
// OPNUMs and their corresponding structures (module-private)
// ============================================================================
const OPNUMS: Record<string, unknown> = {};

// ============================================================================
// HELPER FUNCTIONS AND INTERFACES
// ============================================================================
function checkNullString(str: unknown): unknown {
  if (str === NULL) {
    return str;
  }
  const s = str as string;
  if (s.charAt(s.length - 1) !== '\x00') {
    return s + '\x00';
  }
  return s;
}

export class IWbemClassObject extends IRemUnknown {
  protected override _iid: Buffer;
  private __iWbemServices: IWbemServices | null;
  private __methods: Record<string, MethodItem> | null = null;
  encodingUnit!: ENCODING_UNIT;

  constructor(iface: INTERFACE, iWbemServices?: IWbemServices | null) {
    super(iface);
    this._iid = IID_IWbemClassObject;
    this.__iWbemServices = iWbemServices ?? null;

    const objRef = this.getObjRef();
    if (objRef) {
      const objRefCustom = new OBJREF_CUSTOM(objRef);
      const pObjectData = objRefCustom.get('pObjectData') as Buffer;
      this.encodingUnit = new ENCODING_UNIT(pObjectData);
      this.parseObject();
      if ((this.encodingUnit.fields['ObjectBlock']) && !((this.encodingUnit.fields['ObjectBlock']) as OBJECT_BLOCK).isInstance()) {
        this.createMethods(this.getClassName(), this.getMethods());
      } else {
        this.createProperties(this.getProperties());
      }
    }
  }

  parseObject(): void {
    ((this.encodingUnit.fields['ObjectBlock']) as OBJECT_BLOCK).parseObject();
  }

  getObject(): OBJECT_BLOCK {
    return (this.encodingUnit.fields['ObjectBlock']) as OBJECT_BLOCK;
  }

  getClassName(): string {
    const objBlock = (this.encodingUnit.fields['ObjectBlock']) as OBJECT_BLOCK;
    if (!objBlock.isInstance()) {
      return ((objBlock.fields['ClassType'] as any)['CurrentClass'] as CLASS_AND_METHODS_PART).getClassName().split(' ')[0]!;
    } else {
      return ((objBlock.fields['InstanceType'] as any)['CurrentClass'] as CLASS_AND_METHODS_PART).getClassName().split(' ')[0]!;
    }
  }

  printInformation(): void {
    ((this.encodingUnit.fields['ObjectBlock']) as OBJECT_BLOCK).printInformation();
  }

  getProperties(): Record<string, PropertyItem> {
    const objBlock = (this.encodingUnit.fields['ObjectBlock']) as OBJECT_BLOCK;
    if (objBlock.ctCurrent == null) {
      return {};
    }
    return objBlock.ctCurrent.properties;
  }

  getMethods(): Record<string, MethodItem> {
    const objBlock = (this.encodingUnit.fields['ObjectBlock']) as OBJECT_BLOCK;
    if (objBlock.ctCurrent == null) {
      return {};
    }
    return objBlock.ctCurrent.methods;
  }

  createProperties(properties: Record<string, PropertyItem>): void {
    for (const property of Object.keys(properties)) {
      const cimType = properties[property]!.type & (~Inherited);
      let value: unknown;
      if (cimType === CIM_TYPE_ENUM.CIM_TYPE_OBJECT && properties[property]!.value != null) {
        const objRefCustom = new OBJREF_CUSTOM();
        objRefCustom.set('iid', this._iid);
        objRefCustom.set('clsid', CLSID_WbemClassObject);
        objRefCustom.set('cbExtension', 0);
        const propVal = properties[property]!.value as Structure;
        objRefCustom.set('ObjectReferenceSize', propVal.getData().length);
        objRefCustom.set('pObjectData', propVal);
        value = new IWbemClassObject(
          new INTERFACE({
            cinstance: this.getCinstance(),
            objRef: objRefCustom.getData() as unknown as Buffer,
            ipidRemUnknown: this.getIpidRemUnknown(),
            oxid: this.getOxid(),
            target: this.getTarget(),
          }),
        );
      } else if (cimType === CIM_TYPE_ENUM.CIM_ARRAY_OBJECT) {
        if (Array.isArray(properties[property]!.value)) {
          value = [];
          for (const item of properties[property]!.value as Structure[]) {
            const objRefCustom = new OBJREF_CUSTOM();
            objRefCustom.set('iid', this._iid);
            objRefCustom.set('clsid', CLSID_WbemClassObject);
            objRefCustom.set('cbExtension', 0);
            objRefCustom.set('ObjectReferenceSize', item.getData().length);
            objRefCustom.set('pObjectData', item);
            const wbemClass = new IWbemClassObject(
              new INTERFACE({
                cinstance: this.getCinstance(),
                objRef: objRefCustom.getData() as unknown as Buffer,
                ipidRemUnknown: this.getIpidRemUnknown(),
                oxid: this.getOxid(),
                target: this.getTarget(),
              }),
            );
            (value as IWbemClassObject[]).push(wbemClass);
          }
        } else {
          value = properties[property]!.value;
        }
      } else {
        value = properties[property]!.value;
      }
      (this as Record<string, unknown>)[property] = value;
    }
  }

  createMethods(_classOrInstance: string, methods: Record<string, MethodItem>): void {
    for (const methodName of Object.keys(methods)) {
      (this as Record<string, unknown>)[methodName] = (...args: unknown[]) => {
        return this.__execMethodInternal(_classOrInstance, methods[methodName]!, args);
      };
    }
  }

  private static __ndEntry(index: number, nullDefault: boolean, inheritedDefault: boolean): number {
    return ((nullDefault ? 1 : 0) << 1 | (inheritedDefault ? 1 : 0)) << (2 * index);
  }

  private async __execMethodInternal(
    classOrInstance: string,
    methodDefinition: MethodItem,
    args: unknown[],
  ): Promise<IWbemClassObject | null> {
    if (!this.__iWbemServices) {
      return null;
    }

    let objRefCustomIn: unknown = NULL;
    if (methodDefinition.InParams != null && methodDefinition.InParamsRaw != null) {
      const inParamsDef = methodDefinition.InParams;
      const paramKeys = Object.keys(inParamsDef).sort(
        (a, b) => inParamsDef[a]!.order - inParamsDef[b]!.order,
      );

      const encodingUnit = new ENCODING_UNIT();
      const inParams = new OBJECT_BLOCK();
      inParams.structure = [...OBJECT_BLOCK.instanceType];
      inParams.fields['ObjectFlags'] = 0x02;
      inParams.fields['Decoration'] = Buffer.alloc(0);

      const instanceType = new INSTANCE_TYPE();
      instanceType.fields['CurrentClass'] = Buffer.alloc(0);
      instanceType.fields['InstanceQualifierSet'] = Buffer.from([0x04, 0x00, 0x00, 0x00, 0x01]);

      const parametersClass = new ENCODED_STRING();
      parametersClass.fields['Encoded_String_Flag'] = 0;
      parametersClass.structure = [...(ENCODED_STRING as any).tascii];
      parametersClass.fields['Character'] = Buffer.from('__PARAMETERS\0');
      parametersClass.data = null;
      let instanceHeap = parametersClass.getData();
      let curHeapPtr = instanceHeap.length;

      let ndTable = 0;
      let valueTable = Buffer.alloc(0);

      for (let i = 0; i < paramKeys.length; i++) {
        const paramDef = inParamsDef[paramKeys[i]!]!;
        const inArg = i < args.length ? args[i] : null;
        const pType = paramDef.type & (~(CIM_ARRAY_FLAG | Inherited));
        let packStr: string;
        if (paramDef.type & CIM_ARRAY_FLAG) {
          packStr = HEAPREF.replace(/=.*$/, '');
        } else {
          packStr = CIM_TYPES_REF[pType]!.replace(/=.*$/, '');
        }

        if (inArg === null || inArg === undefined) {
          ndTable |= IWbemClassObject.__ndEntry(i, true, true);
          valueTable = Buffer.concat([valueTable, Buffer.alloc(calcsize(packStr))]);
        } else if (paramDef.type & CIM_ARRAY_FLAG) {
          if (pType === CIM_TYPE_ENUM.CIM_TYPE_STRING || pType === CIM_TYPE_ENUM.CIM_TYPE_DATETIME ||
              pType === CIM_TYPE_ENUM.CIM_TYPE_REFERENCE || pType === CIM_TYPE_ENUM.CIM_TYPE_OBJECT) {
            const arr = inArg as unknown[];
            const arraySize = structPack(HEAPREF.replace(/=.*$/, ''), arr.length);
            const arrayItems: Buffer[] = [];
            for (const curVal of arr) {
              const strIn = new ENCODED_STRING();
              if (typeof curVal === 'string') {
                strIn.fields['Encoded_String_Flag'] = 0x01;
                strIn.structure = [...(ENCODED_STRING as any).tunicode];
                strIn.fields['Character'] = Buffer.from(curVal, 'utf16le');
              } else {
                strIn.fields['Character'] = curVal as Buffer;
              }
              strIn.data = null;
              arrayItems.push(strIn.getData());
            }
            let curStrHeapPtr = curHeapPtr + 4;
            let arrayHeapPtrValues = Buffer.alloc(0);
            let arrayValueTable = Buffer.alloc(0);
            for (let j = 0; j < arrayItems.length; j++) {
              arrayHeapPtrValues = Buffer.concat([arrayHeapPtrValues,
                structPack('<L', curStrHeapPtr + 4 * (arrayItems.length - j) + arrayValueTable.length)]);
              arrayValueTable = Buffer.concat([arrayValueTable, arrayItems[j]!]);
              curStrHeapPtr += 4;
            }
            valueTable = Buffer.concat([valueTable, structPack('<L', curHeapPtr)]);
            instanceHeap = Buffer.concat([instanceHeap, arraySize, arrayHeapPtrValues, arrayValueTable]);
            curHeapPtr = instanceHeap.length;
          } else {
            const arr = inArg as number[];
            const arraySize = structPack(HEAPREF.replace(/=.*$/, ''), arr.length);
            valueTable = Buffer.concat([valueTable, structPack('<L', curHeapPtr)]);
            let arrayData = arraySize;
            for (const curVal of arr) {
              arrayData = Buffer.concat([arrayData, structPack(packStr, curVal)]);
            }
            instanceHeap = Buffer.concat([instanceHeap, arrayData]);
            curHeapPtr = instanceHeap.length;
          }
        } else if (pType === CIM_TYPE_ENUM.CIM_TYPE_OBJECT) {
          if (inArg != null) {
            valueTable = Buffer.concat([valueTable, structPack('<L', curHeapPtr)]);
            const marshaledObject = (inArg as any).marshalMe();
            const objEncLen = structPack('<L', marshaledObject.fields['pObjectData'].fields['ObjectEncodingLength']);
            const objBlock = (marshaledObject.fields['pObjectData'].fields['ObjectBlock'] as Structure).getData();
            instanceHeap = Buffer.concat([instanceHeap, objEncLen, objBlock]);
            curHeapPtr = instanceHeap.length;
          } else {
            valueTable = Buffer.concat([valueTable, Buffer.alloc(4)]);
            ndTable |= IWbemClassObject.__ndEntry(i, true, true);
          }
        } else if (pType !== CIM_TYPE_ENUM.CIM_TYPE_STRING &&
                   pType !== CIM_TYPE_ENUM.CIM_TYPE_DATETIME &&
                   pType !== CIM_TYPE_ENUM.CIM_TYPE_REFERENCE) {
          valueTable = Buffer.concat([valueTable, structPack(packStr, Number(inArg))]);
        } else {
          const strIn = new ENCODED_STRING();
          if (typeof inArg === 'string') {
            strIn.fields['Encoded_String_Flag'] = 0x01;
            strIn.structure = [...(ENCODED_STRING as any).tunicode];
            strIn.fields['Character'] = Buffer.from(inArg, 'utf16le');
          } else {
            strIn.fields['Character'] = inArg as Buffer;
          }
          strIn.data = null;
          valueTable = Buffer.concat([valueTable, structPack('<L', curHeapPtr)]);
          instanceHeap = Buffer.concat([instanceHeap, strIn.getData()]);
          curHeapPtr = instanceHeap.length;
        }
      }

      const ndTableLen = Math.floor((paramKeys.length - 1) / 4) + 1;
      const packedNdTable = Buffer.alloc(ndTableLen);
      for (let i = 0; i < ndTableLen; i++) {
        packedNdTable[i] = (ndTable >> (i * 8)) & 0xff;
      }

      instanceType.fields['NdTable_ValueTable'] = Buffer.concat([packedNdTable, valueTable]);

      const heapRecord = new HEAP();
      heapRecord.fields['HeapLength'] = instanceHeap.length | 0x80000000;
      heapRecord.fields['HeapItem'] = instanceHeap;
      heapRecord.data = null;
      instanceType.fields['InstanceHeap'] = heapRecord;

      instanceType.data = null;
      instanceType.fields['EncodingLength'] = instanceType.getData().length;
      instanceType.data = null;

      const inMethods = (methodDefinition.InParamsRaw!.fields['ClassType'] as Structure)
        .fields['CurrentClass'] as Structure;
      const inMethodsClassPart = inMethods.fields['ClassPart'] as Structure;
      const classHeader = inMethodsClassPart.fields['ClassHeader'] as Structure;
      classHeader.fields['EncodingLength'] = inMethodsClassPart.getData().length;
      classHeader.data = null;
      inMethodsClassPart.data = null;
      instanceType.fields['CurrentClass'] = inMethodsClassPart;
      instanceType.data = null;

      inParams.fields['InstanceType'] = instanceType.getData();
      inParams.data = null;

      encodingUnit.fields['ObjectBlock'] = inParams;
      encodingUnit.fields['ObjectEncodingLength'] = inParams.getData().length;
      encodingUnit.data = null;

      const objRefCustom = new OBJREF_CUSTOM();
      objRefCustom.set('iid', this._iid);
      objRefCustom.set('clsid', CLSID_WbemClassObject);
      objRefCustom.set('cbExtension', 0);
      const euData = encodingUnit.getData();
      objRefCustom.set('ObjectReferenceSize', euData.length);
      objRefCustom.set('pObjectData', euData);
      objRefCustomIn = objRefCustom;
    }

    return this.__iWbemServices.ExecMethod(
      classOrInstance,
      methodDefinition.name,
      0,
      NULL,
      objRefCustomIn,
    );
  }
}

export class IWbemLoginClientID extends IRemUnknown {
  protected override _iid: Buffer;

  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IWbemLoginClientID;
  }

  async SetClientInfo(wszClientMachine: string, lClientProcId = 1234): Promise<NDRCALL> {
    const request = new IWbemLoginClientID_SetClientInfo();
    request.set('wszClientMachine', checkNullString(wszClientMachine));
    request.set('lClientProcId', lClientProcId);
    request.set('lReserved', 0);
    return this.request(request, this._iid, this.getIPid()!);
  }
}

export class IWbemLoginHelper extends IRemUnknown {
  protected override _iid: Buffer;

  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IWbemLoginHelper;
  }

  async SetEvent(sEventToSet: string): Promise<NDRCALL> {
    const request = new IWbemLoginHelper_SetEvent();
    request.set('sEventToSet', sEventToSet);
    return this.request(request, this._iid, this.getIPid()!);
  }
}

export class IWbemWCOSmartEnum extends IRemUnknown {
  protected override _iid: Buffer;

  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IWbemWCOSmartEnum;
  }

  async Next(proxyGUID: Buffer, lTimeout: number, uCount: number): Promise<NDRCALL> {
    const request = new IWbemWCOSmartEnum_Next();
    request.set('proxyGUID', proxyGUID);
    request.set('lTimeout', lTimeout);
    request.set('uCount', uCount);
    return this.request(request, this._iid, this.getIPid()!);
  }
}

export class IWbemFetchSmartEnum extends IRemUnknown {
  protected override _iid: Buffer;

  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IWbemFetchSmartEnum;
  }

  async GetSmartEnum(): Promise<NDRCALL> {
    const request = new IWbemFetchSmartEnum_GetSmartEnum();
    return this.request(request, this._iid, this.getIPid()!);
  }
}

export class IWbemCallResult extends IRemUnknown {
  protected override _iid: Buffer;

  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IWbemCallResult;
  }

  async GetResultObject(lTimeout: number): Promise<NDRCALL> {
    const request = new IWbemCallResult_GetResultObject();
    request.set('lTimeout', lTimeout);
    return this.request(request, this._iid, this.getIPid()!);
  }

  async GetResultString(lTimeout: number): Promise<NDRCALL> {
    const request = new IWbemCallResult_GetResultString();
    request.set('lTimeout', lTimeout);
    return this.request(request, this._iid, this.getIPid()!);
  }

  async GetResultServices(lTimeout: number): Promise<NDRCALL> {
    const request = new IWbemCallResult_GetResultServices();
    request.set('lTimeout', lTimeout);
    return this.request(request, this._iid, this.getIPid()!);
  }

  async GetCallStatus(lTimeout: number): Promise<unknown> {
    const request = new IWbemCallResult_GetCallStatus();
    request.set('lTimeout', lTimeout);
    const resp = await this.request(request, this._iid, this.getIPid()!);
    return resp.get('plStatus');
  }
}

export class IEnumWbemClassObject extends IRemUnknown {
  protected override _iid: Buffer;
  private __iWbemServices: IWbemServices | null;

  constructor(iface: INTERFACE, iWbemServices?: IWbemServices | null) {
    super(iface);
    this._iid = IID_IEnumWbemClassObject;
    this.__iWbemServices = iWbemServices ?? null;
  }

  async Reset(): Promise<NDRCALL> {
    const request = new IEnumWbemClassObject_Reset();
    return this.request(request, this._iid, this.getIPid()!);
  }

  async Next(lTimeout: number, uCount: number): Promise<IWbemClassObject[]> {
    const request = new IEnumWbemClassObject_Next();
    request.set('lTimeout', lTimeout);
    request.set('uCount', uCount);
    const resp = await this.request(request, this._iid, this.getIPid()!);
    const interfaces: IWbemClassObject[] = [];
    const apObjects = resp.get('apObjects') as unknown[];
    if (Array.isArray(apObjects)) {
      for (const iface of apObjects) {
        const abData = (iface as any).get('abData') as number[];
        interfaces.push(
          new IWbemClassObject(
            new INTERFACE({
              cinstance: this.getCinstance(),
              objRef: Buffer.from(abData),
              ipidRemUnknown: this.getIpidRemUnknown(),
              oxid: this.getOxid(),
              target: this.getTarget(),
            }),
            this.__iWbemServices,
          ),
        );
      }
    }
    return interfaces;
  }

  async NextAsync(lTimeout: number, pSink: unknown): Promise<NDRCALL> {
    const request = new IEnumWbemClassObject_NextAsync();
    request.set('lTimeout', lTimeout);
    request.set('pSink', pSink);
    return this.request(request, this._iid, this.getIPid()!);
  }

  async Clone(): Promise<NDRCALL> {
    const request = new IEnumWbemClassObject_Clone();
    return this.request(request, this._iid, this.getIPid()!);
  }

  async Skip(lTimeout: number, uCount: number): Promise<NDRCALL> {
    const request = new IEnumWbemClassObject_Skip();
    request.set('lTimeout', lTimeout);
    request.set('uCount', uCount);
    return this.request(request, this._iid, this.getIPid()!);
  }
}

export class IWbemServices extends IRemUnknown {
  protected override _iid: Buffer;

  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IWbemServices;
  }

  async OpenNamespace(strNamespace: string, lFlags = 0, pCtx: unknown = NULL): Promise<NDRCALL> {
    const request = new IWbemServices_OpenNamespace();
    request.set('strNamespace', strNamespace);
    request.set('lFlags', lFlags);
    request.set('pCtx', pCtx);
    return this.request(request, this._iid, this.getIPid()!);
  }

  async CancelAsyncCall(objectSink: unknown): Promise<unknown> {
    const request = new IWbemServices_CancelAsyncCall();
    request.set('IWbemObjectSink', objectSink);
    const resp = await this.request(request, this._iid, this.getIPid()!);
    return resp.get('ErrorCode');
  }

  async QueryObjectSink(): Promise<INTERFACE> {
    const request = new IWbemServices_QueryObjectSink();
    request.set('lFlags', 0);
    const resp = await this.request(request, this._iid, this.getIPid()!);
    const ppResponseHandler = resp.get('ppResponseHandler') as any;
    return new INTERFACE({
      cinstance: this.getCinstance(),
      objRef: Buffer.from(ppResponseHandler.get('abData') as number[]),
      ipidRemUnknown: this.getIpidRemUnknown(),
      target: this.getTarget(),
    });
  }

  async GetObject(strObjectPath: string, lFlags = 0, pCtx: unknown = NULL): Promise<[IWbemClassObject, IWbemCallResult | typeof NULL]> {
    const request = new IWbemServices_GetObject();
    request.set('strObjectPath', strObjectPath);
    request.set('lFlags', lFlags);
    request.set('pCtx', pCtx);
    const resp = await this.request(request, this._iid, this.getIPid()!);

    const errorCode = resp.get('ErrorCode') as number;
    if (errorCode !== 0) {
      throw new Error(`GetObject('${strObjectPath}') failed: 0x${errorCode.toString(16)}`);
    }

    const ppObjField = resp.fields['ppObject'] as any;
    const ppObjRefId = ppObjField?.fields?.['ReferentID'] ?? ppObjField?.get?.('ReferentID') ?? 0;
    if (ppObjRefId === 0 || ppObjRefId === 0n) {
      throw new Error(`GetObject('${strObjectPath}') returned NULL ppObject (ErrorCode=0, ipid=${this.getIPid()?.toString('hex')}, oxid=${this.getOxid()})`);
    }

    const ppObject = resp.get('ppObject') as any;
    const ppObjectInstance = new IWbemClassObject(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.from(ppObject.get('abData') as number[]),
        ipidRemUnknown: this.getIpidRemUnknown(),
        oxid: this.getOxid(),
        target: this.getTarget(),
      }),
      this,
    );

    let ppcallResult: IWbemCallResult | typeof NULL = NULL;
    const ppCallField = resp.fields['ppCallResult'] as any;
    const ppCallRefId = ppCallField?.fields?.['ReferentID'] ?? ppCallField?.get?.('ReferentID') ?? 0;
    if (ppCallRefId !== 0 && ppCallRefId !== 0n) {
      const ppCallResultObj = resp.get('ppCallResult') as any;
      ppcallResult = new IWbemCallResult(
        new INTERFACE({
          cinstance: this.getCinstance(),
          objRef: Buffer.from(ppCallResultObj.get('abData') as number[]),
          ipidRemUnknown: this.getIpidRemUnknown(),
          target: this.getTarget(),
        }),
      );
    }
    return [ppObjectInstance, ppcallResult];
  }

  async PutClass(pObject: unknown, lFlags = 0, pCtx: unknown = NULL): Promise<NDRCALL> {
    const request = new IWbemServices_PutClass();
    request.set('pObject', pObject);
    request.set('lFlags', lFlags);
    request.set('pCtx', pCtx);
    request.set('pResponseHandler', NULL);
    request.set('ppCallResult', NULL);
    return this.request(request, this._iid, this.getIPid()!);
  }

  async DeleteClass(strClass: string, lFlags = 0, pCtx: unknown = NULL): Promise<NDRCALL> {
    const request = new IWbemServices_DeleteClass();
    request.set('strClass', checkNullString(strClass));
    request.set('lFlags', lFlags);
    request.set('pCtx', pCtx);
    request.set('ppCallResult', NULL);
    return this.request(request, this._iid, this.getIPid()!);
  }

  async CreateClassEnum(strSuperClass: string, lFlags = 0, pCtx: unknown = NULL): Promise<NDRCALL> {
    const request = new IWbemServices_CreateClassEnum();
    request.set('strSuperClass', checkNullString(strSuperClass));
    request.set('lFlags', lFlags);
    request.set('pCtx', pCtx);
    return this.request(request, this._iid, this.getIPid()!);
  }

  async PutInstance(pInst: unknown, lFlags = 0, pCtx: unknown = NULL): Promise<IWbemCallResult> {
    const request = new IWbemServices_PutInstance();
    if (pInst === NULL) {
      request.set('pInst', pInst);
    } else {
      const instObj = pInst as { getData(): Buffer };
      const pInstField = request.get('pInst') as any;
      pInstField.set('ulCntData', instObj.getData().length);
      pInstField.set('abData', Array.from(instObj.getData()));
    }
    request.set('lFlags', lFlags);
    request.set('pCtx', pCtx);
    request.set('ppCallResult', NULL);
    const resp = await this.request(request, this._iid, this.getIPid()!);
    const ppCallResult = resp.get('ppCallResult') as any;
    if (!ppCallResult || typeof ppCallResult.get !== 'function') {
      const errorCode = (resp.get('ErrorCode') as number) ?? 0;
      return { GetCallStatus: async () => errorCode } as unknown as IWbemCallResult;
    }
    return new IWbemCallResult(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.from(ppCallResult.get('abData') as number[]),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }

  async DeleteInstance(strObjectPath: string, lFlags = 0, pCtx: unknown = NULL): Promise<IWbemCallResult> {
    const request = new IWbemServices_DeleteInstance();
    request.set('strObjectPath', checkNullString(strObjectPath));
    request.set('lFlags', lFlags);
    request.set('pCtx', pCtx);
    request.set('ppCallResult', NULL);
    const resp = await this.request(request, this._iid, this.getIPid()!);
    const ppCallResult2 = resp.get('ppCallResult') as any;
    if (!ppCallResult2 || typeof ppCallResult2.get !== 'function') {
      const errorCode = (resp.get('ErrorCode') as number) ?? 0;
      return { GetCallStatus: async () => errorCode } as unknown as IWbemCallResult;
    }
    return new IWbemCallResult(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.from(ppCallResult2.get('abData') as number[]),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }

  async CreateInstanceEnum(strSuperClass: string, lFlags = 0, pCtx: unknown = NULL): Promise<IEnumWbemClassObject> {
    const request = new IWbemServices_CreateInstanceEnum();
    request.set('strSuperClass', strSuperClass);
    request.set('lFlags', lFlags);
    request.set('pCtx', pCtx);
    const resp = await this.request(request, this._iid, this.getIPid()!);
    const ppEnum = resp.get('ppEnum') as any;
    return new IEnumWbemClassObject(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.from(ppEnum.get('abData') as number[]),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }

  async ExecQuery(strQuery: string, lFlags = 0, pCtx: unknown = NULL): Promise<IEnumWbemClassObject> {
    const request = new IWbemServices_ExecQuery();
    request.set('strQueryLanguage', checkNullString('WQL'));
    request.set('strQuery', checkNullString(strQuery));
    request.set('lFlags', lFlags);
    request.set('pCtx', pCtx);
    const resp = await this.request(request, this._iid, this.getIPid()!);
    const ppEnum = resp.get('ppEnum') as any;
    return new IEnumWbemClassObject(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.from(ppEnum.get('abData') as number[]),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
      this,
    );
  }

  async ExecNotificationQuery(strQuery: string, lFlags = 0, pCtx: unknown = NULL): Promise<IEnumWbemClassObject> {
    const request = new IWbemServices_ExecNotificationQuery();
    request.set('strQueryLanguage', checkNullString('WQL'));
    request.set('strQuery', checkNullString(strQuery));
    request.set('lFlags', lFlags);
    request.set('pCtx', pCtx);
    const resp = await this.request(request, this._iid, this.getIPid()!);
    const ppEnum = resp.get('ppEnum') as any;
    return new IEnumWbemClassObject(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.from(ppEnum.get('abData') as number[]),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
      this,
    );
  }

  async ExecMethod(
    strObjectPath: string,
    strMethodName: string,
    lFlags = 0,
    pCtx: unknown = NULL,
    pInParams: unknown = NULL,
    ppOutParams: unknown = NULL,
  ): Promise<IWbemClassObject> {
    const request = new IWbemServices_ExecMethod();
    request.set('strObjectPath', checkNullString(strObjectPath));
    request.set('strMethodName', checkNullString(strMethodName));
    request.set('lFlags', lFlags);
    request.set('pCtx', pCtx);
    if (pInParams === NULL) {
      request.set('pInParams', pInParams);
    } else {
      const inParamsObj = pInParams as { getData(): Buffer };
      const pInParamsField = request.get('pInParams') as any;
      pInParamsField.set('ulCntData', inParamsObj.getData().length);
      pInParamsField.set('abData', Array.from(inParamsObj.getData()));
    }

    request.fields['ppCallResult'] = NULL;
    if (ppOutParams === NULL) {
      (request.fields['ppOutParams'] as any).fields['Data'] = NULL;
    } else {
      const outParamsObj = ppOutParams as { getData(): Buffer };
      const ppOutParamsField = request.get('ppOutParams') as any;
      ppOutParamsField.set('ulCntData', outParamsObj.getData().length);
      ppOutParamsField.set('abData', Array.from(outParamsObj.getData()));
    }
    const resp = await this.request(request, this._iid, this.getIPid()!);
    const respOutParams = resp.get('ppOutParams') as any;
    return new IWbemClassObject(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.from(respOutParams.get('abData') as number[]),
        ipidRemUnknown: this.getIpidRemUnknown(),
        oxid: this.getOxid(),
        target: this.getTarget(),
      }),
    );
  }
}

export class IWbemLevel1Login extends IRemUnknown {
  protected override _iid: Buffer;

  constructor(iface: INTERFACE) {
    super(iface);
    this._iid = IID_IWbemLevel1Login;
  }

  async EstablishPosition(): Promise<unknown> {
    const request = new IWbemLevel1Login_EstablishPosition();
    request.set('reserved1', NULL);
    request.set('reserved2', 0);
    const resp = await this.request(request, this._iid, this.getIPid()!);
    return resp.get('LocaleVersion');
  }

  async RequestChallenge(): Promise<unknown> {
    const request = new IWbemLevel1Login_RequestChallenge();
    request.set('reserved1', NULL);
    request.set('reserved2', NULL);
    const resp = await this.request(request, this._iid, this.getIPid()!);
    return resp.get('reserved3');
  }

  async WBEMLogin(): Promise<unknown> {
    const request = new IWbemLevel1Login_WBEMLogin();
    request.set('reserved1', NULL);
    request.set('reserved2', NULL);
    request.set('reserved3', 0);
    request.set('reserved4', NULL);
    const resp = await this.request(request, this._iid, this.getIPid()!);
    return resp.get('reserved5');
  }

  async NTLMLogin(wszNetworkResource: string, wszPreferredLocale: string, pCtx: unknown): Promise<IWbemServices> {
    const request = new IWbemLevel1Login_NTLMLogin();
    request.set('wszNetworkResource', checkNullString(wszNetworkResource));
    request.set('wszPreferredLocale', checkNullString(wszPreferredLocale));
    request.set('lFlags', 0);
    request.set('pCtx', pCtx);
    const resp = await this.request(request, this._iid, this.getIPid()!);
    const ppNamespace = resp.get('ppNamespace') as any;
    return new IWbemServices(
      new INTERFACE({
        cinstance: this.getCinstance(),
        objRef: Buffer.from(ppNamespace.get('abData') as number[]),
        ipidRemUnknown: this.getIpidRemUnknown(),
        target: this.getTarget(),
      }),
    );
  }
}

// Link request classes to their response classes
(IWbemLevel1Login_EstablishPosition as any).Response = IWbemLevel1Login_EstablishPositionResponse;
(IWbemLevel1Login_RequestChallenge as any).Response = IWbemLevel1Login_RequestChallengeResponse;
(IWbemLevel1Login_WBEMLogin as any).Response = IWbemLevel1Login_WBEMLoginResponse;
(IWbemLevel1Login_NTLMLogin as any).Response = IWbemLevel1Login_NTLMLoginResponse;
(IWbemObjectSink_Indicate as any).Response = IWbemObjectSink_IndicateResponse;
(IWbemObjectSink_SetStatus as any).Response = IWbemObjectSink_SetStatusResponse;
(IWbemServices_OpenNamespace as any).Response = IWbemServices_OpenNamespaceResponse;
(IWbemServices_CancelAsyncCall as any).Response = IWbemServices_CancelAsyncCallResponse;
(IWbemServices_QueryObjectSink as any).Response = IWbemServices_QueryObjectSinkResponse;
(IWbemServices_GetObject as any).Response = IWbemServices_GetObjectResponse;
(IWbemServices_GetObjectAsync as any).Response = IWbemServices_GetObjectAsyncResponse;
(IWbemServices_PutClass as any).Response = IWbemServices_PutClassResponse;
(IWbemServices_PutClassAsync as any).Response = IWbemServices_PutClassAsyncResponse;
(IWbemServices_DeleteClass as any).Response = IWbemServices_DeleteClassResponse;
(IWbemServices_DeleteClassAsync as any).Response = IWbemServices_DeleteClassAsyncResponse;
(IWbemServices_CreateClassEnum as any).Response = IWbemServices_CreateClassEnumResponse;
(IWbemServices_CreateClassEnumAsync as any).Response = IWbemServices_CreateClassEnumAsyncResponse;
(IWbemServices_PutInstance as any).Response = IWbemServices_PutInstanceResponse;
(IWbemServices_PutInstanceAsync as any).Response = IWbemServices_PutInstanceAsyncResponse;
(IWbemServices_DeleteInstance as any).Response = IWbemServices_DeleteInstanceResponse;
(IWbemServices_DeleteInstanceAsync as any).Response = IWbemServices_DeleteInstanceAsyncResponse;
(IWbemServices_CreateInstanceEnum as any).Response = IWbemServices_CreateInstanceEnumResponse;
(IWbemServices_CreateInstanceEnumAsync as any).Response = IWbemServices_CreateInstanceEnumAsyncResponse;
(IWbemServices_ExecQuery as any).Response = IWbemServices_ExecQueryResponse;
(IWbemServices_ExecQueryAsync as any).Response = IWbemServices_ExecQueryAsyncResponse;
(IWbemServices_ExecNotificationQuery as any).Response = IWbemServices_ExecNotificationQueryResponse;
(IWbemServices_ExecNotificationQueryAsync as any).Response = IWbemServices_ExecNotificationQueryAsyncResponse;
(IWbemServices_ExecMethod as any).Response = IWbemServices_ExecMethodResponse;
(IWbemServices_ExecMethodAsync as any).Response = IWbemServices_ExecMethodAsyncResponse;
(IEnumWbemClassObject_Reset as any).Response = IEnumWbemClassObject_ResetResponse;
(IEnumWbemClassObject_Next as any).Response = IEnumWbemClassObject_NextResponse;
(IEnumWbemClassObject_NextAsync as any).Response = IEnumWbemClassObject_NextAsyncResponse;
(IEnumWbemClassObject_Clone as any).Response = IEnumWbemClassObject_CloneResponse;
(IEnumWbemClassObject_Skip as any).Response = IEnumWbemClassObject_SkipResponse;
(IWbemCallResult_GetResultObject as any).Response = IWbemCallResult_GetResultObjectResponse;
(IWbemCallResult_GetResultString as any).Response = IWbemCallResult_GetResultStringResponse;
(IWbemCallResult_GetResultServices as any).Response = IWbemCallResult_GetResultServicesResponse;
(IWbemCallResult_GetCallStatus as any).Response = IWbemCallResult_GetCallStatusResponse;
(IWbemFetchSmartEnum_GetSmartEnum as any).Response = IWbemFetchSmartEnum_GetSmartEnumResponse;
(IWbemWCOSmartEnum_Next as any).Response = IWbemWCOSmartEnum_NextResponse;
(IWbemLoginClientID_SetClientInfo as any).Response = IWbemLoginClientID_SetClientInfoResponse;
(IWbemLoginHelper_SetEvent as any).Response = IWbemLoginHelper_SetEventResponse;
(IWbemBackupRestore_Backup as any).Response = IWbemBackupRestore_BackupResponse;
(IWbemBackupRestore_Restore as any).Response = IWbemBackupRestore_RestoreResponse;
(IWbemBackupRestoreEx_Pause as any).Response = IWbemBackupRestoreEx_PauseResponse;
(IWbemBackupRestoreEx_Resume as any).Response = IWbemBackupRestoreEx_ResumeResponse;
(IWbemRefreshingServices_AddObjectToRefresher as any).Response = IWbemRefreshingServices_AddObjectToRefresherResponse;
(IWbemRefreshingServices_AddObjectToRefresherByTemplate as any).Response = IWbemRefreshingServices_AddObjectToRefresherByTemplateResponse;
(IWbemRefreshingServices_AddEnumToRefresher as any).Response = IWbemRefreshingServices_AddEnumToRefresherResponse;
(IWbemRefreshingServices_RemoveObjectFromRefresher as any).Response = IWbemRefreshingServices_RemoveObjectFromRefresherResponse;
(IWbemRefreshingServices_GetRemoteRefresher as any).Response = IWbemRefreshingServices_GetRemoteRefresherResponse;
(IWbemRefreshingServices_ReconnectRemoteRefresher as any).Response = IWbemRefreshingServices_ReconnectRemoteRefresherResponse;
(IWbemRemoteRefresher_RemoteRefresh as any).Response = IWbemRemoteRefresher_RemoteRefreshResponse;
(IWbemRemoteRefresher_StopRefreshing as any).Response = IWbemRemoteRefresher_StopRefreshingResponse;
(IWbemShutdown_Shutdown as any).Response = IWbemShutdown_ShutdownResponse;
(IUnsecuredApartment_CreateObjectStub as any).Response = IUnsecuredApartment_CreateObjectStubResponse;
(IWbemUnsecuredApartment_CreateSinkStub as any).Response = IWbemUnsecuredApartment_CreateSinkStubResponse;

// Impacket - Collection of TypeScript classes for working with network protocols.
//
// [MS-NSPI]: Name Service Provider Interface (NSPI) Protocol
// [MS-OXNSPI]: Exchange Server Name Service Provider Interface (NSPI) Protocol
//
// Ported from impacket/dcerpc/v5/nspi.py

import { uuidtupToBin, stringToBin, binToString, EMPTY_UUID } from '@impacket/uuid';
import { Structure, type FieldDescriptor } from '@impacket/structure';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRPOINTER,
  NDRUNION,
  NDRUniConformantArray,
  NDRUniConformantVaryingArray,
  NDRUniVaryingArray,
  NULL,
  type NDRField,
} from './ndr';
import {
  DWORD,
  LPDWORD,
  UUID,
  PUUID,
  LONG,
  ULONG,
  FILETIME,
  PFILETIME,
  BYTE,
  SHORT,
  LPSTR,
  LPWSTR,
  USHORT,
  LPLONG,
  STR,
} from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_NSPI = uuidtupToBin([
  'F5CC5A18-4264-101A-8C59-08002B2F8426',
  '56.0',
]);

class DCERPCSessionError extends DCERPCException {
  toString(): string {
    return `NSPI SessionError: code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

////////////////////////////////////////////////////////////////////////////////
// STRUCTURES
////////////////////////////////////////////////////////////////////////////////

class handle_t extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['context_handle_attributes', ULONG],
    ['context_handle_uuid', UUID],
  ];

  constructor(data?: Buffer | null, isNDR64: boolean = false) {
    super(data, isNDR64);
    if (!data) {
      this.set('context_handle_uuid', Buffer.alloc(16, 0));
    }
  }

  isNull(): boolean {
    const uuid = this.get('context_handle_uuid') as Buffer;
    return Buffer.isBuffer(uuid) && uuid.equals(Buffer.alloc(16, 0));
  }
}

// 2.2.1 Permitted Property Type Values
export const PtypEmbeddedTable = 0x0000000d;
export const PtypNull = 0x00000001;
export const PtypUnspecified = 0x00000000;

// 2.2.3 Display Type Values
export const DT_MAILUSER = 0x00000000;
export const DT_DISTLIST = 0x00000001;
export const DT_FORUM = 0x00000002;
export const DT_AGENT = 0x00000003;
export const DT_ORGANIZATION = 0x00000004;
export const DT_PRIVATE_DISTLIST = 0x00000005;
export const DT_REMOTE_MAILUSER = 0x00000006;
export const DT_CONTAINER = 0x00000100;
export const DT_TEMPLATE = 0x00000101;
export const DT_ADDRESS_TEMPLATE = 0x00000102;
export const DT_SEARCH = 0x00000200;

// 2.2.4 Default Language Code Identifier
export const NSPI_DEFAULT_LOCALE = 0x00000409;

// 2.2.5 Required Codepages
export const CP_TELETEX = 0x00004f25;
export const CP_WINUNICODE = 0x000004b0;

// 2.2.6.1 Comparison Flags
export const NORM_IGNORECASE = 1 << 0;
export const NORM_IGNORENONSPACE = 1 << 1;
export const NORM_IGNORESYMBOLS = 1 << 2;
export const SORT_STRINGSORT = 1 << 12;
export const NORM_IGNOREKANATYPE = 1 << 16;
export const NORM_IGNOREWIDTH = 1 << 17;

// 2.2.7 Permanent Entry ID GUID
export const GUID_NSPI = stringToBin('C840A7DC-42C0-1A10-B4B9-08002B2FE182');

// 2.2.8 Positioning Minimal Entry IDs
export const MID_BEGINNING_OF_TABLE = 0x00000000;
export const MID_END_OF_TABLE = 0x00000002;
export const MID_CURRENT = 0x00000001;

// 2.2.9 Ambiguous Name Resolution Minimal Entry IDs
export const MID_UNRESOLVED = 0x00000000;
export const MID_AMBIGUOUS = 0x00000001;
export const MID_RESOLVED = 0x00000002;

// 2.2.10 Table Sort Orders
export const SortTypeDisplayName = 0;
export const SortTypePhoneticDisplayName = 0x00000003;
export const SortTypeDisplayName_RO = 0x000003e8;
export const SortTypeDisplayName_W = 0x000003e9;

// 2.2.11 NspiBind Flags
export const fAnonymousLogin = 0x00000020;

// 2.2.12 Retrieve Property Flags
export const fSkipObjects = 0x00000001;
export const fEphID = 0x00000002;

// 2.2.13 NspiGetSpecialTable Flags
export const NspiAddressCreationTemplates = 0x00000002;
export const NspiUnicodeStrings = 0x00000004;

// 2.2.14 NspiQueryColumns Flags
export const NspiUnicodeProptypes = 0x80000000;

// 2.2.15 NspiGetIDsFromNames Flags
export const NspiVerifyNames = 0x00000002;

// 2.2.16 NspiGetTemplateInfo Flags
export const TI_TEMPLATE = 0x00000001;
export const TI_SCRIPT = 0x00000004;
export const TI_EMT = 0x00000010;
export const TI_HELPFILE_NAME = 0x00000020;
export const TI_HELPFILE_CONTENTS = 0x00000040;

// 2.2.17 NspiModLinkAtt Flags
export const fDelete = 0x00000001;

// 2.3.1.1 FlatUID_r
export const FlatUID_r = UUID;
export const PFlatUID_r = PUUID;

// 2.3.1.2 PropertyTagArray_r
export class PropertyTagArray extends NDRUniConformantVaryingArray {
  static item = DWORD;
}

export class PropertyTagArray_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cValues', ULONG],
    ['aulPropTag', PropertyTagArray],
  ];
}

export class PPropertyTagArray_r extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', PropertyTagArray_r],
  ];
}

// 2.3.1.3 Binary_r
export class Binary extends NDRUniConformantArray {
  static item = 'c';
}

export class PBinary extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', Binary],
  ];
}

export class Binary_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cValues', DWORD],
    ['lpb', PBinary],
  ];
}

// 2.3.1.4 ShortArray_r
export class ShortArray extends NDRUniConformantArray {
  static item = SHORT;
}

export class PShortArray extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', ShortArray],
  ];
}

export class ShortArray_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cValues', DWORD],
    ['lpi', PShortArray],
  ];
}

// 2.3.1.5 LongArray_r
export class LongArray extends NDRUniConformantArray {
  static item = LONG;
}

export class PLongArray extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', LongArray],
  ];
}

export class LongArray_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cValues', DWORD],
    ['lpl', PLongArray],
  ];
}

// 2.3.1.6 StringArray_r
export class StringArray extends NDRUniConformantArray {
  static item = LPSTR;
}

export class PStringArray extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', StringArray],
  ];
}

export class StringArray_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cValues', DWORD],
    ['lppszA', PStringArray],
  ];
}

// 2.3.1.7 BinaryArray_r
export class BinaryArray extends NDRUniConformantArray {
  static item = Binary_r;
}

export class PBinaryArray extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', BinaryArray],
  ];
}

export class BinaryArray_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cValues', DWORD],
    ['lpbin', PBinaryArray],
  ];
}

// 2.3.1.8 FlatUIDArray_r
export class FlatUIDArray extends NDRUniConformantArray {
  static item = PFlatUID_r;
}

export class PFlatUIDArray extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', FlatUIDArray],
  ];
}

export class FlatUIDArray_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cValues', DWORD],
    ['lpguid', PFlatUIDArray],
  ];
}

// 2.3.1.9 WStringArray_r
export class WStringArray extends NDRUniConformantArray {
  static item = LPWSTR;
}

export class PWStringArray extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', WStringArray],
  ];
}

export class WStringArray_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cValues', DWORD],
    ['lppszW', PWStringArray],
  ];
}

// 2.3.1.10 DateTimeArray_r
export class DateTimeArray extends NDRUniConformantArray {
  static item = PFILETIME;
}

export class PDateTimeArray extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', DateTimeArray],
  ];
}

export class DateTimeArray_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cValues', DWORD],
    ['lpft', PDateTimeArray],
  ];
}

// 2.3.1.11 PROP_VAL_UNION
export class PROP_VAL_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [
    ['tag', DWORD],
  ];

  static union: Record<number, NDRField> = {
    0x0002: ['i', SHORT],                 // PtypInteger16
    0x0003: ['l', LONG],                  // PtypInteger32
    0x000b: ['b', USHORT],               // PtypBoolean
    0x001e: ['lpszA', LPSTR],            // PtypString8
    0x0102: ['bin', Binary_r],           // PtypBinary
    0x001f: ['lpszW', LPWSTR],           // PtypString
    0x0048: ['lpguid', PFlatUID_r],      // PtypGuid
    0x0040: ['ft', FILETIME],            // PtypTime
    0x000a: ['err', ULONG],             // PtypErrorCode
    0x1002: ['MVi', ShortArray_r],       // PtypMultipleInteger16
    0x1003: ['MVl', LongArray_r],        // PtypMultipleInteger32
    0x101e: ['MVszA', StringArray_r],    // PtypMultipleString8
    0x1102: ['MVbin', BinaryArray_r],    // PtypMultipleBinary
    0x1048: ['MVguid', FlatUIDArray_r],  // PtypMultipleGuid
    0x101f: ['MVszW', WStringArray_r],   // PtypMultipleString
    0x1040: ['MVft', DateTimeArray_r],   // PtypMultipleTime
    0x0001: ['lReserved', LONG],         // PtypNull
    0x000d: ['lReserved', LONG],         // PtypEmbeddedTable
    0x0000: ['lReserved', LONG],         // PtypUnspecified
  };
}

// 2.3.1.12 PropertyValue_r
export class PropertyValue_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ulPropTag', DWORD],
    ['ulReserved', DWORD], // dwAlignPad
    ['Value', PROP_VAL_UNION],
  ];
}

export class PPropertyValue_r extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', PropertyValue_r],
  ];
}

// 2.3.2 PropertyRow_r
export class PropertyValue extends NDRUniConformantArray {
  static item = PropertyValue_r;
}

export class PPropertyValue extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', PropertyValue],
  ];
}

export class PropertyRow_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Reserved', DWORD], // ulAdrEntryPad
    ['cValues', DWORD],
    ['lpProps', PPropertyValue],
  ];
}

export class PPropertyRow_r extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', PropertyRow_r],
  ];
}

// 2.3.3 PropertyRowSet_r
export class PropertyRowSet extends NDRUniConformantArray {
  static item = PropertyRow_r;
}

export class PropertyRowSet_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cRows', DWORD],
    ['aRow', PropertyRowSet],
  ];
}

export class PPropertyRowSet_r extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', PropertyRowSet_r],
  ];
}

// 2.3.4 Restrictions
export class Restriction_r extends NDRSTRUCT {
  // Structure set after RestrictionUnion_r is defined
}

export class PRestriction_r extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', Restriction_r],
  ];
}

// 2.3.4.1 AndRestriction_r, OrRestriction_r
export class AndRestriction extends NDRUniConformantArray {
  static item = Restriction_r;
}

export class PAndRestriction extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', AndRestriction],
  ];
}

export class AndRestriction_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cRes', DWORD],
    ['lpRes', PAndRestriction],
  ];
}

export const OrRestriction_r = AndRestriction_r;

// 2.3.4.2 NotRestriction_r
export class NotRestriction_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['lpRes', PRestriction_r],
  ];
}

// 2.3.4.3 ContentRestriction_r
export class ContentRestriction_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ulFuzzyLevel', DWORD],
    ['ulPropTag', DWORD],
    ['lpProp', PPropertyValue_r],
  ];
}

// 2.3.4.4 BitMaskRestriction_r
export class BitMaskRestriction_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['relBMR', DWORD],
    ['ulPropTag', DWORD],
    ['ulMask', DWORD],
  ];
}

// 2.3.4.5 PropertyRestriction_r
export class PropertyRestriction_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['relop', DWORD],
    ['ulPropTag', DWORD],
    ['lpProp', PPropertyValue_r],
  ];
}

// 2.3.4.6 ComparePropsRestriction_r
export class ComparePropsRestriction_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['relop', DWORD],
    ['ulPropTag1', DWORD],
    ['ulPropTag2', DWORD],
  ];
}

// 2.3.4.7 SubRestriction_r
export class SubRestriction_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ulSubObject', DWORD],
    ['lpRes', PRestriction_r],
  ];
}

// 2.3.4.8 SizeRestriction_r
export class SizeRestriction_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['relop', DWORD],
    ['ulPropTag', DWORD],
    ['cb', DWORD],
  ];
}

// 2.3.4.9 ExistRestriction_r
export class ExistRestriction_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['ulReserved1', DWORD],
    ['ulPropTag', DWORD],
    ['ulReserved2', DWORD],
  ];
}

// 2.3.4.10 RestrictionUnion_r
export class RestrictionUnion_r extends NDRUNION {
  static commonHdr: NDRField[] = [
    ['tag', DWORD],
  ];

  static union: Record<number, NDRField> = {
    0x00000000: ['resAnd', AndRestriction_r],
    0x00000001: ['resOr', OrRestriction_r],
    0x00000002: ['resNot', NotRestriction_r],
    0x00000003: ['resContent', ContentRestriction_r],
    0x00000004: ['resProperty', PropertyRestriction_r],
    0x00000005: ['resCompareProps', ComparePropsRestriction_r],
    0x00000006: ['resBitMask', BitMaskRestriction_r],
    0x00000007: ['resSize', SizeRestriction_r],
    0x00000008: ['resExist', ExistRestriction_r],
    0x00000009: ['resSubRestriction', SubRestriction_r],
  };
}

// 2.3.4.11 Restriction_r (deferred structure assignment)
Restriction_r.structure = [
  ['rt', DWORD],
  ['res', RestrictionUnion_r],
] as NDRField[];

// 2.3.5.1 PropertyName_r
export class PropertyName_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['lpguid', PFlatUID_r],
    ['ulReserved', DWORD],
    ['lID', LONG],
  ];
}

export class PPropertyName_r extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', PropertyName_r],
  ];
}

// 2.3.5.2 PropertyNameSet_r
export class PropertyNameSet extends NDRUniConformantArray {
  static item = PropertyName_r;
}

export class PropertyNameSet_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cNames', DWORD],
    ['aulPropTag', PropertyNameSet],
  ];
}

export class PPropertyNameSet_r extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', PropertyNameSet_r],
  ];
}

// 2.3.6.1 StringsArray_r
export class StringsArray extends NDRUniConformantArray {
  static item = LPSTR;
}

export class StringsArray_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Count', DWORD],
    ['Strings', StringsArray],
  ];
}

// 2.3.6.1 WStringsArray_r
export class WStringsArray extends NDRUniConformantArray {
  static item = LPWSTR;
}

export class WStringsArray_r extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Count', DWORD],
    ['Strings', WStringsArray],
  ];
}

// 2.3.7 STAT
export class STAT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['SortType', DWORD],
    ['ContainerID', DWORD],
    ['CurrentRec', DWORD],
    ['Delta', LONG],
    ['NumPos', DWORD],
    ['TotalRecs', DWORD],
    ['CodePage', DWORD],
    ['TemplateLocale', DWORD],
    ['SortLocale', DWORD],
  ];
}

export class PSTAT extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', STAT],
  ];
}

// 2.3.8.1 MinimalEntryID
export const MinEntryID = '<L=0';

// 2.3.8.2 EphemeralEntryID
export class EphemeralEntryID extends Structure {
  static structure: FieldDescriptor[] = [
    ['IDType', '<B=0x87'],
    ['R1', '<B=0'],
    ['R2', '<B=0'],
    ['R3', '<B=0'],
    ['ProviderUID', '16s=Buffer.alloc(16, 0)'],
    ['R4', '<L=0x0000001'],
    ['DisplayType', '<L'],
    ['MId', MinEntryID],
  ];
}

// 2.3.8.3 PermanentEntryID
export class PermanentEntryID extends Structure {
  static defaultGuid = GUID_NSPI;
  static structure: FieldDescriptor[] = [
    ['IDType', '<B=0'],
    ['R1', '<B=0'],
    ['R2', '<B=0'],
    ['R3', '<B=0'],
    ['ProviderUID', '16s=Buffer.alloc(16, 0)'],
    ['R4', '<L=0x0000001'],
    ['DisplayType', '<L'],
    ['DistinguishedName', 'z'],
  ];

  toString(): string {
    return String((this as unknown as Record<string, unknown>)['DistinguishedName'] ?? '');
  }
}

////////////////////////////////////////////////////////////////////////////////
// RPC CALLS
////////////////////////////////////////////////////////////////////////////////

// 3.1.4.1 NspiBind (Opnum 0)
export class NspiBindResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pServerGuid', PFlatUID_r],
    ['contextHandle', handle_t],
    ['ErrorCode', ULONG],
  ];
}

export class NspiBind extends NDRCALL {
  static opnum = 0;
  static Response = NspiBindResponse;
  static structure: NDRField[] = [
    ['dwFlags', DWORD],
    ['pStat', STAT],
    ['pServerGuid', PFlatUID_r],
  ];
}

// 3.1.4.2 NspiUnbind (Opnum 1)
export class NspiUnbindResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['contextHandle', handle_t],
    ['ErrorCode', ULONG],
  ];
}

export class NspiUnbind extends NDRCALL {
  static opnum = 1;
  static Response = NspiUnbindResponse;
  static structure: NDRField[] = [
    ['contextHandle', handle_t],
    ['Reserved', DWORD], // flags
  ];
}

// 3.1.4.4 NspiUpdateStat (Opnum 2)
export class NspiUpdateStatResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pStat', STAT],
    ['plDelta', LPLONG],
    ['ErrorCode', ULONG],
  ];
}

export class NspiUpdateStat extends NDRCALL {
  static opnum = 2;
  static Response = NspiUpdateStatResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['Reserved', DWORD], // flags
    ['pStat', STAT],
    ['plDelta', LPLONG],
  ];
}

// 3.1.4.8 NspiQueryRows (Opnum 3)
// Module-private DWORD_ARRAY to avoid collision with dtypes export
class DWORD_ARRAY extends NDRUniConformantArray {
  static item = DWORD;
}

class PDWORD_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [
    ['Data', DWORD_ARRAY],
  ];
}

export class NspiQueryRowsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pStat', STAT],
    ['ppRows', PPropertyRowSet_r],
    ['ErrorCode', ULONG],
  ];
}

export class NspiQueryRows extends NDRCALL {
  static opnum = 3;
  static Response = NspiQueryRowsResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['dwFlags', DWORD],
    ['pStat', STAT],
    ['dwETableCount', DWORD],
    ['lpETable', PDWORD_ARRAY],
    ['Count', DWORD],
    ['pPropTags', PPropertyTagArray_r],
  ];
}

// 3.1.4.9 NspiSeekEntries (Opnum 4)
export class NspiSeekEntriesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['pStat', STAT],
    ['ppRows', PPropertyRowSet_r],
    ['ErrorCode', ULONG],
  ];
}

export class NspiSeekEntries extends NDRCALL {
  static opnum = 4;
  static Response = NspiSeekEntriesResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['Reserved', DWORD], // flags
    ['pStat', STAT],
    ['pTarget', PropertyValue_r],
    ['lpETable', PropertyTagArray_r],
    ['pPropTags', PropertyTagArray_r],
  ];
}

// 3.1.4.13 NspiDNToMId (Opnum 7)
export class NspiDNToMIdResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppOutMIds', PPropertyTagArray_r],
    ['ErrorCode', ULONG],
  ];
}

export class NspiDNToMId extends NDRCALL {
  static opnum = 7;
  static Response = NspiDNToMIdResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['Reserved', DWORD], // flags
    ['pNames', StringsArray_r],
  ];
}

// 3.1.4.6 NspiGetPropList (Opnum 8)
export class NspiGetPropListResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppOutMIds', PPropertyTagArray_r],
    ['ErrorCode', ULONG],
  ];
}

export class NspiGetPropList extends NDRCALL {
  static opnum = 8;
  static Response = NspiGetPropListResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['dwFlags', DWORD],
    ['dwMId', DWORD],
    ['CodePage', DWORD],
  ];
}

// 3.1.4.7 NspiGetProps (Opnum 9)
export class NspiGetPropsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppRows', PPropertyRow_r],
    ['ErrorCode', ULONG],
  ];
}

export class NspiGetProps extends NDRCALL {
  static opnum = 9;
  static Response = NspiGetPropsResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['dwFlags', DWORD],
    ['pStat', PSTAT],
    ['pPropTags', PPropertyTagArray_r],
  ];
}

// 3.1.4.12 NspiCompareMIds (Opnum 10)
export class NspiCompareMIdsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['plResult', LONG],
    ['ErrorCode', ULONG],
  ];
}

export class NspiCompareMIds extends NDRCALL {
  static opnum = 10;
  static Response = NspiCompareMIdsResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['Reserved', DWORD], // flags
    ['pStat', STAT],
    ['MId1', DWORD],
    ['MId2', DWORD],
  ];
}

// 3.1.4.3 NspiGetSpecialTable (Opnum 12)
export class NspiGetSpecialTableResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['lpVersion', DWORD],
    ['ppRows', PPropertyRowSet_r],
    ['ErrorCode', DWORD],
  ];
}

export class NspiGetSpecialTable extends NDRCALL {
  static opnum = 12;
  static Response = NspiGetSpecialTableResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['dwFlags', DWORD],
    ['pStat', PSTAT],
    ['lpVersion', LPDWORD],
  ];
}

// 3.1.4.20 NspiGetTemplateInfo (Opnum 13)
export class NspiGetTemplateInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppData', PPropertyRow_r],
    ['ErrorCode', ULONG],
  ];
}

export class NspiGetTemplateInfo extends NDRCALL {
  static opnum = 13;
  static Response = NspiGetTemplateInfoResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['dwFlags', DWORD],
    ['ulType', DWORD],
    ['pDN', LPSTR],
    ['dwCodePage', DWORD],
    ['dwLocaleID', DWORD],
  ];
}

// 3.1.4.15 NspiModLinkAtt (Opnum 14)
export class NspiModLinkAttResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ErrorCode', ULONG],
  ];
}

export class NspiModLinkAtt extends NDRCALL {
  static opnum = 14;
  static Response = NspiModLinkAttResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['dwFlags', DWORD],
    ['ulPropTag', DWORD],
    ['dwMId', DWORD],
    ['lpEntryIds', BinaryArray_r],
  ];
}

// 3.1.4.5 NspiQueryColumns (Opnum 16)
export class NspiQueryColumnsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppColumns', PPropertyTagArray_r],
    ['ErrorCode', ULONG],
  ];
}

export class NspiQueryColumns extends NDRCALL {
  static opnum = 16;
  static Response = NspiQueryColumnsResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['Reserved', DWORD], // flags
    ['dwFlags', DWORD],  // mapiFlags
  ];
}

// 3.1.4.16 NspiGetNamesFromIDs (Opnum 17)
export class NspiGetNamesFromIDsResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppReturnedPropTags', PPropertyTagArray_r],
    ['ppNames', PPropertyNameSet_r],
    ['ErrorCode', ULONG],
  ];
}

export class NspiGetNamesFromIDs extends NDRCALL {
  static opnum = 17;
  static Response = NspiGetNamesFromIDsResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['Reserved', DWORD], // flags
    ['lpguid', PFlatUID_r],
    ['pPropTags', PPropertyTagArray_r],
  ];
}

// 3.1.4.17 NspiGetIDsFromNames (Opnum 18)
export class PropertyName_r_ARRAY extends NDRUniConformantVaryingArray {
  static item = PropertyName_r;
}

export class NspiGetIDsFromNamesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppPropTags', PPropertyTagArray_r],
    ['ErrorCode', ULONG],
  ];
}

export class NspiGetIDsFromNames extends NDRCALL {
  static opnum = 18;
  static Response = NspiGetIDsFromNamesResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['Reserved', DWORD], // flags
    ['dwFlags', DWORD],  // mapiFlags
    ['cPropNames', DWORD],
    ['pNames', PropertyName_r_ARRAY],
  ];
}

// 3.1.4.18 NspiResolveNames (Opnum 19)
export class NspiResolveNamesResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppMIds', PPropertyTagArray_r],
    ['ppRows', PPropertyRowSet_r],
    ['ErrorCode', ULONG],
  ];
}

export class NspiResolveNames extends NDRCALL {
  static opnum = 19;
  static Response = NspiResolveNamesResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['Reserved', DWORD], // flags
    ['pStat', STAT],
    ['pPropTags', PPropertyTagArray_r],
    ['paStr', StringsArray_r],
  ];
}

// 3.1.4.19 NspiResolveNamesW (Opnum 20)
export class NspiResolveNamesWResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppMIds', PPropertyTagArray_r],
    ['ppRows', PPropertyRowSet_r],
    ['ErrorCode', ULONG],
  ];
}

export class NspiResolveNamesW extends NDRCALL {
  static opnum = 20;
  static Response = NspiResolveNamesWResponse;
  static structure: NDRField[] = [
    ['hRpc', handle_t],
    ['Reserved', DWORD], // flags
    ['pStat', STAT],
    ['pPropTags', PPropertyTagArray_r],
    ['paStr', WStringsArray_r],
  ];
}

////////////////////////////////////////////////////////////////////////////////
// OPNUMs and their corresponding structures
////////////////////////////////////////////////////////////////////////////////
const OPNUMS: Record<number, [typeof NDRCALL, typeof NDRCALL]> = {
  0: [NspiBind, NspiBindResponse],
  1: [NspiUnbind, NspiUnbindResponse],
  2: [NspiUpdateStat, NspiUpdateStatResponse],
  3: [NspiQueryRows, NspiQueryRowsResponse],
  4: [NspiSeekEntries, NspiSeekEntriesResponse],
  7: [NspiDNToMId, NspiDNToMIdResponse],
  8: [NspiGetPropList, NspiGetPropListResponse],
  9: [NspiGetProps, NspiGetPropsResponse],
  10: [NspiCompareMIds, NspiCompareMIdsResponse],
  12: [NspiGetSpecialTable, NspiGetSpecialTableResponse],
  13: [NspiGetTemplateInfo, NspiGetTemplateInfoResponse],
  14: [NspiModLinkAtt, NspiModLinkAttResponse],
  16: [NspiQueryColumns, NspiQueryColumnsResponse],
  17: [NspiGetNamesFromIDs, NspiGetNamesFromIDsResponse],
  18: [NspiGetIDsFromNames, NspiGetIDsFromNamesResponse],
  19: [NspiResolveNames, NspiResolveNamesResponse],
  20: [NspiResolveNamesW, NspiResolveNamesWResponse],
};

////////////////////////////////////////////////////////////////////////////////
// HELPER FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

function checkNullString(str: string | typeof NULL): string | typeof NULL {
  if (str === NULL) return str;
  if (typeof str !== 'string') return str;
  if (str.length === 0 || str[str.length - 1] !== '\x00') return str + '\x00';
  return str;
}

export function getGuidFromDn(legacyDN: string): Buffer {
  const dn = String(legacyDN);
  const guid = dn.substring(dn.lastIndexOf('=') + 1);
  return stringToBin(guid);
}

export function getDnFromGuid(guid: string, minimize: boolean = false): string {
  const dnTemplate = minimize
    ? '/guid='
    : '/o=NT5/ou=00000000000000000000000000000000/cn=';
  const guidBin = stringToBin(guid);
  return `${dnTemplate}${guidBin.toString('hex')}`;
}

export class ExchBinaryObject {
  data: Buffer;
  constructor(data: Buffer) {
    this.data = data;
  }
}

export function getUnixTime(t: bigint): number {
  let val = t - 116444736000000000n;
  val = val / 10000000n;
  return Number(val);
}

type DceRequestFn = <T>(
  req: unknown,
  uuid?: unknown,
  checkError?: boolean,
) => Promise<T>;

export async function hNspiBind(
  dce: DCERPC_v5,
  pStat?: unknown,
): Promise<NspiBindResponse> {
  const request = new NspiBind();
  if (pStat == null) {
    (request.fields['pStat'] as STAT).set('CodePage', CP_TELETEX);
  } else {
    request.set('pStat', pStat);
  }
  return (dce as unknown as { request: DceRequestFn }).request<NspiBindResponse>(
    request,
  );
}

export async function hNspiUnbind(
  dce: DCERPC_v5,
  handler: unknown,
): Promise<NspiUnbindResponse> {
  const request = new NspiUnbind();
  request.set('contextHandle', handler);
  return (dce as unknown as { request: DceRequestFn }).request<NspiUnbindResponse>(
    request,
    undefined,
    false,
  );
}

export async function hNspiUpdateStat(
  dce: DCERPC_v5,
  handler: unknown,
  pStat: unknown,
  plDelta: unknown = NULL,
): Promise<NspiUpdateStatResponse> {
  const request = new NspiUpdateStat();
  request.set('hRpc', handler);
  request.set('pStat', pStat);
  request.set('plDelta', plDelta);
  return (dce as unknown as { request: DceRequestFn }).request<NspiUpdateStatResponse>(
    request,
    undefined,
    false,
  );
}

export async function hNspiQueryRows(
  dce: DCERPC_v5,
  handler: unknown,
  {
    dwFlags = fSkipObjects,
    pStat = undefined as unknown,
    ContainerID = 0,
    Count = 50,
    pPropTags = [] as number[],
    pPropTagsRaw = NULL as unknown,
    lpETable = [] as number[],
  } = {},
): Promise<NspiQueryRowsResponse> {
  const request = new NspiQueryRows();
  request.set('hRpc', handler);
  request.set('dwFlags', dwFlags);
  request.set('Count', Count);

  if (pStat == null) {
    (request.fields['pStat'] as STAT).set('ContainerID', ContainerID);
  } else {
    request.set('pStat', pStat);
  }

  if (pPropTags.length > 0) {
    for (const aulPropTag of pPropTags) {
      const prop = new (DWORD as unknown as new () => { set(k: string, v: unknown): void })();
      prop.set('Data', aulPropTag);
      ((request.fields['pPropTags'] as Record<string, unknown>)['aulPropTag'] as unknown[]).push(prop);
    }
    (request.fields['pPropTags'] as Record<string, unknown>)['cValues'] = pPropTags.length;
  } else {
    request.set('pPropTags', pPropTagsRaw);
  }

  if (lpETable.length > 0) {
    for (const mID of lpETable) {
      const elem = new (DWORD as unknown as new () => { set(k: string, v: unknown): void })();
      elem.set('Data', mID);
      (request.fields['lpETable'] as unknown[]).push(elem);
    }
    request.set('dwETableCount', lpETable.length);
  } else {
    request.set('lpETable', NULL);
    request.set('dwETableCount', 0);
  }

  return (dce as unknown as { request: DceRequestFn }).request<NspiQueryRowsResponse>(
    request,
  );
}

export async function hNspiSeekEntries(
  dce: DCERPC_v5,
  handler: unknown,
  displayName: string,
  {
    ContainerID = 0,
    lpETable = [] as number[],
    lpETableRaw = NULL as unknown,
    pPropTags = [] as number[],
    pPropTagsRaw = NULL as unknown,
  } = {},
): Promise<NspiSeekEntriesResponse> {
  const request = new NspiSeekEntries();
  request.set('hRpc', handler);
  (request.fields['pStat'] as STAT).set('ContainerID', ContainerID);
  (request.fields['pStat'] as STAT).set('SortType', SortTypeDisplayName);

  (request.fields['pTarget'] as PropertyValue_r).set('ulPropTag', 0x3001001f);
  ((request.fields['pTarget'] as PropertyValue_r).fields['Value'] as PROP_VAL_UNION).set('tag', 0x0000001f);
  ((request.fields['pTarget'] as PropertyValue_r).fields['Value'] as PROP_VAL_UNION).set('lpszW', checkNullString(displayName));

  if (lpETable.length > 0) {
    for (const mID of lpETable) {
      const elem = new (DWORD as unknown as new () => { set(k: string, v: unknown): void })();
      elem.set('Data', mID);
      (request.fields['lpETable'] as unknown[]).push(elem);
    }
  } else {
    request.set('lpETable', lpETableRaw);
  }

  if (pPropTags.length > 0) {
    for (const aulPropTag of pPropTags) {
      const prop = new (DWORD as unknown as new () => { set(k: string, v: unknown): void })();
      prop.set('Data', aulPropTag);
      ((request.fields['pPropTags'] as Record<string, unknown>)['aulPropTag'] as unknown[]).push(prop);
    }
  } else {
    request.set('pPropTags', pPropTagsRaw);
  }

  return (dce as unknown as { request: DceRequestFn }).request<NspiSeekEntriesResponse>(
    request,
  );
}

export async function hNspiDNToMId(
  dce: DCERPC_v5,
  handler: unknown,
  pNames: string[] = [],
): Promise<NspiDNToMIdResponse> {
  const request = new NspiDNToMId();
  request.set('hRpc', handler);
  (request.fields['pNames'] as StringsArray_r).set('Count', pNames.length);

  for (const name of pNames) {
    const lpstr = new (LPSTR as unknown as new () => { set(k: string, v: unknown): void })();
    lpstr.set('Data', checkNullString(name));
    ((request.fields['pNames'] as StringsArray_r).fields['Strings'] as unknown[]).push(lpstr);
  }

  return (dce as unknown as { request: DceRequestFn }).request<NspiDNToMIdResponse>(
    request,
  );
}

export async function hNspiGetPropList(
  dce: DCERPC_v5,
  handler: unknown,
  dwMId: number = 0,
  dwFlags: number = fSkipObjects,
  CodePage: number = CP_TELETEX,
): Promise<NspiGetPropListResponse> {
  const request = new NspiGetPropList();
  request.set('hRpc', handler);
  request.set('dwMId', dwMId);
  request.set('dwFlags', dwFlags);
  request.set('CodePage', CodePage);
  return (dce as unknown as { request: DceRequestFn }).request<NspiGetPropListResponse>(
    request,
  );
}

export async function hNspiGetProps(
  dce: DCERPC_v5,
  handler: unknown,
  {
    ContainerID = 0,
    CurrentRec = 0,
    dwFlags = fSkipObjects,
    CodePage = CP_TELETEX,
    pPropTags = [] as number[],
  } = {},
): Promise<NspiGetPropsResponse> {
  const request = new NspiGetProps();
  request.set('hRpc', handler);
  request.set('dwFlags', dwFlags);

  (request.fields['pStat'] as PSTAT).set('CurrentRec', CurrentRec);
  (request.fields['pStat'] as PSTAT).set('ContainerID', ContainerID);
  (request.fields['pStat'] as PSTAT).set('CodePage', CodePage);

  for (const aulPropTag of pPropTags) {
    const prop = new (DWORD as unknown as new () => { set(k: string, v: unknown): void })();
    prop.set('Data', aulPropTag);
    ((request.fields['pPropTags'] as Record<string, unknown>)['aulPropTag'] as unknown[]).push(prop);
  }
  (request.fields['pPropTags'] as Record<string, unknown>)['cValues'] = pPropTags.length + 1;

  return (dce as unknown as { request: DceRequestFn }).request<NspiGetPropsResponse>(
    request,
  );
}

export async function hNspiGetSpecialTable(
  dce: DCERPC_v5,
  handler: unknown,
  dwFlags: number = NspiUnicodeStrings,
  pStat?: unknown,
  lpVersion: unknown = NULL,
): Promise<NspiGetSpecialTableResponse> {
  const request = new NspiGetSpecialTable();
  request.set('hRpc', handler);
  request.set('dwFlags', dwFlags);
  if (pStat != null) {
    request.set('pStat', pStat);
  }
  request.set('lpVersion', lpVersion);
  return (dce as unknown as { request: DceRequestFn }).request<NspiGetSpecialTableResponse>(
    request,
  );
}

export async function hNspiGetTemplateInfo(
  dce: DCERPC_v5,
  handler: unknown,
  {
    pDN = NULL as string | typeof NULL,
    dwLocaleID = 0,
    ulType = 0,
    dwCodePage = 0,
    dwFlags = 0xffffffff,
  } = {},
): Promise<NspiGetTemplateInfoResponse> {
  const request = new NspiGetTemplateInfo();
  request.set('hRpc', handler);
  request.set('dwFlags', dwFlags);
  request.set('ulType', ulType);
  request.set('pDN', checkNullString(pDN));
  request.set('dwCodePage', dwCodePage);
  request.set('dwLocaleID', dwLocaleID);
  return (dce as unknown as { request: DceRequestFn }).request<NspiGetTemplateInfoResponse>(
    request,
  );
}

export async function hNspiModLinkAtt(
  dce: DCERPC_v5,
  handler: unknown,
  dwFlags: number,
  ulPropTag: number,
  dwMId: number,
  lpEntryIds: Array<{ getData(): Buffer }>,
): Promise<NspiModLinkAttResponse> {
  const request = new NspiModLinkAtt();
  request.set('hRpc', handler);
  request.set('dwFlags', dwFlags);
  request.set('ulPropTag', ulPropTag);
  request.set('dwMId', dwMId);

  for (const lpEntryId of lpEntryIds) {
    const prop = new Binary_r();
    const data = lpEntryId.getData();
    prop.set('lpb', data);
    prop.set('cValues', data.length);
    ((request.fields['lpEntryIds'] as BinaryArray_r).fields['lpbin'] as unknown[]).push(prop);
  }
  (request.fields['lpEntryIds'] as BinaryArray_r).set('cValues', lpEntryIds.length);

  return (dce as unknown as { request: DceRequestFn }).request<NspiModLinkAttResponse>(
    request,
  );
}

export async function hNspiQueryColumns(
  dce: DCERPC_v5,
  handler: unknown,
  dwFlags: number = NspiUnicodeProptypes,
): Promise<NspiQueryColumnsResponse> {
  const request = new NspiQueryColumns();
  request.set('hRpc', handler);
  request.set('dwFlags', dwFlags);
  return (dce as unknown as { request: DceRequestFn }).request<NspiQueryColumnsResponse>(
    request,
  );
}

export async function hNspiGetNamesFromIDs(
  dce: DCERPC_v5,
  handler: unknown,
  {
    lpguid = EMPTY_UUID as Buffer,
    pPropTags = [] as number[],
    pPropTagsRaw = NULL as unknown,
  } = {},
): Promise<NspiGetNamesFromIDsResponse> {
  const request = new NspiGetNamesFromIDs();
  request.set('hRpc', handler);
  request.set('lpguid', lpguid);

  if (pPropTags.length > 0) {
    for (const aulPropTag of pPropTags) {
      const prop = new (DWORD as unknown as new () => { set(k: string, v: unknown): void })();
      prop.set('Data', aulPropTag);
      ((request.fields['pPropTags'] as Record<string, unknown>)['aulPropTag'] as unknown[]).push(prop);
    }
    (request.fields['pPropTags'] as Record<string, unknown>)['cValues'] = pPropTags.length;
  } else if (pPropTagsRaw === NULL) {
    request.fields['pPropTags'] = NULL;
  } else {
    request.set('pPropTags', pPropTagsRaw);
  }

  return (dce as unknown as { request: DceRequestFn }).request<NspiGetNamesFromIDsResponse>(
    request,
  );
}

export async function hNspiResolveNames(
  dce: DCERPC_v5,
  handler: unknown,
  {
    ContainerID = 0,
    pPropTags = [] as number[],
    pPropTagsRaw = NULL as unknown,
    paStr = [] as string[],
  } = {},
): Promise<NspiResolveNamesResponse> {
  const request = new NspiResolveNames();
  request.set('hRpc', handler);
  (request.fields['pStat'] as STAT).set('ContainerID', ContainerID);

  if (pPropTags.length > 0) {
    for (const aulPropTag of pPropTags) {
      const prop = new (DWORD as unknown as new () => { set(k: string, v: unknown): void })();
      prop.set('Data', aulPropTag);
      ((request.fields['pPropTags'] as Record<string, unknown>)['aulPropTag'] as unknown[]).push(prop);
    }
    (request.fields['pPropTags'] as Record<string, unknown>)['cValues'] = pPropTags.length;
  } else if (pPropTagsRaw === NULL) {
    request.fields['pPropTags'] = NULL;
  } else {
    request.set('pPropTags', pPropTagsRaw);
  }

  if (paStr.length > 0) {
    for (const paStrElem of paStr) {
      const value = new (LPSTR as unknown as new () => { set(k: string, v: unknown): void })();
      value.set('Data', checkNullString(paStrElem));
      ((request.fields['paStr'] as StringsArray_r).fields['Strings'] as unknown[]).push(value);
    }
    (request.fields['paStr'] as StringsArray_r).set('Count', paStr.length);
  }

  return (dce as unknown as { request: DceRequestFn }).request<NspiResolveNamesResponse>(
    request,
  );
}

export async function hNspiResolveNamesW(
  dce: DCERPC_v5,
  handler: unknown,
  {
    ContainerID = 0,
    pPropTags = [] as number[],
    pPropTagsRaw = NULL as unknown,
    paStr = [] as string[],
  } = {},
): Promise<NspiResolveNamesWResponse> {
  const request = new NspiResolveNamesW();
  request.set('hRpc', handler);
  (request.fields['pStat'] as STAT).set('ContainerID', ContainerID);

  if (pPropTags.length > 0) {
    for (const aulPropTag of pPropTags) {
      const prop = new (DWORD as unknown as new () => { set(k: string, v: unknown): void })();
      prop.set('Data', aulPropTag);
      ((request.fields['pPropTags'] as Record<string, unknown>)['aulPropTag'] as unknown[]).push(prop);
    }
    (request.fields['pPropTags'] as Record<string, unknown>)['cValues'] = pPropTags.length;
  } else if (pPropTagsRaw === NULL) {
    request.fields['pPropTags'] = NULL;
  } else {
    request.set('pPropTags', pPropTagsRaw);
  }

  if (paStr.length > 0) {
    for (const paStrElem of paStr) {
      const value = new (LPWSTR as unknown as new () => { set(k: string, v: unknown): void })();
      value.set('Data', checkNullString(paStrElem));
      ((request.fields['paStr'] as WStringsArray_r).fields['Strings'] as unknown[]).push(value);
    }
    (request.fields['paStr'] as WStringsArray_r).set('Count', paStr.length);
  }

  return (dce as unknown as { request: DceRequestFn }).request<NspiResolveNamesWResponse>(
    request,
  );
}
